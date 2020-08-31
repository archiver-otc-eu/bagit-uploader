#!/usr/bin/env python3

import configargparse
import shutil
import tempfile
import urllib.request
from urllib.parse import urlparse
import urllib3
import requests
import os
import logging
import json
import time
import datetime
import tarfile
import zipfile
from http import HTTPStatus
from bdbag import bdbag_api

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

FILES_INDEX = "fetch.txt"
CHECKSUM_MANIFEST_FORMAT = "manifest-{0}.txt"
METADATA_JSON = "metadata.json"
MD5 = "md5"
SHA1 = "sha1"
SHA256 = "sha256"
SHA512 = "sha512"
HASHING_ALGORITHMS = [MD5, SHA1, SHA256, SHA512]
PATH_SEPARATOR = "/"

DEFAULT_CONFIG_FILE = 'config.yaml'

parser = configargparse.ArgumentParser(
    formatter_class=configargparse.ArgumentDefaultsHelpFormatter,
    default_config_files=['config.yaml'],
    description='Register files in the Onedata system.')

requiredNamed = parser.add_argument_group('required named arguments')

requiredNamed.add_argument(
    '--host', '-H',
    action='store',
    help='Oneprovider host.',
    dest='host',
    required=True)

requiredNamed.add_argument(
    '--space-id', '-spi',
    action='store',
    help='Id of the space in which the files will be registered.',
    dest='space_id',
    required=True)

requiredNamed.add_argument(
    '--storage-id', '-sti',
    action='store',
    help='Id of the storage on which the files are located. Storage must be created as an `imported` storage with path type equal to `canonical`.',
    dest='storage_id',
    required=True)

requiredNamed.add_argument(
    '--token', '-t',
    action='store',
    help='Onedata access token.',
    dest='token',
    required=True)

requiredNamed.add_argument(
    '--bag-path', '-b',
    action='append',
    help='Path to BagIt bag. It can be path to a bag archive (supported formats: `zip`, `tar`, `tgz`), extracted bag '
         'directory or URL to a bag archive. Many bag paths can be passed (e.g. `-b BAG_PATH1 -b BAG_PATH2`).',
    dest='bag_paths',
    required=True)

parser.add_argument(
    '--file-mode', '-m',
    action='store',
    help='POSIX mode with which files will be registered, represented as an octal string.',
    dest='mode',
    default="0664"
)

parser.add_argument(
    '--disable-auto-detection', '-dd',
    action='store_true',
    help='Flag which disables automatic detection of file attributes and verification whether file exists on storage. '
         'Passing this flag results in faster registration of files but there is a risk of registering files that '
         'don\'t exist on storage. Such files will be visible in the space but not accessible.',
    dest='disable_auto_detection',
    default=False
)

parser.add_argument(
    '--logging-frequency', '-lf',
    action='store',
    type=int,
    help='Frequency of logging. Log will occur after registering every logging_freq number of files.',
    dest='logging_freq',
    default=None)

parser.add_argument(
    '--disable-cert-verification', '-dv',
    action='store_true',
    help='Flag which disables verification of SSL certificate.',
    dest='disable_cert_verification',
    default=False)

parser.add_argument(
    '--config-file',
    action='store',
    is_config_file=True,
    help='Path to config file which will override the default {0}'.format(DEFAULT_CONFIG_FILE),
    dest='config_file'
)

parser.add_argument(
    '--destination-host', '-dhost',
    action='store',
    help='Host of a Oneprovider to which files will be replicated after registration. If not passed, replication won\'t be performed.',
    dest='destination_host',
    default=None
)


parser.add_argument(
    '--sync-timeout', '-st',
    action='store',
    type=int,
    help='Time for synchronization of files between provider in seconds. All registered files that are to be replicated'
         'must be visible by the destination provider.',
    dest='sync_timeout',
    default=60
)


ONEPROVIDER_REST_FORMAT = "https://{0}/api/v3/oneprovider/{1}"
REGISTER_FILE_PATH = "data/register"
SCHEDULE_TRANSFER_PATH = "transfers"
LOOKUP_FILE_ID_PATH = "lookup-file-id/{0}/{1}"
SPACE_DETAILS_PATH = "spaces/{0}"
FILE_DISTRIBUTION_PATH = "data/{0}/distribution"
PROVIDER_INFO = "configuration"


def register_file(destination_path, storage_file_id, size, xattrs, custom_json_metadata=dict()):
    payload = {
        'spaceId': args.space_id,
        'storageId': args.storage_id,
        'storageFileId': storage_file_id,
        'destinationPath': destination_path,
        'size': int(size),
        'mode': args.mode,
        'xattrs': xattrs,
        'autoDetectAttributes': not args.disable_auto_detection
    }
    if custom_json_metadata:
        payload['json'] = custom_json_metadata
    try:
        response = requests.post(REGISTER_FILE_ENDPOINT, json=payload, headers=HEADERS, verify=(not args.disable_cert_verification))
        if response.status_code == HTTPStatus.CREATED:
            # ensure that path starts with slash
            return os.path.join(PATH_SEPARATOR, destination_path), response.json()['fileId'], int(size)
        else:
            logger.error("Registration of {0} failed with HTTP status {1}.\n""Response: {2}"
                          .format(storage_file_id, response.status_code, response.content)),
            return None
    except Exception as e:
        logger.error("Registration of {0} failed due to {1}".format(storage_file_id, e), exc_info=True)


def get_space_name(space_id):
    get_space_details_endpoint = ONEPROVIDER_REST_FORMAT.format(args.host, SPACE_DETAILS_PATH.format(space_id))
    response = requests.get(get_space_details_endpoint, headers=HEADERS, verify=(not args.disable_cert_verification))
    return response.json()['name']


def lookup_file_id(space_name, path):
    lookup_file_id_endpoint = ONEPROVIDER_REST_FORMAT.format(args.host, LOOKUP_FILE_ID_PATH.format(space_name, path))
    response = requests.post(lookup_file_id_endpoint, headers=HEADERS, verify=(not args.disable_cert_verification))
    return response.json()['fileId']


def schedule_transfer_job(file_id, destination_provider):
    payload = {
        "type": "replication",
        "replicatingProviderId": destination_provider,
        "fileId": file_id,
        "dataSourceType": "file"
    }
    response = requests.post(SCHEDULE_TRANSFER_ENDPOINT, headers=HEADERS, json=payload, verify=(not args.disable_cert_verification))
    return response.json()['transferId']


def ensure_bag_extracted(bag_path, should_remove_extracted_bag=False):
    try:
        (is_file, is_dir, is_uri) = bdbag_api.inspect_path(bag_path)
        if is_file:
            bag_path = extract_bag_archive(bag_path)
            return ensure_bag_extracted(bag_path, should_remove_extracted_bag=True)
        elif is_dir and bdbag_api.is_bag(bag_path):
            # bag_path is already a path to a correct bag structure
            return bag_path, should_remove_extracted_bag
        elif is_uri:
            bag_path = download(bag_path)
            return ensure_bag_extracted(bag_path)
        else:
            logger.error("Passed path {0} to bag that does not exist or is not a valid bag.".format(bag_path))
            return None, False
    except:
        logger.error("Passed path {0} to bag that does not exist or is not a valid bag.".format(bag_path),
                      exc_info=True)
        return None, False


def extract_bag_archive(bag_archive_path):
    return extract_bag(bag_archive_path, temp=True)


def extract_bag(bag_path, output_path=None, temp=False):
    # This function is a copy of bdbag_api.extract_bag function but it properly
    # handles case when bag directory has different basename than archive file
    if not os.path.exists(bag_path):
        raise RuntimeError("Specified bag path not found: %s" % bag_path)

    bag_dir = os.path.splitext(os.path.basename(bag_path))[0]
    if os.path.isfile(bag_path):
        if temp:
            output_path = tempfile.mkdtemp(prefix='bag_')
        elif not output_path:
            output_path = os.path.splitext(bag_path)[0]
            if os.path.exists(output_path):
                newpath = ''.join([output_path, '-', datetime.strftime(datetime.now(), "%Y-%m-%d_%H.%M.%S")])
                print("Specified output path %s already exists, moving existing directory to %s" %
                            (output_path, newpath))
                shutil.move(output_path, newpath)
            output_path = os.path.dirname(bag_path)
        if zipfile.is_zipfile(bag_path):
            print("Extracting ZIP archived file: %s" % bag_path)
            with open(bag_path, 'rb') as bag_file:
                zipped = zipfile.ZipFile(bag_file)
                zipped.extractall(output_path)
                bag_dir = zipped.namelist()[0].rstrip(os.path.sep)
                zipped.close()
        elif tarfile.is_tarfile(bag_path):
            print("Extracting TAR/GZ/BZ2 archived file: %s" % bag_path)
            tarred = tarfile.open(bag_path)
            tarred.extractall(output_path)
            bag_dir = tarred.getnames()[0].rstrip(os.path.sep)
            tarred.close()
        else:
            raise RuntimeError("Archive format not supported for file: %s"
                               "\nSupported archive formats are ZIP or TAR/GZ/BZ2" % bag_path)

    extracted_path = os.path.join(output_path, bag_dir)
    print("File %s was successfully extracted to directory %s" % (bag_path, extracted_path))

    return extracted_path


def download(url):
    with urllib.request.urlopen(url) as response:
        file_name = os.path.basename(url)
        file_path = os.path.join(TEMP_DIR, file_name)
        with open(file_path, "wb+") as tmp_file:
            shutil.copyfileobj(response, tmp_file)
            tmp_file.flush()
            return tmp_file.name


def map_hashing_algorithm_to_manifest(hashing_algorithm):
    return CHECKSUM_MANIFEST_FORMAT.format(hashing_algorithm)


def collect_all_checksums(bag_path):
    all_checksums = dict()
    for hashing_algorith in HASHING_ALGORITHMS:
        checksums = collect_checksums(bag_path, hashing_algorith)
        if checksums:
            all_checksums[hashing_algorith] = checksums
    return all_checksums


def collect_checksums(bag_path, hashing_algorithm):
    manifest = map_hashing_algorithm_to_manifest(hashing_algorithm)
    manifest_path = os.path.join(bag_path, manifest)
    if os.path.exists(manifest_path):
        checksums = dict()
        with open(manifest_path, 'r') as f:
            for line in f:
                [hash, file_path] = line.split()
                checksums[file_path] = hash
        return checksums
    return None


def prepare_checksum_xattrs(file_path, all_checksums):
    checksum_xattrs = dict()
    for hashing_algorithm, checksums in all_checksums.items():
        checksum_xattrs["checksum.{0}".format(hashing_algorithm)] = checksums[file_path]
    return checksum_xattrs


def prepare_metadata_json(bag_path):
    metadata_json_path = os.path.join(bag_path, METADATA_JSON)
    if os.path.exists(metadata_json_path):
        with open(metadata_json_path, 'r') as f:
            metadata_json = json.load(f)
            metadata_json_per_file = {}
            for idx, element in enumerate(metadata_json.get("metadata", [])):
                if "filename" not in element:
                    logger.critical("ERROR: Metadata entry {} in {} doesn't contain "
                                    "required 'filename' field: {}"
                                    .format(idx, metadata_json_path, element)),
                    exit(1)
                else:
                    metadata_json_per_file[element['filename']] = element

            return metadata_json_per_file
    else:
        return dict()


def get_file_custom_json_metadata(file_path, metadata_json):
    abs_file_path = os.path.join(PATH_SEPARATOR, file_path)
    rel_file_path = file_path.lstrip(PATH_SEPARATOR)
    if abs_file_path in metadata_json:
        return metadata_json.get(abs_file_path)
    elif rel_file_path in metadata_json:
        return metadata_json.get(rel_file_path)
    else:
        return dict()


def path_to_tokens(path):
    tokens = []
    parent, base = os.path.split(path)
    if base:
        tokens.append(base)
    while parent != PATH_SEPARATOR:
        parent, base = os.path.split(parent)
        if base:
            tokens.append(base)
    tokens.append(PATH_SEPARATOR)
    tokens.reverse()
    return tokens


def find_common_dir(dir1, dir2):
    dir1_tokens = path_to_tokens(dir1)
    dir2_tokens = path_to_tokens(dir2)
    len1 = len(dir1_tokens)
    len2 = len(dir2_tokens)
    result = []
    j = i = 0
    while i <= len1 - 1 and j <= len2 - 1:
        if dir1_tokens[i] != dir2_tokens[j]:
            break
        result.append(dir1_tokens[i])
        i += 1
        j += 1
    return os.path.join(*tuple(result))


def get_file_distribution(provider_host, file_id):
    get_file_distribution_endpoint = ONEPROVIDER_REST_FORMAT.format(provider_host, FILE_DISTRIBUTION_PATH.format(file_id))
    response = requests.get(get_file_distribution_endpoint, headers=HEADERS, verify=(not args.disable_cert_verification))
    if response.status_code == HTTPStatus.OK:
        return response.json()


def wait_for_synchronization_of_files(files_sizes, destination_host, src_provider_id, attempts):
    for file_id, file_size in files_sizes.items():
        wait_for_synchronization_of_file(file_id, file_size, destination_host, src_provider_id, attempts)


def wait_for_synchronization_of_file(file_id, expected_file_size, destination_host, src_provider_id, attempts):
    if attempts == 0:
        raise Exception("File {0} not synchronized, coult not schedule transfer".format(file_id))
    else:
        file_distribution = get_file_distribution(destination_host, file_id)
        if file_distribution:
            src_provider_file_distribution = find_provider_file_distribution(file_distribution, src_provider_id)
            if src_provider_file_distribution and src_provider_file_distribution['totalBlocksSize'] == expected_file_size:
                return
            else:
                time.sleep(1)
                wait_for_synchronization_of_file(file_id, expected_file_size, destination_host, src_provider_id, attempts - 1)
        else:
            time.sleep(1)
            wait_for_synchronization_of_file(file_id, expected_file_size, destination_host, src_provider_id,
                                             attempts - 1)


def find_provider_file_distribution(file_distribution, provider_id):
    for element in file_distribution:
        if element['providerId'] == provider_id:
            return element


def lookup_provider_id(provider_host):
    get_provider_info_endpoint = ONEPROVIDER_REST_FORMAT.format(provider_host, PROVIDER_INFO)
    response = requests.get(get_provider_info_endpoint, headers=HEADERS, verify=(not args.disable_cert_verification))
    return response.json()['providerId']


args = parser.parse_args()

TEMP_DIR = tempfile.mkdtemp(dir=".", prefix=".")
REGISTER_FILE_ENDPOINT = ONEPROVIDER_REST_FORMAT.format(args.host, REGISTER_FILE_PATH)
SCHEDULE_TRANSFER_ENDPOINT = ONEPROVIDER_REST_FORMAT.format(args.host, SCHEDULE_TRANSFER_PATH)
HEADERS = {'X-Auth-Token': args.token, "content-type": "application/json"}

total_size = 0
total_count = 0
parent_dir = None
files_sizes = dict()

try:
    for bag_path in args.bag_paths:
        print("Registering files from bag: ", bag_path)
        bag_path, should_remove_extracted_bag = ensure_bag_extracted(bag_path)
        if bag_path:
            all_checksums = collect_all_checksums(bag_path)
            files_json_metadata = prepare_metadata_json(bag_path)
            with open(os.path.join(bag_path, FILES_INDEX), 'r') as f:
                i = 0
                for line in f:
                    [file_uri, size, file_path] = line.split()
                    xattrs = prepare_checksum_xattrs(file_path, all_checksums)
                    checksum_xattrs = prepare_checksum_xattrs(file_path, all_checksums)
                    file_json_metadata = get_file_custom_json_metadata(file_path, files_json_metadata)
                    result = register_file(file_path, file_uri, size, checksum_xattrs, file_json_metadata)
                    if result:
                        destination_path, file_id, file_size = result
                        files_sizes[file_id] = file_size
                        total_count += 1
                        total_size += int(size)
                        tmp_parent_dir = os.path.dirname(destination_path)
                        if not parent_dir:
                            parent_dir = tmp_parent_dir
                        else:
                            parent_dir = find_common_dir(parent_dir, tmp_parent_dir)
                    i += 1
                    if args.logging_freq and i % args.logging_freq == 0 and i > 0:
                        print("Processed {0} files".format(i))

        if should_remove_extracted_bag:
            shutil.rmtree(os.path.dirname(bag_path), ignore_errors=True)

    print("\nTotal registered files count: {0}".format(total_count))
    print("Total size: {0}".format(total_size))

    if args.destination_host:
        print("\nWaiting for all registered files to be synchronized to provider: {0}".format(args.destination_host))
        destination_provider_id = lookup_provider_id(args.destination_host)
        src_provider_id = lookup_provider_id(args.host)
        wait_for_synchronization_of_files(files_sizes, args.destination_host, src_provider_id, args.sync_timeout)
        print("\nScheduling transfer of directory: {0}".format(parent_dir))
        space_name = get_space_name(args.space_id)
        dir_id = lookup_file_id(space_name, parent_dir)
        transfer_id = schedule_transfer_job(dir_id, destination_provider_id)
        print("Scheduled transfer: {0}".format(transfer_id))

finally:
    shutil.rmtree(TEMP_DIR, ignore_errors=True)
