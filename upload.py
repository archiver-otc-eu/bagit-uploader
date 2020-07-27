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
from http import HTTPStatus
from bdbag import bdbag_api

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FILES_INDEX = "fetch.txt"
CHECKSUM_MANIFEST_FORMAT = "manifest-{0}.txt"
MD5 = "md5"
SHA1 = "sha1"
SHA256 = "sha256"
SHA512 = "sha512"
HASHING_ALGORITHMS = [MD5, SHA1, SHA256, SHA512]

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
    '--destination-provider-id', '-dpid',
    action='store',
    help='Id of a Oneprovider to which files will be replicated after registration. If not passed, replication won\'t be performed.',
    dest='destination_provider_id',
    default=None
)

ONEPROVIDER_REST_FORMAT = "https://{0}/api/v3/oneprovider/{1}"
REGISTER_FILE_PATH = "data/register"
SCHEDULE_TRANSFER_PATH = "transfers"
LOOKUP_FILE_ID_PATH = "lookup-file-id/{0}/{1}"
SPACE_DETAILS_PATH = "spaces/{0}"

def strip_server_url(storage_file_id):
    parsed_url = urlparse(storage_file_id)
    if parsed_url.scheme:
        return parsed_url.path
    else:
        return storage_file_id


def register_file(destination_path, storage_file_id, size, xattrs):
    storage_file_id = strip_server_url(storage_file_id)
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
    try:
        response = requests.post(REGISTER_FILE_ENDPOINT, json=payload, headers=HEADERS, verify=(not args.disable_cert_verification))
        if response.status_code == HTTPStatus.CREATED:
            return destination_path
        else:
            logging.error("Registration of {0} failed with HTTP status {1}.\n""Response: {2}"
                          .format(storage_file_id, response.status_code, response.content)),
            return False
    except Exception as e:
        logging.error("Registration of {0} failed due to {1}".format(storage_file_id, e), exc_info=True)


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


def ensure_bag_extracted(bag_path):
    try:
        (is_file, is_dir, is_uri) = bdbag_api.inspect_path(bag_path)
        if is_file:
            bag_path = extract_bag_archive(bag_path)
            return ensure_bag_extracted(bag_path)
        elif is_dir and bdbag_api.is_bag(bag_path):
            # bag_path is already a path to a correct bag structure
            return bag_path
        elif is_uri:
            bag_path = download(bag_path)
            return ensure_bag_extracted(bag_path)
        else:
            logging.error("Passed path {0} to bag that does not exist or is not a valid bag.".format(bag_path))
            return None
    except:
        logging.error("Passed path {0} to bag that does not exist or is not a valid bag.".format(bag_path),
                      exc_info=True)
        return None


def extract_bag_archive(bag_archive_path):
    return bdbag_api.extract_bag(bag_archive_path, temp=True)


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


def longest_common_prefix(str1, str2):
    len1 = len(str1)
    len2 = len(str2)
    result = ""
    j = i = 0
    while i <= len1 - 1 and j <= len2 - 1:
        if str1[i] != str2[j]:
            break
        result += (str1[i])
        i += 1
        j += 1
    return result


args = parser.parse_args()

TEMP_DIR = tempfile.mkdtemp(dir=".", prefix=".")
REGISTER_FILE_ENDPOINT = ONEPROVIDER_REST_FORMAT.format(args.host, REGISTER_FILE_PATH)
SCHEDULE_TRANSFER_ENDPOINT = ONEPROVIDER_REST_FORMAT.format(args.host, SCHEDULE_TRANSFER_PATH)
HEADERS = {'X-Auth-Token': args.token, "content-type": "application/json"}

total_size = 0
total_count = 0
parent_dir = None

try:
    for bag_path in args.bag_paths:
        print("Registering files from bag: ", bag_path)
        bag_path = ensure_bag_extracted(bag_path)
        if bag_path:
            all_checksums = collect_all_checksums(bag_path)
            with open(os.path.join(bag_path, FILES_INDEX), 'r') as f:
                i = 0
                for line in f:
                    [file_uri, size, file_path] = line.split()
                    xattrs = prepare_checksum_xattrs(file_path, all_checksums)
                    destination_path = register_file(file_path, file_uri, size, prepare_checksum_xattrs(file_path, all_checksums))
                    if destination_path:
                        total_count += 1
                        total_size += int(size)
                        tmp_parent_dir = os.path.dirname(destination_path)
                        print(destination_path)
                        if not parent_dir:
                            parent_dir = tmp_parent_dir
                        else:
                            parent_dir = longest_common_prefix(parent_dir, tmp_parent_dir)
                    i += 1
                    if args.logging_freq and i % args.logging_freq == 0 and i > 0:
                        print("Processed {0} files".format(i))

    print("\nTotal registered files count: {0}".format(total_count))
    print("Total size: {0}".format(total_size))
    print("Scheduling transfer of directory {0}".format(parent_dir))

    if args.destination_provider_id:
        space_name = get_space_name(args.space_id)
        dir_id = lookup_file_id(space_name, parent_dir)
        transfer_id = schedule_transfer_job(dir_id, args.destination_provider_id)
        print("Scheduled transfer: {0}".format(transfer_id))

finally:
    shutil.rmtree(TEMP_DIR, ignore_errors=True)
