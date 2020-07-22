#!/usr/bin/env python3

import argparse
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

parser = argparse.ArgumentParser(
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    description='Register files in the Onedata system')

requiredNamed = parser.add_argument_group('required named arguments')

requiredNamed.add_argument(
    '-H', '--host',
    action='store',
    help='Oneprovider host',
    dest='host',
    required=True)

requiredNamed.add_argument(
    '-spi', '--space-id',
    action='store',
    help='Id of the space in which the file will be registered.',
    dest='space_id',
    required=True)

requiredNamed.add_argument(
    '-sti', '--storage-id',
    action='store',
    help='Id of the storage on which the file is located. Storage must be created as an `imported` storage with path type equal to `canonical`.',
    dest='storage_id',
    required=True)

requiredNamed.add_argument(
    '-t', '--token',
    action='store',
    help='Onedata access token',
    dest='token',
    required=True)

requiredNamed.add_argument(
    '-b', '--bag-path',
    action='append',
    help='Path to bag. It can be path to a bag archive, extracted bag directory or URI to a bag archive.',
    dest='bag_paths',
    required=True)

requiredNamed.add_argument(
    '-m', '--file-mode',
    action='store',
    help='POSIX mode with which files will be registered, represented as an octal string',
    dest='mode',
    default="664"
)

requiredNamed.add_argument(
    '-dd', '--disable-auto-detection',
    action='store_true',
    help='Do not automatically detect file attributes and do not check whether file exists on storage.',
    dest='disable_auto_detection',
    default=False
)

parser.add_argument(
    '-logging', '--logging-frequency',
    action='store',
    type=int,
    help='Frequency of logging. Log will occur after registering every logging_freq number of files',
    dest='logging_freq',
    default=None)

requiredNamed.add_argument(
    '-dv', '--disable-cert-verification',
    action='store_true',
    help='Do not verify SSL certificate',
    dest='disable_cert_verification',
    default=False)

REGISTER_FILE_ENDPOINT = "https://{0}/api/v3/oneprovider/data/register"


def strip_server_url(storage_file_id):
    parsed_url = urlparse(storage_file_id)
    if parsed_url.scheme:
        return parsed_url.path
    else:
        return storage_file_id


def register_file(destination_path, storage_file_id, size, xattrs):
    headers = {
        'X-Auth-Token': args.token,
        "content-type": "application/json"
    }
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
        endpoint = REGISTER_FILE_ENDPOINT.format(args.host)
        response = requests.post(endpoint, json=payload, headers=headers, verify=(not args.disable_cert_verification))
        if response.status_code == HTTPStatus.CREATED:
            return True
        else:
            logging.error("Registration of {0} failed with HTTP status {1}.\n""Response: {2}"
                          .format(storage_file_id, response.status_code, response.content)),
            return False
    except Exception as e:
        logging.error("Registration of {0} failed due to {1}".format(storage_file_id, e), exc_info=True)


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


args = parser.parse_args()
total_size = 0
total_count = 0

TEMP_DIR = tempfile.mkdtemp(dir=".", prefix=".")
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
                    if register_file(file_path, file_uri, size, prepare_checksum_xattrs(file_path, all_checksums)):
                        total_count += 1
                        total_size += int(size)
                    i += 1
                    if args.logging_freq and i % args.logging_freq == 0 and i > 0:
                        print("Processed {0} files".format(i))

    print("\nTotal registered files count: {0}".format(total_count))
    print("Total size: {0}".format(total_size))

finally:
    shutil.rmtree(TEMP_DIR, ignore_errors=True)
