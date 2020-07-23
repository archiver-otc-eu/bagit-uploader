# bagit-uploader
This repository contains script for registering files stored in [BagIt](https://datatracker.ietf.org/doc/rfc8493/) 
format in the Onedata system. 

The files are registered using Oneprovider [REST API](https://onedata.org/#/home/api/stable/oneprovider?anchor=operation/register_file).

## Getting started

Required packages can be installed using pip:
```bash
pip install -r requirements.txt
``` 

## Arguments

Script has the following list of **required** arguments:
* `-H`, `--host` - Oneprovider host.
* `-spi`, `--space-id` - Id of the space in which the files will be registered.
* `-sti`, `--storage-id` - Id of the storage on which the files are located.
                        Storage must be created as an `imported` storage with
                        path type equal to `canonical`.
* `-t`, `--token` - Onedata access token.
* `-b`, `--bag-path` - Path to BagIt bag. It can be path to a bag archive (supported formats: `zip`, `tar`, `tgz`), extracted bag directory or URL to a bag archive. 
Many bag paths can be passed (e.g. `-b BAG_PATH1 -b BAG_PATH2`).

Additionally, script has the following list of **optional** arguments:
* `-m`, `--file-mode` - POSIX mode with which files will be registered, represented as an octal string (default: `"664"`)
* `-dd`, `--disable-auto-detection` - Flag which disables automatic detection of file attributes and verification whether file exists on storage.
Passing this flag results in faster registration of files but there is a risk of registering files that don't exist on storage.
Such files will be visible in the space but not accessible.
* `-dv`, `--disable-cert-verification` - Flag which disables verification of SSL certificate.
* `-lf`, `--logging-frequency` - Frequency of logging. Log will occur after registering every logging_freq number of files.

## Usage
```bash
./upload.py -spi $SPACE_ID -sti $STORAGE_ID -t $TOKEN -H $HOST \ 
 -b bag_archiver_test_2014_11_15.tgz \
 -b bag_archiver_test_2017_10_11 \
 -b https://example.org/bag_archiver_test_2015_01_25.tgz
```