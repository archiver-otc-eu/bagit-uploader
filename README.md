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
* `-dhost`, `--destination-host` - Host of a Oneprovider to which files will be replicated after registration. 
If not passed, replication won't be performed.

## Usage
```bash
./upload.py -spi $SPACE_ID -sti $STORAGE_ID -t $TOKEN -H $HOST -dhost $DEST_PROVIDER_HOST \ 
 -b bag_archiver_test_2014_11_15.tgz \
 -b bag_archiver_test_2017_10_11 \
 -b https://example.org/bag_archiver_test_2015_01_25.tgz
```

## Config file
Arguments that start with `'--'` (eg. `--host`) can also be set in a config file (by default `config.yaml`, but can be
overridden by passing `--config-file CONFIG_FILE`).
Config file syntax allows: `key: value`, `flag: true`, `stuff: [a,b,c]` (for details,
see syntax at https://goo.gl/R74nmi). If an arg is specified in more than one
place, then commandline values override config file values which override
defaults.

Example content of `config.yaml` is presented below
```yaml
host: dev-oneprovider-krakow.default.svc.cluster.local
token: MDAzM2xvY2F00aW9uIGRldi1vbmV6b25lLmRlZmF1bHQuc3ZjLmNsdXN00ZXIubG9jYWwKMDA2YmlkZW500aWZpZXIgMi9ubWQvdXNyLTE3Mjk2MDBhMjE5YTFhZjNmNjc2MmQzOGE5YWFkMWZhY2hiN2M00L2FjdC8zMzE2ODg00MDg2YTdmNDY3OTEyODNiNzM3M2E2YTE4N2NoZDE1OAowMDE5Y2lkIGludGVyZmFjZSA9IHJlc3QKMDAxOGNpZCBzZXJ2aWNlID00gb3B3LSoKMDAyZnNpZ25hdHVyZSBLJbKLSFCaMYh500ThOCROkoq5W01OHM1Yt02lvstDZJ3YQo
bag-path: [bag_archiver_test_2014_11_15.tgz, bag_archiver_test_2017_10_11, https://example.org/bag_archiver_test_2015_01_25.tgz]
storage-id: ee5eb90cb451feb7a84a8185588e31d5e2f4c308
space-id: 7b6863abad13e4191ba2bf540d553fe75cdf7117
disable-auto-detection: true
destination-host: dev-oneprovider-paris.default.svc.cluster.local
```

## Usage with config file 
```bash
./upload.py
```