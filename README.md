[![banner](https://raw.githubusercontent.com/nevermined-io/assets/main/images/logo/banner_logo.png)](https://nevermined.io)


# Nevermined Gateway

> Nevermined gate keeper helping data publishers & owners to provide extended data services
> [nevermined.io](https://nevermined.io/)


[![Docker Build Status](https://img.shields.io/docker/cloud/build/neverminedio/gateway.svg)](https://hub.docker.com/r/neverminedio/gateway)
[![Python package](https://github.com/nevermined-io/gateway/workflows/Python%20package/badge.svg)](https://github.com/nevermined-io/gateway/actions)


## Table of Contents

  - [Features](#features)
  - [Running Locally, for Dev and Test](#running-locally-for-dev-and-test)
  - [API documentation](#api-documentation)
  - [Configuration](#configuration)
     - [The [nevermined-contracts] and [resources] Sections](#the-nevermined-contracts-and-resources-sections)
     - [The [metadata driver] Section](#the-metadata-driver-section)
  - [Dependencies](#dependencies)
  - [Testing](#testing)
  - [New Version](#new-version)
  - [License](#license)

---

## Features

In the Nevermined ecosystem, Gateway is the technical component executed by the Publishers
allowing them to provide extended data services (e.g. storage and compute).
Nevermined Gateway, as part of the Publisher ecosystem, includes the credentials to interact
with the infrastructure (initially cloud, but could be on-premise).

## Running Locally, for Dev and Test

If you want to contribute to the development of Nevermined Gateway, then you could do the following. (If you want to run a Nevermined Gateway in production, then you will have to do something else.)

First, clone this repository:

```bash
git clone git@github.com:nevermined-io/gateway.git
cd nevermined-gateway/
```

Then run some things that Nevermined Gateway expects to be running:

```bash
git clone git@github.com:nevermined-io/tools.git
cd nevermined-tools
bash start_nevermined.sh --no-gateway --local-spree-node
```

Nevermined Tools is the repository where all the Nevermined Docker Compose files are located.
We are running the script `start_nevermined.sh`: the easy way to have Nevermined projects
up and running. We run without Gateway instance.

To learn more about Nevermined Tools, visit [the Tools repository](https://github.com/nevermined-io/tools).

Note that it runs an Nevermined Metadata instance and an Elasticsearch instance but Nevermined Metadata can
also work with MongoDB.

The most simple way to start is:

```bash
pip install -r requirements_dev.txt

export FLASK_APP=nevermined_gateway/run.py
export PROVIDER_ADDRESS=0x00bd138abd70e2f00903268f3db08f2d25677c9e
export PROVIDER_PASSWORD=node0
export PROVIDER_KEYFILE=tests/resources/data/publisher_key_file.json
export RSA_PRIVKEY_FILE=tests/resources/data/rsa_priv_key.pem
export RSA_PUBKEY_FILE=tests/resources/data/rsa_pub_key.pem
export CONFIG_FILE=config.ini
export AUTHLIB_INSECURE_TRANSPORT=true

./scripts/wait_for_migration_and_extract_keeper_artifacts.sh
flask run --port=8030
```

You can generate the RSA private and public keys using the following commands:

```bash
openssl genrsa -out tests/resources/data/rsa_priv_key.pem 1024
openssl rsa -in tests/resources/data/rsa_priv_key.pem -pubout -out tests/resources/data/rsa_pub_key.pem
```

```bash
export PROVIDER_BABYJUB_SECRET=abc
export BUYER_BABYJUB_SECRET=abd
export PROVIDER_BABYJUB_PUBLIC1=0x2e3133fbdaeb5486b665ba78c0e7e749700a5c32b1998ae14f7d1532972602bb
export PROVIDER_BABYJUB_PUBLIC2=0x0b932f02e59f90cdd761d9d5e7c15c8e620efce4ce018bf54015d68d9cb35561
export BUYER_BABYJUB_PUBLIC1=0x0d7cdd240c2f5b0640839c49fbaaf016a8c5571b8f592e2b62ea939063545981
export BUYER_BABYJUB_PUBLIC2=0x14b14fa0a30ec744dde9f32d519c65ebaa749bfe991a32deea44b83a4e5c65bb
```

That will use HTTP (i.e. not SSL/TLS).

The proper way to run the Flask application is using an application server such as Gunicorn. This allow you to run using SSL/TLS.
You can generate some certificates for testing by doing:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

and when it asks for the Common Name (CN), answer `localhost`

Then edit the config file `config.ini` so that:

```yaml
gateway.url = https://localhost:8030
```

Then execute this command:

```bash
gunicorn --certfile cert.pem --keyfile key.pem -b 0.0.0.0:8030 -w 1 nevermined_gateway.run:app
```

## API documentation

Once you have Nevermined Gateway running you can get access to the API documentation at:

```bash
https://127.0.0.1:8030/api/v1/docs
```

## Configuration

To get configuration settings, Nevermined Gateway first checks to see if there is a non-empty
environment variable named CONFIG_FILE. It there is, it will look in a config file
at that path. Otherwise it will look in a config file named `config.ini`. Note
that some settings in the config file can be overwritten by setting certain
environment variables; there are more details below.

See the [example config.ini file in this repo](config.ini). You will see that
there are three sections: `[nevermined-contracts]`, `[resources]` and `[metadata driver]`.

### The nevermined-contracts and resources Sections

The `[nevermined-contracts]` section is used to setup connection to the blockchain nodes and load nevermined-contracts artifacts.
The `[resources]` sections is used to configure Metadata API and Gateway services.

### The [metadata driver] Section

The `[metadata driver]` section of the config file is where a publisher puts their own credentials for various third-party services, such as Azure Storage.
At the time of writing, Gateway could support files with three kinds of URLs:

- files in Azure Storage: files with "core.windows.net" in their URLs
- files in Amazon S3 storage: files with "s3://" in their URLs
- files in on-premise storage: all other files with resolvable URLs

Initial work has also been done to support Azure Compute but it's not officially supported yet.

A publisher can choose to support none, one, two or all of the above. It depends on which cloud providers they use.

If a publisher wants to store some files in Azure Storage (and make them available
from there), then they must get and set the following config settings in the [metadata-driver]
section of the config file.

```ini
[metadata-driver]
azure.account.name = <Azure Storage Account Name (for storing files)>
azure.account.key = <Azure Storage Account key>
azure.resource_group = <Azure resource group>
azure.location = <Azure Region>
azure.client.id = <Azure Application ID>
azure.client.secret = <Azure Application Secret>
azure.tenant.id = <Azure Tenant ID>
azure.subscription.id = <Azure Subscription>
; azure.share.input and azure.share.output are only used
; for Azure Compute data assets (not for Azure Storage data assets).
; If you're not supporting Azure Compute, just leave their values
; as compute and output, respectively.
azure.share.input = compute
azure.share.output = output
```

You can override any of those config file settings by setting one or more of the following environment variables. You will want to do that if you're running Brizo in a container.

```text
AZURE_ACCOUNT_NAME
AZURE_ACCOUNT_KEY
AZURE_RESOURCE_GROUP
AZURE_LOCATION
AZURE_CLIENT_ID
AZURE_CLIENT_SECRET
AZURE_TENANT_ID
AZURE_SUBSCRIPTION_ID
# Just always set AZURE_SHARE_INPUT='compute' for now
AZURE_SHARE_INPUT='compute'
# Just always set AZURE_SHARE_OUTPUT='output' for now
AZURE_SHARE_OUTPUT='output'
```

If a publisher wants to store some files in Amazon S3 storage (and make them
available from there), then there are no AWS-related config settings to set
in the config file. AWS credentials actually get stored elsewhere.

If a publisher wants to store some files on-premise (and make them available
from there), then there are no special config settings to set in the config
file. The only requirement is that the file URLs must be resolvable by the Gateway.

## Dependencies

Nevermined Gateway relies on the following libraries:

- [common-utils-py](https://github.com/nevermined-io/common-utils-py) provides common functions and data-structures for interaction with the Nevermined components
- [contracts-lib-py](https://github.com/nevermined-io/contracts-lib-py) handles all of the `keeper` interactions
- [secret-store-client](https://github.com/nevermined-io/secret-store-client-py) to encrypt/decrypt the dataset urls
- [metadata-driver-azure](https://github.com/nevermined-io/metadata-driver-azure) mediates access to assets in Azure
- [metadata-driver-aws](https://github.com/nevermined-io/metadata-driver-aws) mediates access to assets in AWS
- [metadata-driver-onprem](https://github.com/nevermined-io/metadata-driver-onprem) mediates access to on-premise assets

## Testing

Automatic tests are setup via Github actions.
Our tests use the pytest framework.


## New Version

Update the version number in [`nevermined_gateway/version.py`](https://github.com/nevermined-io/gateway/blob/master/nevermined_gateway/version.py).

## Attribution

This project is based in the [Ocean Protocol Brizo](https://github.com/oceanprotocol/brizo). It keeps the same Apache v2 License and adds some improvements.
See [NOTICE file](NOTICE).

## License

```text
Copyright 2020 Keyko GmbH
This product includes software developed at
BigchainDB GmbH and Ocean Protocol (https://www.oceanprotocol.com/)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
