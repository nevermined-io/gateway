[![banner](https://raw.githubusercontent.com/keyko-io/assets/master/images/logo/small/keyko_logo@2x-100.jpg)](https://keyko.io)

# Nevermined Gateway

> Nevermined gate keeper helping to data publishers & owners to provide extended data services
> [keyko.io](https://keyko.io/)


[![Docker Build Status](https://img.shields.io/docker/cloud/build/keykoio/nevermined-gateway.svg)](https://hub.docker.com/r/keykoio/nevermined-gateway/)
[![GitHub contributors](https://img.shields.io/github/contributors/keyko-io/nevermined-gateway.svg)](https://github.com/keyko-io/nevermined-gateway/graphs/contributors)


## Table of Contents

  - [Features](#features)
  - [Running Locally, for Dev and Test](#running-locally-for-dev-and-test)
  - [API documentation](#api-documentation)
  - [Configuration](#configuration)
     - [The [keeper-contracts] and [resources] Sections](#the-keeper-contracts-and-resources-sections)
     - [The [osmosis] Section](#the-osmosis-section)
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
git clone git@github.com:keyko-io/nevermined-gateway.git
cd nevermined-gateway/
```

Then run some things that Nevermined Gateway expects to be running:

```bash
git clone git@github.com:keyko-io/nevermined-tools.git
cd nevermined-tools
bash start_nevermined.sh --no-gateway --local-spree-node
```

Nevermined Tools is the repository where all the Nevermined Docker Compose files are located. 
We are running the script `start_nevermined.sh`: the easy way to have Nevermined projects 
up and running. We run without Gateway instance.

To learn more about Nevermined Tools, visit [the Tools repository](https://github.com/keyko-io/nevermined-tools).

Note that it runs an Nevermined Metadata instance and an Elasticsearch instance but Nevermined Metadata can 
also work with MongoDB.

The most simple way to start is:

```bash
pip install -r requirements_dev.txt
export FLASK_APP=nevermined_gateway/run.py
export CONFIG_FILE=config.ini
./scripts/wait_for_migration_and_extract_keeper_artifacts.sh
flask run --port=8030
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
there are three sections: `[keeper-contracts]`, `[resources]` and `[osmosis]`.

### The [keeper-contracts] and [resources] Sections

The `[keeper-contracts]` section is used to setup connection to the keeper nodes and load keeper-contracts artifacts.
The `[resources]` sections is used to configure Aquarius and Brizo services. 

### The [osmosis] Section

The `[osmosis]` section of the config file is where a publisher puts their own credentials for various third-party services, such as Azure Storage.
At the time of writing, Brizo could support files with three kinds of URLs:

- files in Azure Storage: files with "core.windows.net" in their URLs
- files in Amazon S3 storage: files with "s3://" in their URLs
- files in on-premise storage: all other files with resolvable URLs

Initial work has also been done to support Azure Compute but it's not officially supported yet.

A publisher can choose to support none, one, two or all of the above. It depends on which cloud providers they use.

If a publisher wants to store some files in Azure Storage (and make them available 
from there), then they must get and set the following config settings in the [osmosis] 
section of the config file. 

```ini
[osmosis]
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
file. The only requirement is that the file URLs must be resolvable by Brizo. 

## Dependencies

Nevermined Gateway relies on the following Ocean libraries:

- [common-utils-py](https://github.com/keyko-io/common-utils-py) provides common functions and datastructures for interaction with the Ocean Protocol components
- [contracts-lib-py](https://github.com/keyko-io/contracts-lib-py) handles all of the `keeper` interactions
- [ocean-secret-store-client](https://github.com/oceanprotocol/secret-store-client-py) to encrypt/decrypt the dataset urls
- [osmosis-azure-driver](https://github.com/oceanprotocol/osmosis-azure-driver) mediates access to assets in Azure
- [osmosis-aws-driver](https://github.com/oceanprotocol/osmosis-aws-driver) mediates access to assets in AWS
- [osmosis-on-premise-driver](https://github.com/oceanprotocol/osmosis-on-premise-driver) mediates access to on-premise assets

## Testing

Automatic tests are setup via Github actions.
Our tests use the pytest framework.


## New Version

The `bumpversion.sh` script helps to bump the project version. You can execute 
the script using as first argument {major|minor|patch} to bump accordingly the version.

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
