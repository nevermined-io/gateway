#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0


class ConfigSections:
    KEEPER_CONTRACTS = 'keeper-contracts'
    RESOURCES = 'resources'
    OSMOSIS = 'osmosis'


class BaseURLs:
    BASE_GATEWAY_URL = '/api/v1/gateway'
    SWAGGER_URL = '/api/v1/docs'  # URL for exposing Swagger UI (without trailing '/')
    ASSETS_URL = BASE_GATEWAY_URL + '/services'


class Metadata:
    TITLE = 'GATEWAY'
    DESCRIPTION = 'Gateway is the technical component executed by Publishers allowing them to ' \
                  'provide extended data services. When running with our Docker images, ' \
                  'it is exposed under `http://localhost:8030`.'
    HOST = 'myfancygateway.com'
