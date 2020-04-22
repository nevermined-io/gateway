#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0


class ConfigSections:
    KEEPER_CONTRACTS = 'keeper-contracts'
    RESOURCES = 'resources'
    OSMOSIS = 'osmosis'


class BaseURLs:
    BASE_BRIZO_URL = '/api/v1/brizo'
    SWAGGER_URL = '/api/v1/docs'  # URL for exposing Swagger UI (without trailing '/')
    ASSETS_URL = BASE_BRIZO_URL + '/services'


class Metadata:
    TITLE = 'Brizo'
    DESCRIPTION = 'Brizo is the technical component executed by Publishers allowing them to ' \
                  'provide extended data services. When running with our Docker images, ' \
                  'it is exposed under `http://localhost:8030`.'
    HOST = 'myfancybrizo.com'
