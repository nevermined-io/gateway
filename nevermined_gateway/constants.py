import enum


class ConfigSections:
    KEEPER_CONTRACTS = 'nevermined-contracts'
    RESOURCES = 'resources'
    METADATA_DRIVER = 'metadata-driver'
    DECRYPTION_METHODS = ['SecretStore', 'PSK-RSA', 'PSK-ECDSA']
    DEFAULT_DECRYPTION_METHOD = 'SecretStore'
    PING_ITERATIONS = 15
    PING_SLEEP = 1500


class ConditionState(enum.Enum):
    Uninitialized = 0
    Unfulfilled = 1
    Fulfilled = 2
    Aborted = 3


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
