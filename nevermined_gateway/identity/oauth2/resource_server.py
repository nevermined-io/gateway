from authlib.integrations.flask_oauth2 import ResourceProtector
from nevermined_gateway.identity.oauth2.token import NeverminedJWTTokenValidator


def create_resource_server():
    resource_protector = ResourceProtector()
    resource_protector.register_token_validator(NeverminedJWTTokenValidator())

    return resource_protector