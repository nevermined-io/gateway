from nevermined_gateway.identity.oauth2.token import NeverminedJWTBearerGrant, genereate_access_token
from authlib.integrations.flask_oauth2.authorization_server import AuthorizationServer


def save_token(_token_data, _request):
    """This is a required method of the authorization server but in our case
    we are not storing the tokens."""
    pass


def create_authorization_server(app):
    app.config["OAUTH2_ACCESS_TOKEN_GENERATOR"] = genereate_access_token
    authorization = AuthorizationServer(app, save_token=save_token)
    authorization.register_grant(NeverminedJWTBearerGrant)
    
    return authorization