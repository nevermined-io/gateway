"""Config data."""
import configparser
import logging
import os
from pathlib import Path

NAME_KEEPER_URL = 'keeper.url'
NAME_KEEPER_PATH = 'keeper.path'
NAME_AUTH_TOKEN_MESSAGE = 'auth_token_message'
NAME_AUTH_TOKEN_EXPIRATION = 'auth_token_expiration'

NAME_SECRET_STORE_URL = 'secret_store.url'
NAME_PARITY_URL = 'parity.url'
NAME_COMPUTE_API_URL = 'compute_api.url'

environ_names = {
    NAME_KEEPER_URL: ['KEEPER_URL', 'Keeper URL'],
    NAME_KEEPER_PATH: ['KEEPER_PATH', 'Path to the keeper contracts'],
    NAME_AUTH_TOKEN_MESSAGE: ['AUTH_TOKEN_MESSAGE',
                              'Message to use for generating user auth token'],
    NAME_AUTH_TOKEN_EXPIRATION: ['AUTH_TOKEN_EXPIRATION',
                                 'Auth token expiration time expressed in seconds'],
    NAME_SECRET_STORE_URL: ['SECRET_STORE_URL', 'Secret Store URL'],
    NAME_PARITY_URL: ['PARITY_URL', 'Parity URL'],
    NAME_COMPUTE_API_URL: ['COMPUTE_API_URL', 'Compute API URL'],
}


class Config(configparser.ConfigParser):
    """Class to manage the squid-py configuration."""

    def __init__(self, filename=None, options_dict=None, **kwargs):
        """
        Initialize Config class.

        Options available:

        [nevermined-contracts]
        keeper.url = http://localhost:8545                            # nevermined-contracts url.
        keeper.path = artifacts                                       # Path of json abis.
        secret_store.url = http://localhost:12001                     # Secret store url.
        parity.url = http://localhost:8545                            # Parity client url.
        [resources]
        gateway.url = http://localhost:8030                             # Gateway url.

        :param filename: Path of the config file, str.
        :param options_dict: Python dict with the config, dict.
        :param kwargs: Additional args. If you pass text, you have to pass the plain text
        configuration.
        """
        configparser.ConfigParser.__init__(self)

        self._section_name = 'nevermined-contracts'
        self._logger = logging.getLogger('config')

        if filename:
            self._logger.debug(f'Config: loading config file {filename}')
            with open(filename) as fp:
                text = fp.read()
                self.read_string(text)
        else:
            if 'text' in kwargs:
                self.read_string(kwargs['text'])

        if options_dict:
            self._logger.debug(f'Config: loading from dict {options_dict}')
            self.read_dict(options_dict)

        self._load_environ()

    def _load_environ(self):
        for option_name, environ_item in environ_names.items():
            value = os.environ.get(environ_item[0])
            if value is not None:
                self._logger.debug(f'Config: setting environ {option_name} = {value}')
                self.set(self._section_name, option_name, value)

    @property
    def keeper_path(self):
        """Path where the nevermined-contracts artifacts are allocated."""
        keeper_path_string = self.get(self._section_name, NAME_KEEPER_PATH, fallback=None)
        return Path(keeper_path_string).expanduser().resolve() if keeper_path_string else ''

    @property
    def keeper_url(self):
        """URL of the keeper. (e.g.): http://mykeeper:8545."""
        return self.get(self._section_name, NAME_KEEPER_URL, fallback=None)

    @property
    def secret_store_url(self):
        """URL of the secret store component. (e.g.): http://mysecretstore:12001."""
        return self.get(self._section_name, NAME_SECRET_STORE_URL, fallback=None)

    @property
    def parity_url(self):
        """URL of parity client. (e.g.): http://myparity:8545."""
        return self.get(self._section_name, NAME_PARITY_URL, fallback=None)

    @property
    def compute_api_url(self):
        """URL of the compute api service component. (e.g.): http://compute-api:8050."""
        return self.get(self._section_name, NAME_COMPUTE_API_URL, fallback=None)

    @property
    def auth_token_message(self):
        return self.get('resources', NAME_AUTH_TOKEN_MESSAGE, fallback=None)

    @property
    def auth_token_expiration(self):
        return self.get('resources', NAME_AUTH_TOKEN_EXPIRATION, fallback=None)
