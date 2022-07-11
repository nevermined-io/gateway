"""Config data."""
import configparser
import json
import logging
import os
from pathlib import Path

DEFAULT_NAME_METADATA_URL = 'http://172.17.0.1:3100'

NAME_KEEPER_URL = 'keeper.url'
NAME_KEEPER_PATH = 'keeper.path'
NAME_AUTH_TOKEN_MESSAGE = 'auth_token_message'
NAME_AUTH_TOKEN_EXPIRATION = 'auth_token_expiration'

NAME_SECRET_STORE_URL = 'secret_store.url'
NAME_PARITY_URL = 'parity.url'
NAME_COMPUTE_API_URL = 'compute_api.url'

KEYTRANSFER_ZKEY_FILE = 'zkey'
KEYTRANSFER_DAT_FILE = 'dat'
NAME_METADATA_URL = 'metadata.url'

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
    KEYTRANSFER_ZKEY_FILE: ['KEYTRANSFER_ZKEY_FILE', 'zkey file for keytransfer'],
    KEYTRANSFER_DAT_FILE: ['KEYTRANSFER_DAT_FILE', 'dat file for keytransfer'],
    NAME_METADATA_URL: ['METADATA_URL', 'Metadata URL'],
}

upload_backends = {
    'ipfs': 'ipfs://',
    'filecoin': 'cid://',
    's3': 's3://',
    'azure': 'core.windows.net',
    'onprem': 'onprem'
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
        self._external_contracts_section = 'external-contracts'
        self._external_contracts = []
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

        if self._external_contracts_section in self:
            for k, v in self[self._external_contracts_section].items():
                name = k
                address, artifact_path = json.loads(v)
                abi = self._get_abi_from_artifact(artifact_path)
                self._external_contracts.append((address, abi, name))

        self._load_environ()

    def _load_environ(self):
        for option_name, environ_item in environ_names.items():
            value = os.environ.get(environ_item[0])
            if value is not None:
                self._logger.debug(f'Config: setting environ {option_name} = {value}')
                self.set(self._section_name, option_name, value)

    @staticmethod
    def _get_abi_from_artifact(artifact_path):
        with Path(artifact_path).expanduser().resolve() as p:
            return json.loads(p.read_text())['abi']

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
    def keytransfer_zkey(self):
        return self.get('snark', KEYTRANSFER_ZKEY_FILE, fallback='/usr/local/share/keytransfer/keytransfer.zkey')

    @property
    def keytransfer_dat(self):
        return self.get('snark', KEYTRANSFER_DAT_FILE, fallback='/usr/local/share/keytransfer/keytransfer.dat')

    @property
    def auth_token_expiration(self):
        return self.get('resources', NAME_AUTH_TOKEN_EXPIRATION, fallback=None)

    @property
    def ldap_url(self):
        """URL of the ldap server"""
        return self.get("identity-ldap", "ldap.url", fallback=None)

    @property
    def ldap_user(self):
        """User to login to the LDAP server"""
        return self.get("identity-ldap", "ldap.user", fallback=None)

    @property
    def ldap_password(self):
        """Password to login to the LDAP server"""
        return self.get("identity-ldap", "ldap.password", fallback=None)

    @property
    def ldap_address_key(self):
        """The attribute name under which the user's ethereum address is stored"""
        return self.get("identity-ldap", "ldap.address.key", fallback=None)

    @property
    def ldap_dns(self):
        """A list of Distinguished Names to be queried when searching for a user"""
        dns = self.get("identity-ldap", "ldap.dns", fallback=None)
        return dns.split() if dns else []

    @property
    def external_contracts(self):
        return self._external_contracts