"""LDAP Identity Plugin"""

from ldap3 import ALL, Connection, Server

from nevermined_gateway.identity import Identity


class LDAPIdentity(Identity):
    def __init__(self, url, user, password, ldap_dns, address_key="registeredAddress"):
        """Connect to LDAP.

        Sets up a connection to LDAP.

        Args:
            url (str): The url of the LDAP server.
            user (str): The user to login to the LDAP server.
            password (str): The login password.
            ldap_dns (:obj:`list` of :obj:`str`): A list of Distinguished Names to be used
                when querying LDAP. They will be queried in order and return after the first
                success.
            address_key (str, optional): The name of the attribute under which is the user's
                ethereum address.

        """
        self._server = Server(url, get_info=ALL)
        self._conn = Connection(
            self._server, user=user, password=password, auto_bind=True
        )
        self._address_key = address_key
        self._ldap_dns = ldap_dns

    def is_member_of(self, address, credentials_subject):
        """Check if a user with `address` is a member of the LDAP server.

        Makes use of the `credentialsSubject` section of the DDO Verifiable Credential to
        create a filter to query the LDAP server.

        Args:
            address (str): The ethereum address to check.
            credentials_subject (:obj:`list` of :obj:`dict`): A list of credential subjects
                that have permissions to access.

        Returns:
            bool: True if the user with `address` is a credential subject and exists
                in the LDAP server. False otherwise.

        """
        for dn in self._ldap_dns:
            filter_ = self._build_filter(address, credentials_subject)
            result = self._conn.search(dn, filter_)
            if result is True:
                return True

        return False

    def _build_filter(self, address, credentials_subject):
        """Build a filter based on the `address` and `credentialsSubject` section of the DDO.

        This filter will always check if there is a user with `address` in the LDAP server
        that is a subject of the credentials.

        Example of a filter assuming address=0x123:
            ```
            (&
                (registeredAddress=0x123)
                (|
                    (registeredAddress=0x123)
                    (registeredAddress=0x456)
                    (memberOf=ou=sales,ou=groups,dc=nevermined,dc=io)
                )

            )

            ```

        Args:
            address (str): The ethereum address to check.
            credentials_subject (:obj:`list` of :obj:`dict`): A list of credential subjects
                that have permissions to access.

        Returns:
            str: The LDAP query filter.


        """
        queries = ""
        for subject in credentials_subject:
            if subject["type"] == "User":
                queries += f"({self._address_key}={subject['id']})"
            elif subject["type"] == "Group":
                queries += (
                    f"(memberOf=ou={subject['id']},ou=groups,dc=nevermined,dc=io)"
                )

        filter_ = f"(&({self._address_key}={address})(|" + queries + "))"
        return filter_
