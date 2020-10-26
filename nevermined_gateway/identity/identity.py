"""Nevermined Identity interface"""

from abc import ABC, abstractmethod


class Identity(ABC):
    """Nevermined gateway identity interface.

    This is an abstract class defining the methods that need to be implemented when
    writing an integration with an identity service like LDAP or Active Directory.

    """

    @abstractmethod
    def is_member_of(self, address, credentials_subject):
        """Check if a user with `address` is a member of the Identity server.

        Makes use of the `credentialsSubject` section of the DDO Verifiable Credential to
        create a query to the Identity server.

        Args:
            address (str): The ethereum address to check.
            credentials_subject (:obj:`list` of :obj:`dict`): A list of credential subjects
                that have permissions to access.

        Returns:
            bool: True if the user with `address` is a credential subject and exists
                in the Identity server. False otherwise.

        """
