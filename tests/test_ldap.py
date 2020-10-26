from nevermined_gateway.identity.ldap import IdentityLdap

ALICE_ADDRESS = "0x068ed00cf0441e4829d9784fcbe7b9e26d4bd8d0"
BOB_ADDRESS = "0xa99d43d86a0758d5632313b8fa3972b6088a21bb"
JOHN_ADDRESS = "0x00a329c0648769A73afAc7F9381E08FB43dBEA72"
INVALID_ADDRESS = "0000000000000000000000000000000000000000"


def test_single_user():
    identity = IdentityLdap(
        "localhost:1389",
        "cn=admin,dc=nevermined,dc=io",
        "nevermined",
        [
            "ou=People,ou=groups,dc=nevermined,dc=io",
            "ou=acme,ou=external,ou=groups,dc=nevermined,dc=io",
        ],
    )

    # search Alice
    credentials_subject = [{"id": ALICE_ADDRESS, "type": "User"}]
    assert identity.is_member_of(ALICE_ADDRESS, credentials_subject) is True

    # search Bob
    credentials_subject = [{"id": BOB_ADDRESS, "type": "User"}]
    assert identity.is_member_of(BOB_ADDRESS, credentials_subject) is True

    # search John
    credentials_subject = [{"id": JOHN_ADDRESS, "type": "User"}]
    assert identity.is_member_of(JOHN_ADDRESS, credentials_subject) is True

    # search for existing user with invalid address
    credentials_subject = [{"id": ALICE_ADDRESS, "type": "User"}]
    assert identity.is_member_of(INVALID_ADDRESS, credentials_subject) is False

    # search Bob when only Alice has access
    credentials_subject = [{"id": ALICE_ADDRESS, "type": "User"}]
    assert identity.is_member_of(BOB_ADDRESS, credentials_subject) is False


def test_group():
    identity = IdentityLdap(
        "localhost:1389",
        "cn=admin,dc=nevermined,dc=io",
        "nevermined",
        [
            "ou=People,ou=groups,dc=nevermined,dc=io",
            "ou=acme,ou=external,ou=groups,dc=nevermined,dc=io",
        ],
    )

    # only the sales group has access and only Alice belongs to group
    credentials_subject = [{"id": "sales", "type": "Group"}]
    assert identity.is_member_of(ALICE_ADDRESS, credentials_subject) is True
    assert identity.is_member_of(BOB_ADDRESS, credentials_subject) is False
    assert identity.is_member_of(JOHN_ADDRESS, credentials_subject) is False

    # only the finance group has access and only Bob belongs to group
    credentials_subject = [{"id": "finance", "type": "Group"}]
    assert identity.is_member_of(ALICE_ADDRESS, credentials_subject) is False
    assert identity.is_member_of(BOB_ADDRESS, credentials_subject) is True
    assert identity.is_member_of(JOHN_ADDRESS, credentials_subject) is False


def test_group_or_users():
    identity = IdentityLdap(
        "localhost:1389",
        "cn=admin,dc=nevermined,dc=io",
        "nevermined",
        [
            "ou=People,ou=groups,dc=nevermined,dc=io",
            "ou=acme,ou=external,ou=groups,dc=nevermined,dc=io",
        ],
    )

    # only John or people from the sales group have access
    # Bob should be the only one denied access
    credentials_subject = [
        {"id": JOHN_ADDRESS, "type": "User"},
        {"id": "sales", "type": "Group"},
    ]
    assert identity.is_member_of(ALICE_ADDRESS, credentials_subject) is True
    assert identity.is_member_of(BOB_ADDRESS, credentials_subject) is False
    assert identity.is_member_of(JOHN_ADDRESS, credentials_subject) is True
