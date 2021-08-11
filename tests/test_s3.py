from pathlib import Path
from nevermined_gateway.constants import BaseURLs
from common_utils_py.oauth2.token import NeverminedJWTBearerGrant, generate_download_grant_token
from tests.utils import get_registered_ddo, write_s3


def test_s3(client, provider_account):
    # write file to s3
    s3_url = write_s3()
    ddo = get_registered_ddo(provider_account, providers=[provider_account.address], url=s3_url)
    index = 0

    # generate the grant token
    grant_token = generate_download_grant_token(provider_account, ddo.did)

    # request access token
    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": grant_token
    })
    access_token = response.get_json()["access_token"]

    endpoint = BaseURLs.ASSETS_URL + '/download/%d' % (index)
    print(endpoint)
    response = client.get(
        endpoint,
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status == '200 OK'

    expected_file = Path(__file__).parent / "resources/TEST.md"
    assert response.data == expected_file.read_bytes()