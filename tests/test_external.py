import io
import os
from unittest.mock import Mock
from common_utils_py.http_requests.requests_session import get_requests_session
from nevermined_gateway.util import get_download_url, get_asset
from tests.utils import get_registered_ddo
from common_utils_py.oauth2.token import NeverminedJWTBearerGrant, generate_download_grant_token
from nevermined_gateway.constants import BaseURLs

def test_upload_download_filecoin_file(client, provider_account):
    fdata = os.urandom(10000)
    file_ = (io.BytesIO(fdata), 'test.txt')
    data = {'file': file_}
    response = client.post('/api/v1/gateway/services/upload/filecoin', data=data, content_type='multipart/form-data')

    assert response.status_code == 201
    url = response.json['url']
    assert url.startswith('cid://')
    assert len(url) > 40

    download_url = get_download_url(url, None)
    requests_session = get_requests_session()

    request = Mock()
    request.range = None

    print(f'got filecoin download url: {download_url}')
    assert download_url and download_url == url
    response = get_asset(request, requests_session, '', url, None)
    assert response.status_code == 200
    print(response.data)
    assert len(response.data) > 0

    index = 0

    ddo = get_registered_ddo(provider_account, providers=[provider_account.address], url=url)
    # generate the grant token
    grant_token = generate_download_grant_token(provider_account, ddo.did)

    # request access token
    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": grant_token
    })
    access_token = response.get_json()["access_token"]

    endpoint = BaseURLs.ASSETS_URL + '/download/%d' % (index)
    response = client.get(
        endpoint,
        headers={"Authorization": f"Bearer {access_token}"}
    )
    print(response.data)

def test_upload_encrypt_download_filecoin_file(client):

    file_ = (io.BytesIO(b"Hello, Nevermined!"), 'test.txt')
    data = {'encrypt': 'true', 'file': file_}
    response = client.post('/api/v1/gateway/services/upload/filecoin', data=data, content_type='multipart/form-data')

    assert response.status_code == 201
    url = response.json['url']
    assert 'password' in response.json
    assert url.startswith('cid://')
    assert len(url) > 40

    download_url = get_download_url(url, None)
    requests_session = get_requests_session()

    request = Mock()
    request.range = None

    print(f'got filecoin download url: {download_url}')
    assert download_url and download_url == url
    response = get_asset(request, requests_session, '', url, None)
    assert response.status_code == 200
    assert len(response.data) > 0
