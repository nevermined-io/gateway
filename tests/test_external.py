import io
from unittest.mock import Mock

from common_utils_py.http_requests.requests_session import get_requests_session

from nevermined_gateway.util import get_download_url, get_asset


def test_upload_download_filecoin_file(client):

    file_ = (io.BytesIO(b"Hello, Nevermined!"), 'test.txt')
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
    assert len(response.data) > 0

def test_upload_encrypt_download_filecoin_file(client):

    file_ = (io.BytesIO(b"Hello, Nevermined!"), 'test.txt')
    data = {'file': file_, 'encrypt': 'true'}
    response = client.post('/api/v1/gateway/services/upload/filecoin', data=data, content_type='multipart/form-data')

    assert response.status_code == 201
    url = response.json['url']
    print(response.json)
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
