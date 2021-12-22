import io


def test_upload_filecoin_file(client):
    file_ = (io.BytesIO(b"Hello, Nevermined!"), 'test.txt')
    data = {'file': file_}
    response = client.post('/api/v1/gateway/services/upload/filecoin', data=data, content_type='multipart/form-data')
    assert response.status_code == 201
    assert response.json['url'].startswith('cid://')
    assert len(response.json['url']) > 40
