import json
import logging
from datetime import datetime, timedelta, timezone

import jwt
import requests
from requests.exceptions import HTTPError

from ..utils import rsa


JWT_ALG = 'RS256'
JWT_ISS = 'Inspired'


logger = logging.getLogger()


def http_request_method(method):
    def request_method(self, url_name, *args, raise_for_status=True, **kwargs):
        url = f'{self.base_url}/{self.urls[url_name]}'.format(
            publisher_id=self.publisher_id,
        )
        response = getattr(requests, method)(url, *args, **kwargs)
        if raise_for_status:
            try:
                response.raise_for_status()
            except HTTPError as e:
                e.args = (f'{e.args[0]} {response.json()}',)
                raise e
            else:
                logger.info(f'{response.status_code} {response.url}')
        return response
    return request_method


class PublisherClient(object):
    urls = {
        'create': 'create/',
        'test': '{publisher_id}/test',
    }

    def __init__(self,
                 platform_domain,
                 publisher_id=None,
                 signing_key_id=None,
                 signing_key_data=None, signing_key_file=None,
                 token_ttl=3600):
        super().__init__()
        if signing_key_id is not None:
            self.signing_key_id = signing_key_id
        else:
            raise ValueError('Must provide signing_key_id')
        if signing_key_file is not None:
            with open(signing_key_file, 'rb') as file_data:
                signing_key_data = file_data.read()
        if signing_key_data is not None:
            self.signing_key = rsa.deserialize_pem(signing_key_data)
        else:
            raise ValueError('Must provide one of (signing_key_data, signing_key_file)')
        self.base_url = f'https://{platform_domain}/publishers'
        self.publisher_id = publisher_id
        self.token_ttl = timedelta(seconds=token_ttl)

    _http_get = http_request_method('get')
    _http_post = http_request_method('post')

    def _jwt_create_headers(self, user_id=None):
        return {
            'kid': self.signing_key_id,
        }

    def _jwt_create_payload(self, user_id=None):
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        if user_id is not None:
            sub = f'insprd://publishers/{self.publisher_id}/users/{user_id}'
        else:
            sub = f'insprd://publishers/{self.publisher_id}'
        return {
            'iss': JWT_ISS,
            'sub': sub,
            'aud': 'insprd://publishers',
            'iat': int(now.timestamp()),
            'exp': int((now + self.token_ttl).timestamp()),
        }

    def _jwt_create_token(self, user_id=None):
        headers = self._jwt_create_headers(user_id)
        payload = self._jwt_create_payload(user_id)
        return jwt.encode(payload, self.signing_key, algorithm=JWT_ALG, headers=headers)

    def create(self, create_code, name, email):
        if self.publisher_id:
            return
        data = json.dumps({
            'create_code': create_code,
            'email': email,
            'name': name,
            'key_id': self.signing_key_id,
            'public_key': rsa.serialize_public_key(self.signing_key).decode('utf-8'),
        })
        response = self._http_post('create', data=data)
        result = response.json()
        self.publisher_id = result['id']
        return result

    def test(self):
        if not self.publisher_id:
            return
        response = self._http_get('test', headers={'Authorization': self._jwt_create_token()})
        return response
