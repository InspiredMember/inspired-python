import json
from datetime import datetime, timedelta, timezone

import jwt
import requests

from ..utils import rsa


JWT_ALG = 'RS256'
JWT_ISS = 'Inspired'


class PublisherClient(object):
    urls = {
        'create': 'v1/create/',
    }

    def __init__(self, base_url,
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
        #self.base_url = f'https://{base_url}/platform/publishers'
        self.base_url = 'https://fgdsawlhnb.execute-api.us-east-1.amazonaws.com/dev/publishers'
        self.publisher_id = publisher_id
        self.token_ttl = timedelta(seconds=token_ttl)

    def _jwt_create_headers(self, user_id=None):
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        if user_id is not None:
            sub = f'insprd://clients/{self.publisher_id}/users/{user_id}'
        else:
            sub = f'insprd://clients/{self.publisher_id}'
        return {
            'iss': JWT_ISS,
            'kid': self.signing_key_id,
            'sub': sub,
            'iat': int(now.timestamp()),
            'exp': int((now + self.token_ttl).timestamp()),
        }

    def _jwt_create_payload(self, user_id=None):
        payload = {
            'publisher_id': self.publisher_id,
        }
        if user_id is not None:
            payload['user_id'] = user_id
        return payload

    def _jwt_create_token(self, user_id=None):
        headers = self._jwt_create_headers(user_id)
        payload = self._jwt_create_payload(user_id)
        return jwt.encode(payload, self.signing_key, algorithm=JWT_ALG, headers=headers)

    def _http_post(self, url_name, *args, **kwargs):
        response = requests.post(f'{self.base_url}/{self.urls[url_name]}', *args, **kwargs)
        response.raise_for_status()
        return response

    def create(self, name, email):
        if self.publisher_id:
            return
        data = json.dumps({
            'email': email,
            'name': name,
            'key_id': self.signing_key_id,
            'public_key': rsa.serialize_public_key(self.signing_key).decode('utf-8'),
        })
        response = self._http_post('create', data=data)
        return response.json()
