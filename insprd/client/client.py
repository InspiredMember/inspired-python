from datetime import datetime, timedelta, timezone

import jwt
import requests

from ..utils import rsa


JWT_ALG = 'RS256'
JWT_ISS = 'Inspired'


class Client(object):
    def __init__(self, base_url, client_id, signing_key_id,
                 signing_key_data=None, signing_key_file=None, jwt_ttl=3600):
        super(Client, self).__init__()
        self.base_url = base_url
        self.client_id = client_id
        self.signing_key_id = signing_key_id
        if signing_key_file is not None:
            with open(signing_key_file, 'rb') as file_data:
                signing_key_data = file_data.read()
        if signing_key_data is not None:
            self.signing_key = rsa.deserialize_pem(signing_key_data)
        else:
            raise ValueError('One of signing_key_data or signing_key_file is required')
        self.jwt_ttl = timedelta(seconds=jwt_ttl)

    def _jwt_create_headers(self, user_id=None):
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        if user_id is not None:
            sub = f'insprd://clients/{self.client_id}/users/{user_id}'
        else:
            sub = f'insprd://clients/{self.client_id}'
        return {
            'iss': JWT_ISS,
            'kid': self.signing_key_id,
            'sub': sub,
            'iat': int(now.timestamp()),
            'exp': int((now + self.jwt_ttl).timestamp()),
        }

    def _jwt_create_payload(self, user_id=None):
        payload = {
            'client_id': self.client_id,
        }
        if user_id is not None:
            payload['user_id'] = user_id
        return payload

    def _jwt_create_token(self, user_id=None):
        headers = self._jwt_create_headers(user_id)
        payload = self._jwt_create_payload(user_id)
        return jwt.encode(payload, self.signing_key, algorithm=JWT_ALG, headers=headers)

    def create_user(self):
        pass

    def update_user(self, user_id):
        pass
