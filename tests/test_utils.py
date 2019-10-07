from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from insprd.utils import rsa


def test_rsa_create_private_key():
    key = rsa.create_private_key()
    assert isinstance(key, RSAPrivateKey)


def test_rsa_deserialize_pem():
    key = rsa.create_private_key()
    key_bytes = rsa.serialize_private_key(key)
    key2 = rsa.deserialize_pem(key_bytes)
    key2_bytes = rsa.serialize_private_key(key2)
    assert key_bytes == key2_bytes


def test_rsa_serialize_private_key():
    key = rsa.create_private_key()
    key_bytes = rsa.serialize_private_key(key)
    assert isinstance(key_bytes, bytes)


def test_rsa_serialize_public_key():
    key = rsa.create_private_key()
    pub_key_bytes = rsa.serialize_public_key(key)
    assert isinstance(pub_key_bytes, bytes)
