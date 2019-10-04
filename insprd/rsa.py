from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def create_private_key(public_exponent=65537, key_size=4096, backend=default_backend):
    """
    Generates a new RSA private key. Returns an instance of
    `cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`.
    """
    return rsa.generate_private_key(public_exponent, key_size, backend())


def deserialize_pem(data, password=None, backend=default_backend):
    """
    Deserialize a private key from a PEM encoded, bytes-like object into an
    instance of `cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`.
    """
    return serialization.load_pem_private_key(data, password, backend())


def serialize_private_key(private_key):
    """
    Serialize an instance of
    `cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
    into a bytes-like object.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_public_key(private_key):
    """
    Serialize the public key component of an instance of
    `cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
    into a bytes-like object.
    """
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
