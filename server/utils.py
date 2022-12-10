from email.charset import BASE64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64decode, urlsafe_b64encode

import six
import re

BASE64URL = re.compile(br'^[-_0-9A-Za-z]*=*$')

__all__ = [
    'websafe_decode', 'websafe_encode', 'sha_256'
]

def websafe_decode(data):
    if isinstance(data, six.text_type):
        data = data.encode('ascii')
    if not BASE64URL.match(data):
        raise ValueError('Invalid character(s)')
    data+= b'=' * (-len(data) % 4)
    return urlsafe_b64decode(data)

def websafe_encode(data):
    if isinstance(data, six.text_type):
        data = data.encode('ascii')
    return urlsafe_b64encode(data).replace(b'=', b'').decode('ascii')

def sha_256(data):
    Hash = hashes.Hash(hashes.SHA256(), default_backend())
    Hash.update(data)
    return Hash.finalize()