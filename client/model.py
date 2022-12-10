from ctypes import resize
import json
import os
from tkinter.messagebox import NO
from xmlrpc.client import Transport
import six
import struct
from utils import *
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
from binascii import a2b_hex
from enum import Enum, IntEnum, unique

__all__ = [
    ''
]

U2FVersion = 'U2F.v1'
TRANSPORT_EXT_OID = '1.3.6.1.4.1.45724.2.1.1'
PUB_KEY_DER_PREFIX = a2b_hex('3059301306072a8648ce3d020106082a8648ce3d030107034200')

CERTS_TO_FIX = [
    a2b_hex('349bca1031f8c82c4ceca38b9cebf1a69df9fb3b94eed99eb3fb9aa3822d26e8'),
    a2b_hex('dd574527df608e47ae45fbba75a2afdd5c20fd94a02419381813cd55a2a3398f'),
    a2b_hex('1d8764f0f7cd1352df6150045c8f638e517270e8b5dda1c63ade9c2280240cae'),
    a2b_hex('d0edc9a91a1677435a953390865d208c55b3183c6759c9b5a7ff494c322558eb'),
    a2b_hex('6073c436dcd064a48127ddbf6032ac1a66fd59a0c24434f070d4e564c124c897'),
    a2b_hex('ca993121846c464d666096d35f13bf44c1b05af205f9b4a1e00cf6cc10c5e511')
]

def ParseTLVSize(tlv):
    len = tlv[1]
    n_byte  = 1
    if len > 0x80:
        n_byte = len - 0x80
        len = 0
        for i in range(2, 2 + n_byte):
            len = len * 256 + tlv[i]
    return 2 + n_byte + len

def PopByte(data, len):
    x = bytes(data[:len])
    del data[:len]
    return x


def FixCert(der):
    if sha_256(der) in CERTS_TO_FIX:
        der = der[:-257] + b'\0' + der[-256:]
    return der

def ValidateClientData(clientData, challenge, type, validFacet):
    if clientData.type != type:
        raise ValueError("Wrong type")
    if challenge != clientData.challenge:
        raise ValueError("Wrong challenge")
    if validFacet is not None and clientData.origin not in validFacet:
        raise ValueError("Invalid facets")
