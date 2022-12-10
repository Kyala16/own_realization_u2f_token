from datetime import datetime
from hashlib import sha256
from tkinter import N
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography import x509
import json
from mimetypes import init
from utils import *

__all__ = [
    'JwkKey',
    'ClientData',
    'ApplicationId',
    'KeyHandle',
    'RequestMessageReg',
    'RequestMessageAuth',
    'Signature',
    'ResponseMessageReg',
    'ResponseMessageAuth'
]


class JwkKey:
    def __init__(self, kty, crv, x, y) -> None:
        self.kty = kty
        self.crv = crv
        self.x = x
        self.y = y


class ClientData:
    def __init__(self, typ, challenge, origin, cid) -> None:
        self.typ = typ
        self.challenge = challenge
        self.origin = origin
        self.cid = cid

    def GetChallengeParam(self):
        cid_publicKey = f'"kty":"{self.cid.kty},"crv":"{self.cid.crv}","x":"{self.cid.x}","y":"{self.cid.y}"'
        clientData = f'{{"typ":"{self.typ}","challenge":"{self.challenge}","cid_pubkey":{{{cid_publicKey}}},"origin" : "{self.origin}"}}'
        return sha_256(clientData.encode('utf-8'))


class ApplicationId:
    def __init__(self, data) -> None:
        self.data = data

    def GetApplicationParam(self):
        return sha_256(self.data.encode('utf-8'))


# Возможная обертка для KeyHandle
class KeyHandle:
    def __init__(self, privateKey, applicationId) -> None:
        self.privateKey = privateKey
        self.applicationId = applicationId

    def GetKeyHandle(self):
        data = b''.join([self.privateKey, self.applicationId])
        return (sha_256(data))


class RequestMessageReg:
    def __init__(self, challengeParam, applicationParam) -> None:
        self.data = [challengeParam, applicationParam]

    def GetRequestMessage(self):
        return b''.join(self.data)


class RequestMessageAuth:
    CONTROL_BYTE = 0x03

    def __init__(self, CONTROL_BYTE, challengeParam, applicationParam, lenKeyHandle, keyHandle) -> None:
        self.data = [CONTROL_BYTE, challengeParam, applicationParam, lenKeyHandle, keyHandle]

    def GetRequestMessage(self):
        return b''.join(self.data)


class Signature:
    def __init__(self, applicationParam, challengeParam, keyHandle, userPublicKey) -> None:
        self.data = [0x00, applicationParam, challengeParam, keyHandle, userPublicKey]

    def __init__(self, applicationParam, counter, challengeParam) -> None:
        self.data = [applicationParam, 0x01, counter, challengeParam]

    def GetSignature(self, reg):
        data = b''.join(self.data)
        privateKey = ec.generate_private_key(ec.SECP384R1())
        signature = privateKey.sign(data, ec.ECDSA(hashes.SHA256()))
        return signature


class ResponseMessageReg:
    FIRST_BYTE = 0x05

    def __init__(self, FIRST_BYTE, userPublicKey, lenKeyHandle, keyHandle, attestationCert, signature) -> None:
        self.data = [FIRST_BYTE, userPublicKey, lenKeyHandle, keyHandle, attestationCert, signature]

    def GetResponseMessage(self):
        return b''.join(self.data)


class ResponseMessageAuth:
    def __init__(self, userPublicKey, counter, signature) -> None:
        self.data = [userPublicKey, counter, signature]

    def GetResponseMessage(self):
        return b''.join(self.data)


class AssertionCert:
    def __init__(self) -> None:
        self.privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048, )

    def CreateData(self):
        self.data = self.issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"MOSCOW"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.ru"),
        ])

    def GetCert(self):
        self.CreateData()
        cert = x509.CertificateBuilder().subject_name(self.data).issuer_name(self.issuer).public_key(
            self.privateKey.public_key()
            ).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()
                                                                          ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
            ).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False,
                            ).sign(self.privateKey, hashes.SHA256())
        return cert.fingerprint(hashes.SHA256())