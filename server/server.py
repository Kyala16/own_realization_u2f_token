import datetime
import json
import sqlite3
import rsa
from hashlib import new
from sqlite3 import *
import re
from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import PublicFormat, Encoding, KeySerializationEncryption, \
    PrivateFormat
from utils import *
from ECDSA import *
import socket
from cryptography.hazmat.primitives.asymmetric import ec
from ClientData import *

RegisteredDevice = {}
COUNTER = 0
REGFINISH = b'\x05'
private_key_curve = ec.generate_private_key(ec.SECP384R1())
public_key_curve = private_key_curve.public_key()
public_key = public_key_curve.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
private_key = private_key_curve.private_bytes(Encoding.PEM, PrivateFormat.PKCS8,
                                           encryption_algorithm=serialization.NoEncryption())
certificate = create_attestation_certificate(public_key_curve, private_key_curve)
CA_CRT = "app.crt"
CA_KEY = "app.key"


def main():
    server = Server('192.168.8.129', 8080, 'dase.db')
    server.start_server()


class Server:
    def __init__(self, ip, port, base_data):
        self.base_data = base_data
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((ip, port))
        self.server.listen(1)

    def create_sertificate(self):
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(CA_CRT).read())
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(CA_KEY).read(), b"password")
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().C = "RU"
        cert.get_subject().ST = "Moscow"
        cert.get_subject().L = "Moscow"
        cert.get_subject().O = "client"
        cert.get_subject().OU = "client"
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(ca_cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(ca_key, "sha1")
        self.certificate_server = cert
        self.private_key_cert = key

    def start_server(self):
        while True:
            new_socket, from_addr = self.server.accept()
            print(f'CLIENT CONNECTED\n\tIP: {from_addr[0]} PORT: {from_addr[1]}')
            self.create_sertificate()
            new_socket.sendall(crypto.dump_certificate(crypto.FILETYPE_PEM, self.certificate_server))
            data = ' '
            while True:
                data = new_socket.recv(2048)
                if (data == b'DISCONNECT' or data == b''):
                    new_socket.close()
                    break
                if int_to_bytes(data[1]) == b'\x01':
                    self.start_registration(new_socket, data)
                elif int_to_bytes(data[1]) == b'\x02':
                    self.start_auth(new_socket, data)

    def check_certificate(self, certification):
        root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open("app.crt").read())
        store = crypto.X509Store()
        store.add_cert(root_cert)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, certification)
        ctx = crypto.X509StoreContext(store, cert)
        try:
            time_end_cert = (str)(cert.get_notAfter())
            ctx.verify_certificate()
            return True
        except Exception as e:
            print(e)
            return False

    def sender(self, user, text):
        user.send(text.encode('utf-8'))

    def u2f_emulator(self, user, data):
        tempmsg = b'confirm your presence'
        user.sendall(tempmsg)
        temp_data = user.recv(2048)
        return crypto.sign(self.private_key_cert, data, 'sha256')

    def start_registration(self, user, data):
        temp_data = data[6:-10].decode('utf-8')
        start_index_for_challenge = re.search(r"'challenge': '", temp_data).end()
        end_index_for_challenge = re.search(r", 'cid", temp_data).start()-1
        login_password = websafe_decode(temp_data[start_index_for_challenge:end_index_for_challenge])
        challenge = sha_256(data[6:-9])
        application = sha_256(data[-9:-1])
        CommandAPDU = b'\x01\x00\x00'
        len_data = b'\x40'
        request_Massege = b''.join([challenge, application])
        user.sendall(request_Massege)
        request_Massege_sing = self.u2f_emulator(user, request_Massege)
        self.finish_registration(user, request_Massege, login_password, request_Massege_sing)

    def finish_registration(self, user, raw_msg, login_password, sign):
        # connection = sqlite3.connect(self.base_data)
        # cursor = connection.cursor()
        try:
            crypto.verify(self.certificate_server, sign, raw_msg, 'sha256')
        except(Exception):
            tempmsg = b'the private key not right'
            user.sendall(tempmsg)
            temp_data = user.recv(2048)
            user.sendall(b'\x00')
        global COUNTER
        key_handle = wrapper(public_key, raw_msg[32:])
        # Должны сохранять паблик кей + кей хэнле
        file_local_bd = open('local_bd.txt', 'a')
        file_local_bd.write(f"{login_password}:{b''.join([key_handle, public_key])}\n")
        file_local_bd.close()
        signature = private_key_curve.sign(b''.join([b'\x00', raw_msg[:32], raw_msg[32:], key_handle, public_key]),
                                           ec.ECDSA(hashes.SHA256()))
        raw_response_msg = b''.join([REGFINISH, public_key, int_to_bytes(len(key_handle)), key_handle,
                                     certificate.public_bytes(encoding=Encoding.PEM), signature])
        user.sendall(raw_response_msg)
        COUNTER += 1
        user.sendall(b'\x00')
        # connection.commit()
        # connection.close()
        # cursor.close()

    def get_from_bd_data(self, login):
        file_to_get_data = open('local_bd.txt', 'r')
        while True:
            new_string = file_to_get_data.readline()
            if not new_string:
                break
            index_for_del = re.search(r":", new_string).end()-1
            if login == new_string[:index_for_del]:
                return bytes(new_string[index_for_del+1:])
        return b''

    def start_auth(self, user, data):
        CONTROL_BYTE = b'\x03'
        temp_data = data[6:-9].decode('utf-8')
        start_index_for_challenge = re.search(r"'challenge': '", temp_data).end()
        end_index_for_challenge = re.search(r", 'cid", temp_data).start() - 1
        login_password = websafe_decode(temp_data[start_index_for_challenge:end_index_for_challenge])
        challenge = sha_256(data[6:-9])
        application = sha_256(data[-9:-1])
        key_handle = self.get_from_bd_data(login_password)
        RequestMessage = b''.join([CONTROL_BYTE, challenge, application, int_to_bytes(32), key_handle])
        user.sendall(RequestMessage)
        request_Massege_sing = self.u2f_emulator(user, RequestMessage)
        self.finish_auth(user, RequestMessage, request_Massege_sing)

    def finish_auth(self, user, raw_msg, sign):
        try:
            crypto.verify(self.certificate_server, sign, raw_msg, 'sha256')
        except(Exception):
            tempmsg = b'the private key not right'
            user.sendall(tempmsg)
            temp_data = user.recv(1024)
            user.sendall(b'\x00')
        global COUNTER
        user_presence = int_to_bytes(2 ** 7)
        signature = private_key_curve.sign(b''.join([raw_msg[:32], user_presence, int_to_bytes(COUNTER), raw_msg[32:]]),
                                           ec.ECDSA(hashes.SHA256()))
        raw_response_msg = b''.join([user_presence, int_to_bytes(COUNTER), signature])
        user.sendall(raw_response_msg)
        COUNTER += 1
        user.sendall(b'\x00')

    def listen(self, user):
        is_work = True
        while is_work:
            try:
                data = user.recv(1024)
            except Exception as e:
                data = ''
                is_work = False

            if len(data) > 0:
                msg = data.decode('utf-8')
                if msg == 'disconnect':
                    self.sender('YOU ARE DISCONNECTED')
                    user.close()
                    is_work = False
                else:
                    connection = sqlite3.connect(self.base_data)
                    cursor = connection.cursor()
                    try:
                        answer = [x for x in cursor.execute(msg)]
                        error = ''
                    except Exception as e:
                        error = str(e)
                        answer = ''
                    connection.commit()
                    connection.close()
                    cursor.close()

                    ans = json.dumps(
                        {'answer': answer, 'error': error}
                    )
                    self.sender(user, ans)

                data = b''
                msg = ''
            else:
                print(f'CLIENT DISCONNECTED')
                is_work = False


if __name__ == "__main__":
    main()
