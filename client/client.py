import re
from atexit import register
from distutils.cmd import Command
from email import message
from email.mime import application
from hashlib import new
from urllib import request
from utils import *
import socket
import sys
import glob, os
from datetime import datetime
from OpenSSL import crypto
import socketserver
import ssl
from ClientData import *
from utils import *

HOST, PORT = '192.168.8.129', 8080
data = " ".join(sys.argv[1:])
CA_CRT = "app.crt"
CA_KEY = "app.key"
dict_command = {'reg': b'\x01', 'auth': b'\x02'}
cert_dir = "C:\\client_server"
CRL = "C:\\client_server\\crl"

def create_certificate(cert_dir):
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
    return [crypto.dump_certificate(crypto.FILETYPE_PEM, cert), crypto.dump_privatekey(crypto.FILETYPE_PEM, key)]


def create_request_msg(command, public_key, data):
    if (command == 'reg'):
        P1 = b'\x00'
        P2 = b'\x00'
        challenge_param = {"typ": "navigator.id.finishEnrollment",
                           "challenge": f"{websafe_encode(data)}",
                           "cid_pubkey": {"kty": "EC", "crv": "P-256",
                                          "x": f"{websafe_encode(public_key[:int(len(public_key) / 2)])}",
                                          "y": f"{websafe_encode(public_key[int(len(public_key) / 2):])}"},
                           "origin": "localhost"
                           }
    else:
        P1 = b'\x03'
        P2 = b'\x00'
        challenge_param = {"typ": "navigator.id.finishEnrollment",
                           "challenge": f"{websafe_encode(data)}",
                           "cid_pubkey": {"kty": "EC", "crv": "P-256",
                                          "x": f"{websafe_encode(public_key[:int(len(public_key) / 2)])}",
                                          "y": f"{websafe_encode(public_key[int(len(public_key) / 2):])}"},
                           "origin": "localhost"
                           }
    application_param = b'localhost'
    INS = dict_command[command]
    CLA = b'\x00'
    HEADER = b''.join([CLA, INS, P1, P2])
    DATA = bytes(str(challenge_param), 'utf-8') + application_param
    request_msg = b''.join([HEADER, int_to_bytes(len(DATA)), DATA, int_to_bytes(64)])
    return request_msg


def registration():
    login = input("login: ")
    password = input("password: ")
    conf_password = input("confirm password: ")
    if (password != conf_password):
        print("your password is wrong")
        exit(0)
    else:
        file_local_bd = open('local_bd.txt', 'a')
        file_local_bd.write(f'{login}:{password}\n')
        file_local_bd.close()
        return '{"login":' \
               f'"{login}"' \
               ', "password":' \
               f'"{password}"' \
               '}'


def check_time(time):
    time_now = (str)(datetime.now())
    if (int)(time_now[:4]) > (int)(time[2:6]):
        return False
    elif (int)(time_now[:4]) == (int)(time[2:6]):
        if (int)(time_now[5:7]) > (int)(time[6:8]):
            return False
        elif (int)(time_now[5:7]) == (int)(time[6:8]):
            if (int)(time_now[8:10]) > (int)(time[8:10]):
                return False
            elif (int)(time_now[8:10]) == (int)(time[8:10]):
                if (int)(time_now[11:13]) > (int)(time[10:12]):
                    return False
                elif (int)(time_now[11:13]) == (int)(time[10:12]):
                    if (int)(time_now[14:16]) > (int)(time[12:14]):
                        print(5)
                        return False
                    elif (int)(time_now[14:16]) == (int)(time[12:14]):
                        if (int)(time_now[17:19]) > (int)(time[14:16]):
                            print(6)
                            return False
                        else:
                            return True
                    else:
                        return True
                else:
                    return True
            else:
                return True
        else:
            return True
    else:
        return True

def check_certificate(certification):
    root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open("app.crt").read())
    store = crypto.X509Store()
    store.add_cert(root_cert)
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, certification)
    ctx = crypto.X509StoreContext(store, cert)
    try:
        time_end_cert = (str)(cert.get_notAfter())
        answer = check_time(time_end_cert)
        if not answer:
            with open(os.path.join(CRL, f"app{1+len([name for name in os.listdir(CRL) if os.path.isfile(os.path.join(DIR, name))])}.crt"), "wb") as file:
                file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        for filename in glob.glob(os.path.join(CRL, '*.crt')):
            with open(os.path.join(os.getcwd(), filename), 'r') as f:
                content_recalled = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
                if (content_recalled == cert):
                    raise Exception
        ctx.verify_certificate()
        return answer
    except Exception as e:
        print(e)
        return False


def check_your_login_password(login, password):
    file_local_bd = open('local_bd.txt', 'r')
    while True:
        new_string = file_local_bd.readline()
        if not new_string:
            break
        index_for_del = re.search(r":", new_string).end()
        if login == new_string[:index_for_del - 1]:
            if password == new_string[index_for_del:len(new_string) - 1]:
                return True
    return False


def authentication():
    login = input("login: ")
    password = input("password: ")
    try:
        if check_your_login_password(login, password):
            return '{"login":' \
                   f'"{login}"' \
                   ', "password":' \
                   f'"{password}"' \
                   '}'
        else:
            print("your data is wrong")
            exit(0)
    except Exception as e:
        print("you are not login")
        exit(0)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((HOST, PORT))
    certification = sock.recv(2048)
    print(certification)
    client_sert_key = create_certificate(cert_dir)
    print(client_sert_key[0])
    right_cert = check_certificate(client_sert_key[0])
    if not right_cert:
        print("DISCONNECT")
        sock.sendall(b'DISCONNECT')
        sock.close()
        exit(0)
    temp_char = ''
    while True:
        temp_char = input('1)registration\n2)authentication\n3)exit\n')
        if temp_char == 'exit':
            print("DISCONNECT")
            sock.sendall(b'DISCONNECT')
            sock.close()
            break
        elif temp_char == 'registration':
            data_all = registration()
            data = 'reg'
        elif temp_char == 'authentication':
            data_all = authentication()
            data = 'auth'
        else:
            print('Error!?')
            exit(0)
        request_msg = create_request_msg(data, certification, data_all)
        print(request_msg)
        sock.sendall(request_msg)
        recivedData = sock.recv(1024)
        flag = False
        while True:
            print(recivedData)
            if flag:
                answer = input()
                sock.sendall(bytes(answer + "\n", "utf-8"))
            recivedData = sock.recv(2048)
            if recivedData == b'\x00' or (len(recivedData) > 1 and recivedData[-1] == 0):
                break
            try:
                recivedData = recivedData.decode('utf-8')
                flag = True
            except Exception as e:
                flag = False
