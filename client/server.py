from atexit import register
from distutils.cmd import Command
from email import message
from email.mime import application
from hashlib import new
from sqlite3 import DataError
from urllib import request
from utils import *
import socket
import socketserver
import ssl
from ClientData import *
from utils import *

RegisteredDevice = {
    "localhost": b''.join([b'\x02', b"hello localhost"])
}


def start_registrarion(socket):
    msg = "Client Data: "
    socket.sendall(msg.encode())
    dataCh = socket.recv(4096)
    challenge = sha_256(dataCh)
    msg = "origin: "
    socket.sendall(msg.encode())
    dataOr = socket.recv(4096)
    application = sha_256(dataOr)
    socket.sendall(b' ')
    CommandAPDU = b'\x01\x00\x00'
    lendata = 0x40
    requestMassege = b''.join([challenge, application])
    socket.sendall(requestMassege)


def finish_registrarion():
    ...


def start_auth(socket):
    CONTROL_BYTE = b'\x03'
    msg = b"Client Data: "
    socket.sendall(msg)
    dataCh = socket.recv(4096)
    challenge = sha_256(dataCh)
    msg = b"origin: "
    socket.sendall(msg)
    dataOr = socket.recv(4096)
    application = sha_256(dataOr)
    socket.sendall(b' ')
    print(RegisteredDevice[dataOr.decode()[:-1]][0])
    RequestMessage = b''.join([CONTROL_BYTE, challenge, application,
                               bytes(str(RegisteredDevice["localhost"][0]), 'utf-8'),
                               RegisteredDevice[dataOr.decode()[:-1]][1:]])
    socket.sendall(RequestMessage)


def finish_auth():
    ...


def srav(str1, str2):
    flag = True
    for i in range(len(str1)):
        if str1[i] != str2[i]:
            flag = False
    return flag


def deal_with_client(connstream):
    tempMsg = "what you want[reg/auth]:"
    connstream.sendall(tempMsg.encode())
    data = connstream.recv(1024)
    data = data.decode('utf-8')
    if (data == "reg" + chr(10)):
        print(data)
        start_registrarion(connstream)
    elif (data == "auth" + chr(10)):
        print(data)
        start_auth(connstream)
    else:
        exit(0)


def main():
    bindsocket = socket.socket()
    bindsocket.bind(('192.168.8.129', 8080))
    bindsocket.listen(1)
    while True:
        newsocket, fromaddr = bindsocket.accept()
        try:
            deal_with_client(newsocket)
        finally:
            newsocket.shutdown(socket.SHUT_RDWR)
            newsocket.close()


if __name__ == "__main__":
    main()