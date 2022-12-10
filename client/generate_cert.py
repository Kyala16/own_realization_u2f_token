import os
from OpenSSL import crypto

KEY_FILE = 'app.key'
CERT_FILE = 'app.crt'

def main():
    cert_dir = "C:\\client_server"
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)

#   create certification

    certification = crypto.X509()
    certification.get_subject().C = "RU"
    certification.get_subject().ST = "Moscow"
    certification.get_subject().L = "Moscow"
    certification.get_subject().O = "server"
    certification.get_subject().OU = "server"
    certification.get_subject().CN = "localhost"
    certification.set_serial_number(1000)
    certification.gmtime_adj_notBefore(0)
    certification.gmtime_adj_notAfter(10*365*24*60*60)
    certification.set_issuer(certification.get_subject())
    certification.set_pubkey(key)
    certification.sign(key, 'sha1')

    with open(os.path.join(cert_dir, CERT_FILE), "wb") as file:
        file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certification))

    with open(os.path.join(cert_dir, KEY_FILE), "wb") as file:
        file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

if __name__ == "__main__":
    main()