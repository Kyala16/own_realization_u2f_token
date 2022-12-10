from datetime import datetime, timedelta
import os.path
import subprocess
import OpenSSL.crypto
import requests
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
import logging
try:
    from urllib.parse import urlparse
except ImportError:
     from urlparse import urlparse

CRL_FILE_NAME = "db.crl"
ATTRIBUTE_FILE_SUFFIX = ".attr"

logger = logging.getLogger()


class OCSPResponderException(Exception):
    pass


class OCSPResponder(object):
    """
    This object wraps OpenSSL's basic OCSP responder, and supplies an API to control it
    Please make sure that the OCSP key and certificate match, and that the certificate is issued and signed
    by the CA that the responder is supposed to approve certificates for.
    The responder will only be able to approve certificates issued by the CA
    """
    def __init__(self, crl_dir, ca_certificate_path, ocsp_certificate_path,
                 ocsp_key_path, start_responder=False, port=9999, log_output_path=None, request_timeout=0.8, total_timeout=5):
        """
        Initializes the responder
        :param str crl_dir: The path to the directory to write the CRL file in.
        :param str ca_certificate_path: Path to the certificate PEM file for the CA that issued the certificates the
         responder has to approve
        :param str ocsp_certificate_path: Path to the OCSP Responder's certificate PEM file
        :param str ocsp_key_path: Path to the OCSP Responder's private key file
        :param bool start_responder: Should the responder start upon initialization
        :param str port: Port the responder should listen to
        :param str log_output_path: absolute path to an output file for the responder
        :param int request_timeout: timeout in seconds for sending a single OCSP request to the responder
        :param int total_timeout: timeout in seconds for when polling the responder itself for a status of a certificate
        """
        if any(arg is None for arg in [ca_certificate_path, ocsp_certificate_path, ocsp_key_path]):
            raise OCSPResponderException("All certificates must be supplied")
        self.ca_certificate_path = ca_certificate_path
        self.ocsp_certificate_path = ocsp_certificate_path
        self.ocsp_key_path = ocsp_key_path
        self.crl_dir = crl_dir
        self.responder_process = None
        self.ocsp_port = port
        self.crl_file_path = os.path.join(crl_dir, CRL_FILE_NAME)
        self.crl = {}
        self.log_path = log_output_path
        self.request_timeout = request_timeout
        self.total_timeout = total_timeout

    def __del__(self):
        self.stop_responder()
        self.delete_crl_file()

    def start_responder(self):
        """
        Starts the OCSP Responder
        Syntax of shell command:
        openssl ocsp -index <CRL file> -port <port> -rsigner <responder certificate file> -rkey <responder private key file> -CA <ca certificate file>
        """
        if self.is_alive():
            raise OCSPResponderException("Responder already running")

        self.write_crl()
        args = ['openssl', 'ocsp',
                '-index', self.crl_file_path,
                '-port', str(self.ocsp_port),
                '-rsigner', self.ocsp_certificate_path,
                '-rkey', self.ocsp_key_path,
                '-CA', self.ca_certificate_path,
                '-ignore_err']
        if self.log_path is not None:
            args += ['-text', '-out', self.log_path]

        self.responder_process = subprocess.Popen(args=args,
                                                  stdout=subprocess.PIPE,
                                                  stderr=subprocess.STDOUT)

        if self.get_status(self.ocsp_certificate_path, self.ca_certificate_path, self.request_timeout) is None:
            self.stop_responder()
            self.delete_crl_file()
            raise OCSPResponderException("Failed to get a response from the responder")
        assert(self.is_alive())

    def is_alive(self):
        if self.responder_process is not None:
            return True if self.responder_process.poll() is None else False
        return False

    def stop_responder(self):
        if self.is_alive():
            self.responder_process.terminate()
            self.responder_process.wait()

    def restart(self):
        self.stop_responder()
        self.start_responder()

    def delete_crl_file(self):
        if os.path.exists(self.crl_file_path):
            os.remove(self.crl_file_path)
        if os.path.exists(self.crl_file_path + ATTRIBUTE_FILE_SUFFIX):
            os.remove(self.crl_file_path + ATTRIBUTE_FILE_SUFFIX)

    def write_crl(self):
        """
        Creates the CRL file for the OpenSSL OCSP Responder
        """
        self.delete_crl_file()
        with open(self.crl_file_path, 'w') as crl_file:
            for cert in self.crl.values():
                crl_file.write("{}\t{}\t{}\t{}\t{}\t{}\n".format(cert['status'],
                                                                      cert['expiration_time'],
                                                                      cert['revocation_time'],
                                                                      cert['serial_number'],
                                                                      'unknown',
                                                                      cert['subject']))

        with open(self.crl_file_path + ATTRIBUTE_FILE_SUFFIX, 'w') as attribute_file:
            attribute_file.write("unique_subject = no")

    def _add_certificate(self, certificate_path):
        """
        Parses a certificate file to an internal entry in the CRL
        :param str certificate_path: path to the certificate file
        :return: The certificate's serial number (used as a key for CRL entries)
        :rtype: int
        """
        with open(certificate_path, 'rt') as certificate_file:
            certificate_str = certificate_file.read()

        certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate_str)
        serial_number = certificate.get_serial_number()
        subject = certificate.get_subject()
        subject_str = "".join("/{}={}".format(name.decode(), value.decode()) for name, value in subject.get_components())
        cert_entry = {'serial_number': "%X" % serial_number,
                      'expiration_time': certificate.get_notAfter().decode("utf-8")[2:],
                      'revocation_time': '',
                      'subject': subject_str}

        self.crl[serial_number] = cert_entry
        return serial_number

    def set_verified_certificate(self, certificate_path):
        """
        Adds a certificate to the CRL as "Verified"
        :param str certificate_path: path to a PEM certificate file
        """
        serial_number = self._add_certificate(certificate_path)
        self.crl[serial_number]['status'] = 'V'

    def set_revoked_certificate(self, certificate_path, revocation_time=None):
        """
        Adds a certificate to the CRL as "Revoked"
        :param str certificate_path: path to a PEM certificate file
        :param revocation_time: timestamp of the revocation of the certificate (datetime object)
        :type revocation_time: datetime or None for the current time
        """
        serial_number = self._add_certificate(certificate_path)
        self.crl[serial_number]['status'] = 'R'

        if revocation_time is None:
            revocation_time = datetime.utcnow()
        revocation_time_str = revocation_time.strftime("%y%m%d%H%M%S") + "Z"
        self.crl[serial_number]['revocation_time'] = revocation_time_str

    def delete_certificate(self, certificate_path):
        """
        Removes a certificate from the CRL
        :param str certificate_path: path to a PEM certificate file
        """
        serial_number = self._add_certificate(certificate_path)
        self.crl.pop(serial_number, None)

    def get_status(self, certificate_path, issuer_certificate_path, request_timeout=None, total_timeout=None):
        """
        Returns the status of a provided certificate by sending a request to the responder
        :param str certificate_path: path to a PEM certificate file
        :param str issuer_certificate_path: path to the issuer's certificate PEM file
        :param int request_timeout: timeout in seconds for sending a single OCSP request to the responder
        :param int total_timeout: timeout in seconds for when polling the responder itself for a status of a certificate
        :return: the status of the certificate, or None if could not get it (eiter could not send request, or responder
                 sent an exception status)
        :rtype: an enum value of cryptography.x509.ocsp.OCSPCertStatus (or None)
        """
        single_request_timeout = self.request_timeout if request_timeout is None else request_timeout
        delta_seconds = self.total_timeout if total_timeout is None else total_timeout
        current_time = datetime.now()
        delta = timedelta(seconds=delta_seconds)
        status = None

        while datetime.now() < current_time + delta:
            try:
                ocsp_response = OCSPResponder.get_cert_ocsp_response(certificate_path, issuer_certificate_path, timeout=single_request_timeout, ocsp_port=self.ocsp_port)
                status = ocsp.load_der_ocsp_response(ocsp_response).certificate_status
                break
            except requests.exceptions.Timeout as e:  # Request timed out
                logger.info(e)
                pass
            except requests.exceptions.ConnectionError as e:  # Responder could not be reached
                logger.info(e)
                pass
            except ValueError as e:  # Response has an unsuccessful status
                logger.info(e)
                pass

        return status

    @staticmethod
    def _get_cert_from_file(certificate_path):
        """
        Load a certificate from a given PEM file path
        :param str certificate_path: path to certificate path
        :return: a cryptography.x509.Certificate
        """
        with open(certificate_path, 'rb') as cert_file:
            cert_str = cert_file.read()
        return x509.load_pem_x509_certificate(cert_str)

    @staticmethod
    def _get_ocsp_server(cert):
        """
        Retrieves the OCSP URI from a certificate
        :param x509.Certificate cert: The certificate to get the OCSP URI from
        :return: the OCSP URI string
        """
        aia = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsps = [ia for ia in aia if ia.access_method == x509.oid.AuthorityInformationAccessOID.OCSP]
        if not ocsps:
            raise OCSPResponderException('no ocsp server entry in AIA')
        return ocsps[0].access_location.value

    @staticmethod
    def _get_ocsp_response_from_server(ocsp_server, cert, issuer_cert, timeout):
        """
        Builds an OCSP request and sends it
        :param str ocsp_server: the OCSP responder URI
        :param x509.Certificate cert: the certificate to validate with the responder
        :param x509.Certificate issuer_cert: the certificate that issued the validated certificate
        :return: DER encoded OCSP response from the responder
        """
        builder = x509.ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
        req = builder.build()
        data = req.public_bytes(serialization.Encoding.DER)
        headers = {
            'Host': urlparse(ocsp_server).netloc,
            'Content-Type': 'application/ocsp-request'
        }
        ocsp_resp = requests.post(url=ocsp_server, data=data, headers=headers, timeout=timeout)
        if ocsp_resp.ok:
            return ocsp_resp.content
        raise OCSPResponderException('fetching ocsp cert response from responder failed with HTTP error: {} {}'.format(
            ocsp_resp.status_code, ocsp_resp.reason))

    @staticmethod
    def get_cert_ocsp_response(cert_path, issuer_cert_path, timeout, ocsp_port=None):
        """
        Gets an OCSP response for a given certificate
        Sends an OCSP request to a OCSP responder declared in the certificate and gets the response
        :param str cert_path: path to the relevant certificate PEM file
        :param str issuer_cert_path: path to the issuer's certificate PEM file
        :param int timeout: timeout in seconds for getting a response from the responder
        :param int ocsp_port: OCSP responder port. used in self-validation of responder, to override reading OCSP URI from certificate
        :return: A DER encoded OCSP response
        :rtype: bytes
        """
        cert = OCSPResponder._get_cert_from_file(cert_path)
        issuer_cert = OCSPResponder._get_cert_from_file(issuer_cert_path)
        ocsp_server = OCSPResponder._get_ocsp_server(cert) if ocsp_port is None else 'http://localhost:{}'.format(ocsp_port)
        return OCSPResponder._get_ocsp_response_from_server(ocsp_server, cert, issuer_cert, timeout)

