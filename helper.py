# -----------------------------------------------------------------------------
# Copyright (c) 2024 Martin Schobert, Pentagrid AG
#
# All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
#  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#  The views and conclusions contained in the software and documentation are those
#  of the authors and should not be interpreted as representing official policies,
#  either expressed or implied, of the project.
#
#  NON-MILITARY-USAGE CLAUSE
#  Redistribution and use in source and binary form for military use and
#  military research is not permitted. Infringement of these clauses may
#  result in publishing the source code of the utilizing applications and
#  libraries to the public. As this software is developed, tested and
#  reviewed by *international* volunteers, this clause shall not be refused
#  due to the matter of *national* security concerns.
# -----------------------------------------------------------------------------

import os
import socket
import ssl
from pathlib import Path
from typing import Dict

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey, EllipticCurveSignatureAlgorithm
from logger import Logger


def get_cert_fingerprint_hex(cert):
    return ":".join(["%02X" % h for h in cert.fingerprint(hashes.SHA256())])


def verify_cert_signature(cert: x509.Certificate, trusted_issuer_certs: list[x509.Certificate]) -> bool:
    """
    Check if a certificate was signed by one of the trusted issuer certificates. At least one of the trusted
    issuer should have signed the certificate.
    :param cert: The x509.Certificate object that should be verified.
    :param trusted_issuer_certs: A list of x509.Certificate objects.
    :return: Returns True if one of the trusted issuers signed the certificate. Otherwise, False is returned.
    """

    l = Logger()

    for trusted_cert in trusted_issuer_certs:
        try:
            if cert.issuer == trusted_cert.subject:
                trusted_cert.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm)
                l.log_msg(f"Verify cert against {trusted_cert.subject} was successful. That's fine.")
                return True

        except InvalidSignature:
            l.log_msg(f"Verify cert against {trusted_cert.subject} failed.")
            pass

    return False


def is_pre_cert(cert: x509.Certificate) -> bool:
    """
    Check if a certificate is a pre-certificate. These pre-certificates are also stored on crt.sh.
    Pre-certificates are identified by checking for a certificate extension identified by OID 1.3.6.1.4.1.11129.2.4.3,
    also called poison extension. The poison extension and its OID are specified in
    https://datatracker.ietf.org/doc/html/rfc6962#section-3.1.
    :param cert: An x509.Certificate object.
    :return: Returns either True or False.
    """
    # check CT poison extension
    try:
        cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3"))
        return True
    except x509.ExtensionNotFound:
        # cert is not a pre-certificate
        return False


def has_sct(cert: x509.Certificate) -> bool:
    """
    Check if a certificate has a signed certificate timestamp.
    For SCTs, there is certificate extension identified by OID 1.3.6.1.4.1.11129.2.4.2.
    :param cert: An x509.Certificate object.
    :return: Returns either True or False.
    """
    # check CT poison extension
    try:
        cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"))
        return True
    except x509.ExtensionNotFound:
        # cert is not a pre-certificate
        return False


def print_cert(cert: x509.Certificate, cert_descr="Certificate") -> None:
    """
    Print a x509.Certificate object.
    :param cert: The certificate to print.
    :param cert_descr: An optional string description for the certificate. The default is "Certificate", but it
        could be something other meaningful such as "Leaf certificate" or "Certificate that failed the check."
    """

    print(f"+ {cert_descr}:")
    print(f"  Serial number (hex): 0x{cert.serial_number:02x}")
    print(f"  Serial number (dec): {cert.serial_number}")
    print(f"  Subject            : {cert.subject}")
    print(f"  Issuer             : {cert.issuer}")
    print(f"  Not valid before   : {cert.not_valid_before}")
    print(f"  Not valid after    : {cert.not_valid_after}")
    print(f"  Signature Hashalgo : {cert.signature_hash_algorithm.name}")
    print(f"  Fingerprint        : %s" % get_cert_fingerprint_hex(cert))
    print(f"  Pre-certificate    : {is_pre_cert(cert)}")
    print(f"  Python type        : %s" % type(cert.public_key()))


def parse_cert_from_file(cert_file: str) -> x509.Certificate:
    """
    Load a X509 certificate in PEM format from a file.
    :param cert_file: The path of the certificate file
    :return: Returns a Certficate.
    """
    l = Logger()
    l.log_msg(f"Parsing certificate from file {cert_file}.")
    with open(cert_file, "rb") as f:
        cert_data = f.read()

    return x509.load_pem_x509_certificate(cert_data, default_backend())


def parse_local_certs(path: str) -> Dict[int, x509.Certificate]:
    """
    Parse one or more X509 certificates from a file or directory and return it as dictionary. Filter out pre-certificates.
    :param path: A file or a directory path.
    :return: Returns a dict with certificates. Key is the serial number. Value is a x509.Certificate object.
    """

    def _handle_error(err):
        raise IOError(err)

    l = Logger()

    certs = {}

    if not os.path.exists(path):
        raise FileNotFoundError(f"The path {path} for local certificates does not exist.")
    
    if os.path.isfile(path):
        cert = parse_cert_from_file(path)
        if cert:
            certs[cert.serial_number] = cert

    if os.path.isdir(path):
        l.log_msg(f"Reading certificates from {path}.")

        for root, subdirs, files in os.walk(path, onerror=_handle_error):
            
            for filename in files:
                p = os.path.join(root, filename)

                l.log_msg(f"Try to parse file {p}.")
                try:
                    cert = parse_cert_from_file(str(p))
                    if cert:
                        if is_pre_cert(cert):
                            l.log_msg(f"Certificate with serial 0x{cert.serial_number:02x} was found as pre-certificate. Ignoring it.")
                        elif cert.serial_number in certs:
                            l.log_msg(f"Certificate with serial 0x{cert.serial_number:02x} was already loaded. Ignoring it.")
                        else:
                            l.log_msg(f"Adding certificate with serial 0x{cert.serial_number:02x}.")
                        certs[cert.serial_number] = cert
                        
                except ValueError:
                    pass
                
    return certs


def download_cert_from_host(hostname, port):
    l = Logger()
    l.log_msg(f"Download certificate from {hostname}:{port}")
    if port == 25:
        with socket.create_connection((hostname, port)) as s:
            s.send(b"STARTTLS\r\n")
            s.recv(1000)
            with ssl.create_default_context().wrap_socket(s, server_hostname=hostname) as ss:
                certificate_der = ss.getpeercert(True)
                return x509.load_der_x509_certificate(certificate_der, default_backend())
    else:
        cert_data = ssl.get_server_certificate((hostname, port))
        return x509.load_pem_x509_certificate(cert_data.encode('ascii'), default_backend())
