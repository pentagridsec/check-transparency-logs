#!/usr/bin/env python3
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
import sys
import argparse
import sqlite3
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from enum import Enum
from typing import Dict

import helper
from Crtsh import Crtsh
from helper import get_cert_fingerprint_hex, verify_cert_signature, print_cert, is_pre_cert, \
    parse_cert_from_file, parse_local_certs
from logger import Logger

class CertState(Enum):
    """
    The state of our verification. Certificates can be verified or in state ignored, which is used to
    flag certificates, which we do not have anymore.
    """
    UNVERIFIED = 0
    IGNORE = 1
    VERIFIED = 2
    ACCEPTED = 3

class Database:
    def __init__(self, db_file: str):
        """
        Create a new database object to store certificate trust decisions, because we need to keep track of
        already checked certificates. The underlying database is an Sqlite database file.
        :param db_file: The file path to the database. If the file does not exists, we create it.
        """
        self.con = sqlite3.connect(db_file)
        self.cur = self.con.cursor()

        # check if table exists
        res = self.cur.execute("SELECT name FROM sqlite_master WHERE name='certs'")
        if res.fetchone() is None:
            self.cur.execute("CREATE TABLE certs(fingerprint TEXT PRIMARY KEY, crtdb_id INTEGER, serial TEXT, cert_flag INTEGER)")
            self.con.commit()

    def store_known_cert(self, cert: x509.Certificate, crtdb_id: int, state: CertState) -> None:
        """
        Store the verified/ignored state for a certificate locally in the database.
        :param cert: The certificate, which is stored as trusted/ignored.
        :param crtdb_id: The crt.sh ID of the object, or None if not known or existent.
        :param state: The verified or ignored state.
        """
        l = Logger()
        fp_hash = get_cert_fingerprint_hex(cert)
        l.log_msg(f"Store certificate with fingerprint {fp_hash} as known with state {str(state)}.")
        data = (fp_hash, crtdb_id, str(cert.serial_number), str(state))
        self.cur.execute("INSERT INTO certs VALUES(?, ?, ?, ?)", data)
        self.con.commit()

    def is_cert_known_by_crtdb_id(self, crtdb_id: int) -> CertState:
        """
        Check the local database if the object is trusted or should be ignored.
        :param crtdb_id: The crt.sh ID to check.
        :return: Returns the CertState, which is either IGNORE or VERIFIED.
        """
        res = self.cur.execute("SELECT * FROM certs where crtdb_id = ?", (crtdb_id,)).fetchone()
        return self._res_to_state(res)

    def is_cert_known_by_fingerprint(self, cert: x509.Certificate) -> CertState:
        """
        Check the local database if the object is trusted or should be ignored.
        :param cert: The certificate, which is stored as trusted/ignored.
        :return: Returns the CertState, which is either IGNORE or VERIFIED.
        """
        res = self.cur.execute("SELECT * FROM certs where fingerprint = ?", (get_cert_fingerprint_hex(cert),)).fetchone()
        return self._res_to_state(res)

    def _res_to_state(self, res) -> CertState:
        if res is None:
            return CertState.UNVERIFIED
        
        if res[3] == "CertState.VERIFIED":
            return CertState.VERIFIED
        
        elif res[3] == "CertState.IGNORE":
            return CertState.IGNORE
        
        elif res[3] == "CertState.ACCEPTED":
            return CertState.ACCEPTED
        
        raise ValueError(f"Unknown value in database as certificate status: {res[3]}")


def check_logged_certs(db: Database,
                       logged_certs: Dict[int, x509.Certificate],
                       local_certs: Dict[int, x509.Certificate],
                       expected_issuer_certs: list[x509.Certificate],
                       learn:bool=False, interactive:bool=False) -> None:

    l = Logger()
    for downloaded_cert in logged_certs:

        fingerprint = get_cert_fingerprint_hex(downloaded_cert)

        l.log_msg(f"Checking certificate with fingerprint {fingerprint}, which is a logged certificate.")
        known = db.is_cert_known_by_fingerprint(fingerprint)
        if known != CertState.UNVERIFIED: # There is nothing to check for this cert
            continue

        state = check_downloaded_cert(downloaded_cert, local_certs, expected_issuer_certs, learn, interactive)
        db.store_known_cert(downloaded_cert, None, state)


def check_crtsh(db: Database, hostname: str,
                local_certs: Dict[int, x509.Certificate],
                expected_issuer_certs: list[x509.Certificate],
                learn:bool=False, interactive:bool=False) -> None:

    l = Logger()
    crtsh = Crtsh()

    l.log_msg(f"Requesting data from crt.sh for hostname {hostname}.")
    for jcert in crtsh.get_certs_for_hosts(hostname):

        l.log_msg(f"Checking certificate with ID {jcert['id']}, which was found at crt.sh.")
        known = db.is_cert_known_by_crtdb_id(jcert['id'])
        if known != CertState.UNVERIFIED: # There is nothing to check for this cert
            continue

        l.log_msg(f"Downloading not yet seen certificate with ID {jcert['id']} and serial number {jcert['serial_number']} for further checks.")
        downloaded_cert = crtsh.download_cert(jcert['id'])

        state = check_downloaded_cert(downloaded_cert, local_certs, expected_issuer_certs, learn, interactive)
        db.store_known_cert(downloaded_cert, jcert['id'], state)

def check_downloaded_cert(downloaded_cert: x509.Certificate,
                          local_certs: Dict[int, x509.Certificate],
                          expected_issuer_certs: list[x509.Certificate],
                          learn:bool=False, interactive:bool=False) -> CertState:
    l = Logger()
    try:

        l.log_msg("Check signature.")
        if not verify_cert_signature(downloaded_cert, expected_issuer_certs):
            msg = f"Failed to verify signature of certificate with fingerprint {get_cert_fingerprint_hex(downloaded_cert)}."
            l.log_wrn(msg)
            print_cert(downloaded_cert)
            raise InvalidSignature("SECURITY WARNING: " + msg)

        l.log_msg("Check if it is a pre-cert.")
        if is_pre_cert(downloaded_cert):
            l.log_msg(f"Certificate with fingerprint {get_cert_fingerprint_hex(downloaded_cert)} is the pre-certificate. Skipping.")
            return CertState.IGNORE

        l.log_msg("Check if certificate is in local certificates.")
        if downloaded_cert.serial_number not in local_certs:
            l.log_msg("Downloaded certificate not found in local certificates.")
            if learn:
                l.log_msg("Learning mode: ignore cert and store it as trusted.")
                return CertState.IGNORE
            else:
                msg = f"Certificate with fingerprint {get_cert_fingerprint_hex(downloaded_cert)} and serial {downloaded_cert.serial_number:02x} is not known locally."
                l.log_wrn(msg)
                print_cert(downloaded_cert)
                raise ValueError("SECURITY WARNING: " + msg)

        local_cert = local_certs[downloaded_cert.serial_number]

        l.log_msg("Check if certificate fingerprints match.")
        if downloaded_cert.fingerprint(hashes.SHA256()) != local_cert.fingerprint(hashes.SHA256()):
            msg = f"Local and downloaded version of certificate {downloaded_cert.serial_number:02x} have different fingerprints, but the same serial."
            l.log_wrn(msg)
            print_cert(downloaded_cert)
            raise ValueError(f"SECURITY WARNING: " + msg)
        else:
            # If the fingerprints are the same, we know the downloaded cert is the one we got via ACME.
            return CertState.VERIFIED

    except Exception as e:
        if interactive:
            # In interactive mode we ask if the exception should be ignored and the
            # certificate ignored. Otherwise we stop.
            if input(f"+ Exception detected: {e}. Accept and store (y)? ") == "y":
                return CertState.ACCEPTED
            else:
                sys.exit(1)
        else:
            # In non-interactive mode, we forward the exception.
            raise e

    raise RuntimeError("Internal error")

def main():

    parser = argparse.ArgumentParser(prog="local-check.py",
                                     description='Certificate transparency check tool')

    parser.add_argument('--verbose', help='Show more logging', action='store_true', default=False)
    parser.add_argument('--db', metavar='FILE', type=str, help='An Sqlite3 database file with known certificates, for which a decision was already made', default="known_certs.db")
    parser.add_argument('--local-certs', metavar='PATH', type=str, help='Local certificate file or a directory to check. These are the ACME-obtained certificates, for which we know they belong to us.')
    parser.add_argument('--trusted-issuer-certs', metavar='FILE', type=str, help='Expected and trusted CA certificate(s) in a file or set of files.', nargs='+')
    parser.add_argument('--learn', help='Learn previous certs as trusted. You may want to run in interactive mode, first.', action='store_true', default=False)
    parser.add_argument('--interactive', help='Interactive mode and ask what to do.', action='store_true', default=False)

    parser.add_argument('--hostname', metavar='HOSTNAME', type=str, help='Online mode: Hostname to look up at Crt.sh')
    parser.add_argument('--logged-certs', metavar='DIR', type=str,
                        help='Offline mode: A directory with certs from the Certificate Transparency Log. They are for our domains, but not necessarily requested by us. Certspotter default dir is "~/.certspotter/certs"')

    args = parser.parse_args()

    offline_mode = args.logged_certs

    l = Logger()
    l.set_interactive(args.interactive)
    l.set_verbose(args.verbose)
    if offline_mode:
        l.log_msg("Script started in offline mode.")
    else:
        l.log_msg("Script started in online mode using Crt.sh.")

    # Read current serial numbers from certificate files
    local_certs = parse_local_certs(args.local_certs)
    for cert in local_certs.values():
        l.log_msg(f"Found certificate with serial {cert.serial_number}.")

    # load issuer CA certs
    issuer_certs = [parse_cert_from_file(f) for f in args.trusted_issuer_certs]

    db = Database(args.db)

    # load certs from certspotter dir, if existent
    if args.logged_certs:
        # Do an offline test
        logged_certs = helper.parse_local_certs(os.path.expanduser(args.logged_certs))
        check_logged_certs(db, logged_certs, local_certs, issuer_certs, args.learn, args.interactive)
    else:
        # Do an online test using crt.sh
        check_crtsh(db, args.hostname, local_certs, issuer_certs, args.learn, args.interactive)

if __name__ == '__main__':
    main()

    
