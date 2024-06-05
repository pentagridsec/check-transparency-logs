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

import argparse
import os
import sys

import helper
from Crtsh import Crtsh
from Sslmate import Sslmate
from helper import download_cert_from_host
from logger import Logger


def main():

    global verbose_flag, interactive_flag

    parser = argparse.ArgumentParser(prog="local-check.py",
                                     description='Certificate transparency check tool')

    parser.add_argument('--verbose', help='Show more logging', action='store_true', default=False)
    parser.add_argument('--hostname', metavar='HOSTNAME', type=str, help='Hostname to look up', required=True)
    parser.add_argument('--port', metavar='PORT', type=int, help='Port number. The script expects standard TLS, but does a STARTTLS for port 25.', required=True)
    parser.add_argument('--trusted-issuer-certs', metavar='FILE', type=str, help=f'Expected and trusted issuer certificate(s) in a file', nargs='+')
    parser.add_argument('--logged-certs', metavar='DIR', type=str, help=f'A directory with certs from the Certificate Transparency Log', default="~/.certspotter/certs")
    parser.add_argument('--expect-certspotter', help='OR: Expect certificate to be logged in certspotter cert dir.', action='store_true', default=False)
    parser.add_argument('--expect-crtsh', help='OR: Expect certificate to be logged in crt.sh service.', action='store_true', default=False)
    parser.add_argument('--expect-sslmate', help='OR: Expect certificate to be logged in sslmate service.', action='store_true', default=False)


    args = parser.parse_args()
    l = Logger()
    l.set_verbose(args.verbose)

    logged_certs = {}
    crtsh = Crtsh()
    sslmate = Sslmate()

    # load trusted issuer certs
    issuer_certs = [helper.parse_cert_from_file(f) for f in args.trusted_issuer_certs]

    # load certs from certspotter dir (it ignores pre-certs)
    if args.expect_certspotter:
        logged_certs = helper.parse_local_certs(os.path.expanduser(args.logged_certs))

    # download cert
    downloaded_cert = download_cert_from_host(args.hostname, args.port)

    if not helper.verify_cert_signature(downloaded_cert, issuer_certs):
        print("CRITICAL - Certificate is from an unexpected CA and is not trusted.")
        sys.exit(2)

    l.log_msg("Check if cert has SCT.")
    if not helper.has_sct(downloaded_cert):
        print("CRITICAL - Certificate has no STC.")
        sys.exit(2)

    if args.expect_certspotter:
        l.log_msg(f"Lookup cert with serial {downloaded_cert.serial_number} in directory {args.logged_certs}.")
        if downloaded_cert.serial_number in logged_certs:
            print("OK - Downloaded certificate found in certspotter directory. Do not try further lookups.")
            sys.exit(0)

    if args.expect_crtsh and crtsh.find_cert(args.hostname, downloaded_cert):
        print("OK - Downloaded certificate found at crt.sh. Do not try further lookups.")
        sys.exit(0)

    if args.expect_sslmate and sslmate.find_cert(args.hostname, downloaded_cert):
        print("OK - Downloaded certificate found at sslmate. Do not try further lookups.")
        sys.exit(0)

    print("CRITICAL - Certificate not found in any transparency log or online service.")
    sys.exit(2)

if __name__ == '__main__':
    main()

    
