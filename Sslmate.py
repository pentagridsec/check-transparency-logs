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

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from HTTPRequestor import HTTPRequestor
from helper import print_cert
from logger import Logger


class Sslmate:

	def __init__(self):
		self.dl = HTTPRequestor()

	def find_cert(self, hostname: str, cert: x509.Certificate) -> bool:
		"""
		Check if a certificate is in the transparency log using the Sslmate API.
		:param hostname: Hostname to use for the lookup.
		:param cert: An x509.Certificate object, which is looked up via the API.
		:return: Returns True if the certificate was found and False otherwise.
		"""

		l = Logger()
		l.log_msg(f"Lookup cert with serial {cert.serial_number} on sslmate.com.")

		hash = "".join([format(i, '02X') for i in cert.fingerprint(hashes.SHA256())])

		for jcert in self.dl.get_json("https://api.certspotter.com/v1/issuances", params={'domain': hostname}):

			# print(f"+ Check if {jcert['cert_sha256']} == {hash} ")
			if jcert['cert_sha256'].upper() == hash:
				return True

		l.log_msg(f"Serial {cert.serial_number} not found for {hostname} on sslmate.com.")
		#print_cert(cert)
		return False
