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

from typing import Dict

import requests
from requests.adapters import HTTPAdapter
from urllib3 import Retry

class HTTPRequestor():

    def __init__(self):
        """
        Create a new downloaer, which keeps tracks of temporarily server errors.
        """
        retry_strategy = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            respect_retry_after_header=True
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.http = requests.Session()
        self.http.mount("https://", adapter)
        self.http.mount("http://", adapter)

    def _get(self, url: str, params: Dict[str, object]) -> requests.Response:
        """
        Internal helper for send GET requests.
        :param url: The URL to download.
        :param params: Parameters to pass to Request.get.
        :return: Returns a Response object.
        """
        r = self.http.get(url, params=params)

        if r.status_code != 200:
            raise RuntimeError(f"Failed to download certificate. HTTP status code is {r.status_code}.")

        return r

    def get(self, url: str, params: Dict[str, object]) -> bytes:
        """
        Wrapper for GET requests to an URL with parameters. Gets the content as bytes.
        :param url: The URL to download.
        :param params: Parameters to pass to Request.get.
        :return: Returns the reponse as bytes.
        """
        return self._get(url, params).content

    def get_json(self, url: str, params: Dict[str, object]) -> Dict[str, object]:
        """
        Wrapper for GET requests to an URL with parameters. Gets the content as JSON.
        :param url: The URL to download.
        :param params: Parameters to pass to Request.get.
        :return: Returns the reponse as JSON.
        """
        return self._get(url, params).json()
