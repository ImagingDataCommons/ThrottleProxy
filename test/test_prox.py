"""
Copyright 2020, Institute for Systems Biology

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


import requests
import email
import hashlib
from google.auth import default as get_credentials
from google.auth.transport.requests import AuthorizedSession
from config import settings

GOOG_SERVER = settings['GOOG_SERVER']
PROX_SERVER = settings['PROX_SERVER']
URL_META = settings['URL_META']
URL_FRAME_1 = settings['URL_FRAME_1']
URL_FRAME_2 = settings['URL_FRAME_2']
URL_STUDIES_1 = settings['URL_STUDIES_1']

def payload(content):
    msg = email.parser.BytesParser().parsebytes(content)
    for part in msg.walk():
        pay_load = part.get_payload(decode=False)
        splits = pay_load.splitlines()
        pay_load = "".join(splits[2:-2])
        return pay_load

def analyze(payload):
    hash_object = hashlib.md5(str(payload).encode('utf-8'))
    return len(payload), hash_object.hexdigest()

def main():

    credentials, project = get_credentials()
    scoped_credentials = credentials.with_scopes(["https://www.googleapis.com/auth/cloud-platform"])
    auth_session = AuthorizedSession(scoped_credentials)

    url_1 = URL_META
    url_2 = URL_FRAME_1
    url_3 = URL_FRAME_2
    url_4 = URL_STUDIES_1

    url_1_ghc = url_1.format(GOOG_SERVER)
    req = auth_session.get(url_1_ghc)
    ghc_len_1, ghc_hash_1 = analyze(req.content)

    url_2_ghc = url_2.format(GOOG_SERVER)
    req = auth_session.get(url_2_ghc)
    pl = payload(req.content)
    ghc_len_2, ghc_hash_2 = analyze(pl)

    url_3_ghc = url_3.format(GOOG_SERVER)
    req = auth_session.get(url_3_ghc)
    pl = payload(req.content)
    ghc_len_3, ghc_hash_3 = analyze(pl)

    url_4_ghc = url_4.format(GOOG_SERVER)
    req = auth_session.get(url_4_ghc)
    pl = payload(req.content)
    ghc_len_4, ghc_hash_4 = analyze(pl)

    url_1_prox = url_1.format(PROX_SERVER)
    req = requests.request("GET", url_1_prox)
    prox_len_1, prox_hash_1 = analyze(req.content)
    assert(prox_hash_1 == ghc_hash_1)
    assert(prox_len_1 == ghc_len_1)

    url_2_prox = url_2.format(PROX_SERVER)
    req = requests.request("GET", url_2_prox)
    pl = payload(req.content)
    prox_len_2, prox_hash_2 = analyze(pl)
    assert(prox_hash_2 == ghc_hash_2)
    assert(prox_len_2 == ghc_len_2)

    url_3_prox = url_3.format(PROX_SERVER)
    req = requests.request("GET", url_3_prox)
    pl = payload(req.content)
    prox_len_3, prox_hash_3 = analyze(pl)
    assert(prox_hash_3 == ghc_hash_3)
    assert(prox_len_3 == ghc_len_3)

    url_4_prox = url_4.format(PROX_SERVER)
    print(url_4_prox)
    req = requests.request("GET", url_4_prox)
    pl = payload(req.content)
    prox_len_4, prox_hash_4 = analyze(pl)
    assert(prox_hash_4 == ghc_hash_4)
    assert(prox_len_4 == ghc_len_4)




    print("All tests passed")

if __name__ == '__main__':
    main()
