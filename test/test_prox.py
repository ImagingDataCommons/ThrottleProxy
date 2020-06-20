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


'''
        "request": {
          "bodySize": 0,
          "method": "OPTIONS",
          "url": "https://healthcare.googleapis.com/v1beta1/projects/chc-tcia/locations/us-central1/datasets/tcga-brca/dicomStores/tcga-brca/dicomWeb/studies/1.3.6.1.4.1.14519.5.2.1.9203.4002.240753407080370737439271619596/series/1.3.6.1.4.1.14519.5.2.1.9203.4002.113170262927555385612922478544/instances/1.3.6.1.4.1.14519.5.2.1.9203.4002.502593709247672019902402884413/frames/1",
          "httpVersion": "HTTP/2",
          "headers": [
            {
              "name": "Host",
              "value": "healthcare.googleapis.com"
            },
            {
              "name": "User-Agent",
              "value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:74.0) Gecko/20100101 Firefox/74.0"
            },
            {
              "name": "Accept",
              "value": "*/*"
            },
            {
              "name": "Accept-Language",
              "value": "en-US,en;q=0.5"
            },
            {
              "name": "Accept-Encoding",
              "value": "gzip, deflate, br"
            },
            {
              "name": "Access-Control-Request-Method",
              "value": "GET"
            },
            {
              "name": "Access-Control-Request-Headers",
              "value": "accept,authorization"
            },
            {
              "name": "Referer",
              "value": "https://idc-dev.appspot.com/projects/chc-tcia/locations/us-central1/datasets/tcga-brca/dicomStores/tcga-brca/study/1.3.6.1.4.1.14519.5.2.1.9203.4002.240753407080370737439271619596"
            },
            {
              "name": "Origin",
              "value": "https://idc-dev.appspot.com"
            },
            {
              "name": "Connection",
              "value": "keep-alive"
            },
            {
              "name": "TE",
              "value": "Trailers"
            }
          ],
          "cookies": [],
          "queryString": [],
          "headersSize": 900
        },
        "response": {
          "status": 200,
          "statusText": "OK",
          "httpVersion": "HTTP/2",
          "headers": [
            {
              "name": "access-control-allow-origin",
              "value": "https://idc-dev.appspot.com"
            },
            {
              "name": "vary",
              "value": "origin"
            },
            {
              "name": "vary",
              "value": "referer"
            },
            {
              "name": "vary",
              "value": "x-origin"
            },
            {
              "name": "access-control-allow-methods",
              "value": "DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT"
            },
            {
              "name": "access-control-allow-headers",
              "value": "accept,authorization"
            },
            {
              "name": "access-control-max-age",
              "value": "3600"
            },
            {
              "name": "date",
              "value": "Tue, 31 Mar 2020 01:07:47 GMT"
            },
            {
              "name": "content-type",
              "value": "text/html"
            },
            {
              "name": "server",
              "value": "ESF"
            },
            {
              "name": "content-length",
              "value": "0"
            },
            {
              "name": "x-xss-protection",
              "value": "0"
            },
            {
              "name": "x-frame-options",
              "value": "SAMEORIGIN"
            },
            {
              "name": "x-content-type-options",
              "value": "nosniff"
            },
            {
              "name": "alt-svc",
              "value": "quic=\":443\"; ma=2592000; v=\"46,43\",h3-Q050=\":443\"; ma=2592000,h3-Q049=\":443\"; ma=2592000,h3-Q048=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000,h3-T050=\":443\"; ma=2592000"
            },
            {
              "name": "X-Firefox-Spdy",
              "value": "h2"
            }
          ],
          "cookies": [],
          "content": {
            "mimeType": "text/html",
            "size": 0,
            "text": ""
          },
          "redirectURL": "",
          "headersSize": 664,
          "bodySize": 664
        },



'''

'''
        "request": {
          "bodySize": 0,
          "method": "GET",
          "url": "https://healthcare.googleapis.com/v1beta1/projects/chc-tcia/locations/us-central1/datasets/tcga-brca/dicomStores/tcga-brca/dicomWeb/studies/1.3.6.1.4.1.14519.5.2.1.9203.4002.240753407080370737439271619596/series/1.3.6.1.4.1.14519.5.2.1.9203.4002.113170262927555385612922478544/instances/1.3.6.1.4.1.14519.5.2.1.9203.4002.103706408612581767733673809486/frames/1",
          "httpVersion": "HTTP/2",
          "headers": [
            {
              "name": "Host",
              "value": "healthcare.googleapis.com"
            },
            {
              "name": "User-Agent",
              "value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:74.0) Gecko/20100101 Firefox/74.0"
            },
            {
              "name": "Accept",
              "value": "multipart/related; type=\"application/octet-stream\""
            },
            {
              "name": "Accept-Language",
              "value": "en-US,en;q=0.5"
            },
            {
              "name": "Accept-Encoding",
              "value": "gzip, deflate, br"
            },
            {
              "name": "Authorization",
              "value": "Bearer ya29.a0Ae4lvC32HOpzzV6ZBRoUc3R7R2OhZVJh9vT7lNVlHjtQxiVodQ8QsREvGV440GW3rpFnoW4t7LYifXTGnP62j-DfMxTAuYvxiosAny7TPcjJZaKMumVitoNfFlX1Zb-kXGK8g1DVc7tLVgiV2Ys8Vb9OnBpdXJQboCilQw"
            },
            {
              "name": "Origin",
              "value": "https://idc-dev.appspot.com"
            },
            {
              "name": "Connection",
              "value": "keep-alive"
            },
            {
              "name": "Referer",
              "value": "https://idc-dev.appspot.com/projects/chc-tcia/locations/us-central1/datasets/tcga-brca/dicomStores/tcga-brca/study/1.3.6.1.4.1.14519.5.2.1.9203.4002.240753407080370737439271619596"
            },
            {
              "name": "TE",
              "value": "Trailers"
            }
          ],
          "cookies": [],
          "queryString": [],
          "headersSize": 1050
        },
        "response": {
          "status": 200,
          "statusText": "OK",
          "httpVersion": "HTTP/2",
          "headers": [
            {
              "name": "content-type",
              "value": "multipart/related; boundary=45313be6bc4971b04de7f03701085b9d9534ee7b5ffe86ba48c12018cff4; transfer-syntax=1.2.840.10008.1.2.1; type=\"application/octet-stream\""
            },
            {
              "name": "vary",
              "value": "Origin"
            },
            {
              "name": "vary",
              "value": "X-Origin"
            },
            {
              "name": "vary",
              "value": "Referer"
            },
            {
              "name": "content-encoding",
              "value": "gzip"
            },
            {
              "name": "date",
              "value": "Tue, 31 Mar 2020 01:07:47 GMT"
            },
            {
              "name": "server",
              "value": "ESF"
            },
            {
              "name": "cache-control",
              "value": "private"
            },
            {
              "name": "x-xss-protection",
              "value": "0"
            },
            {
              "name": "x-frame-options",
              "value": "SAMEORIGIN"
            },
            {
              "name": "x-content-type-options",
              "value": "nosniff"
            },
            {
              "name": "access-control-allow-origin",
              "value": "https://idc-dev.appspot.com"
            },
            {
              "name": "access-control-expose-headers",
              "value": "content-encoding,transfer-encoding,date,server"
            },
            {
              "name": "alt-svc",
              "value": "quic=\":443\"; ma=2592000; v=\"46,43\",h3-Q050=\":443\"; ma=2592000,h3-Q049=\":443\"; ma=2592000,h3-Q048=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000,h3-T050=\":443\"; ma=2592000"
            },
            {
              "name": "X-Firefox-Spdy",
              "value": "h2"
            }
          ],
          "cookies": [],

'''





    print("All tests passed")

if __name__ == '__main__':
    main()
