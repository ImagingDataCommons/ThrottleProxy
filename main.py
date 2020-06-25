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


from flask import Flask, abort, Response, stream_with_context, request, g, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
from config import settings
import logging
import time
from google.auth import default as get_credentials
from google.auth.transport.requests import AuthorizedSession
import datetime
import redis
import json

#
# Configuration
#

REDIS_HOST = settings['REDIS_HOST']
REDIS_PORT = int(settings['REDIS_PORT'])

DISABLE = (settings['DISABLE'].lower() == 'true')
CHUNK_SIZE = int(settings['CHUNK_SIZE'])
GOOGLE_HC_URL = settings['GOOGLE_HC_URL']
SUPPORTED_PROJECT = settings['SUPPORTED_PROJECT']
DEGRADATION_LEVEL_ONE = int(settings['DEGRADATION_LEVEL_ONE'])
DEGRADATION_LEVEL_ONE_PAUSE = float(settings['DEGRADATION_LEVEL_ONE_PAUSE'])
DEGRADATION_LEVEL_TWO = int(settings['DEGRADATION_LEVEL_TWO'])
DEGRADATION_LEVEL_TWO_PAUSE = float(settings['DEGRADATION_LEVEL_TWO_PAUSE'])
MAX_PER_IP_PER_DAY = int(settings['MAX_PER_IP_PER_DAY'])
MAX_TOTAL_PER_DAY = int(settings['MAX_TOTAL_PER_DAY'])
GLOBAL_IP_ADDRESS = "192.168.255.255"

app = Flask(__name__)

#
# We need to be able to extract the IP address of the actual caller, despite passing through the
# load balancer. This helps us do that cleanly:
#

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2)

#
# Logging:
#

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main.py")

#
# Ok, this is the client we use for this server. Note that it is backed by a connection pool that is managed in
# a way that does not require us to explicitly release the connection on teardown!
#

redis_client = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT)

#
# This function does everything we wish to do inside a redis transaction.
# See: https://github.com/andymccurdy/redis-py/blob/master/README.rst#pipelines
#

def increment_ips(pipe):
    curr_use_per_ip_str = pipe.get(g.proxy_ip_addr)
    curr_use_global_str = pipe.get(GLOBAL_IP_ADDRESS)

    curr_use_per_ip = json.loads(curr_use_per_ip_str) if curr_use_per_ip_str is not None else None
    curr_use_global = json.loads(curr_use_global_str) if curr_use_global_str is not None else None

    if curr_use_per_ip is not None:
        if curr_use_per_ip['day'] != g.proxy_date:
            curr_use_per_ip['day'] = g.proxy_date
            curr_use_per_ip['bytes'] = 0
        curr_use_per_ip['bytes'] += g.proxy_byte_count
    else:
        curr_use_per_ip = {
                           'day':  g.proxy_date,
                           'bytes': g.proxy_byte_count
                          }
    if curr_use_global is not None:
        if curr_use_global['day'] != g.proxy_date:
            curr_use_global['day'] = g.proxy_date
            curr_use_global['bytes'] = 0
        curr_use_global['bytes'] += g.proxy_byte_count
    else:
        curr_use_global = {
                           'day': g.proxy_date,
                           'bytes': g.proxy_byte_count
                          }

    pipe.multi()
    pipe.set(g.proxy_ip_addr, json.dumps(curr_use_per_ip))
    pipe.set(GLOBAL_IP_ADDRESS, json.dumps(curr_use_global))
    return curr_use_per_ip, curr_use_global

#
# We only want to do one redis transaction per request. So we store up the data on the size and
# only update the db atomically when we are done:
#

@app.teardown_request
def teardown(request):

    if not hasattr(g, 'proxy_ip_addr'):
        return
    #logger.info("teardown_request start")
    pre_millis = int(round(time.time() * 1000))
    curr_use_per_ip, curr_use_global = \
        redis_client.transaction(increment_ips, g.proxy_ip_addr, GLOBAL_IP_ADDRESS, value_from_callable=True)
    post_millis = int(round(time.time() * 1000))
    logger.info("DAILY USAGE ON {} FOR IP {} is now {} bytes".format(curr_use_per_ip['day'],
                                                                     g.proxy_ip_addr, curr_use_per_ip['bytes'] ))
    logger.info("DAILY GLOBAL USAGE ON {} is now {} bytes".format(curr_use_global['day'], curr_use_global['bytes'] ))
    logger.info("Transaction length ms: {}".format(str(post_millis - pre_millis)))
    #logger.info("teardown_request done")
    return

#
# We can optionally impose a "delay" time as the user gets close to the limit by providing
# values for these constants > 0. Note, however, that this will require Google to spin up other
# instances through the load balancer to keep up with traffic, as this just sleeps this instance:
#

def calc_delay(byte_count):
    if (DEGRADATION_LEVEL_TWO > 0) and (byte_count > DEGRADATION_LEVEL_TWO):
        delay_time = DEGRADATION_LEVEL_TWO_PAUSE
    elif (DEGRADATION_LEVEL_ONE > 0) and (byte_count > DEGRADATION_LEVEL_ONE):
        delay_time = DEGRADATION_LEVEL_ONE_PAUSE
    else:
        delay_time = 0.0

    return delay_time

#
# This is streaming content, so we count the bytes as they go out the door, based on our streaming chunk size. This
# slightly overcounts, since we don't know how many bytes go out on the last call:
#

def counting_wrapper(req, delay_time):

    # This is too simple; current Python 3 uses "yield from". But we need to
    # do stuff on each call. So should implement full yield from semantics shown at
    # https://www.python.org/dev/peps/pep-0380/


    # NO! Use Response.raw, not iter_content. The latter will decompress the result
    # coming back from Google!
    # (see https://requests.readthedocs.io/en/master/user/quickstart/#raw-response-content
    # and https://requests.readthedocs.io/en/master/community/faq/#encoded-data)
    for v in req.iter_content(chunk_size=CHUNK_SIZE):
        yield v

        g.proxy_byte_count += CHUNK_SIZE
        if delay_time > 0.0:
            time.sleep(delay_time)


@app.route('/_ah/warmup')
def warmup():
    # We are configured with warmup requests. If we need to do something, this is the place.
    return '', 200, {}

#
# Let callers know where they stand, out of band:
#

@app.route('/quota_usage', methods=["GET", "OPTIONS"])
def quota_usage():

    client_ip = request.remote_addr

    if DISABLE:
        logger.info("request from {} has been dropped: proxy disabled".format(client_ip))
        abort(404)

    now_time = datetime.date.today()
    todays_date = str(now_time)

    # Get bytes for this IP and for global usage:

    curr_use_per_ip_str = redis_client.get(client_ip)
    curr_use_global_str = redis_client.get(GLOBAL_IP_ADDRESS)

    curr_use_per_ip = json.loads(curr_use_per_ip_str) if curr_use_per_ip_str is not None else None
    curr_use_global = json.loads(curr_use_global_str) if curr_use_global_str is not None else None

    logger.info("Have data for {}: {}, global: {}".format(client_ip, str(curr_use_per_ip), str(curr_use_global)))

    #
    # Always provide the cors headers to keep OHIF happy:
    #

    cors_headers = None
    if 'origin' in request.headers:
        cors_headers = {
            "Access-Control-Allow-Origin": request.headers['origin'],
            "Access-Control-Allow-Methods": "GET"
        }
        if 'access-control-request-headers' in request.headers:
            cors_headers["Access-Control-Allow-Headers"] = request.headers['access-control-request-headers']

        logger.info("REQUEST METHOD {}".format(request.method))
        logger.info("Request headers: {}".format(str(request.headers)))

    if request.method == "OPTIONS":
        resp = Response('')
        resp.headers = cors_headers
        logger.info("returning OPTION headers {}".format(str(cors_headers)))
        return resp

    # Figure out if it is a new day, bag it if we are over the limit. Note that if we need to reset the byte_count
    # to zero for a new day, we will not need to rewrite to DB yet, since the returns here will not be triggered
    # with a zero count (with sane settings):

    usage_return = {
        "ip": client_ip,
        "bytes_used": 0,
        "fraction_used": 0.0,
        "global_fraction_used": 0.0,
        "date": todays_date
    }

    if curr_use_per_ip is not None:
        last_usage = curr_use_per_ip['day']
        byte_count = curr_use_per_ip['bytes']
        if last_usage != todays_date:
            byte_count = 0

        usage_return["bytes_used"] = byte_count
        usage_return["fraction_used"] = float(byte_count)/float(MAX_PER_IP_PER_DAY)

    if curr_use_global is not None:
        last_global_usage = curr_use_global['day']
        last_global_byte_count = curr_use_global['bytes']
        if last_global_usage != todays_date:
            last_global_byte_count = 0

        usage_return["global_fraction_used"] = float(last_global_byte_count)/float(MAX_TOTAL_PER_DAY)

    return jsonify(usage_return)

#
# Needs to match on e.g. this:
# https://idc-sandbox-002.appspot.com/v1beta1/projects/chc-tcia/locations/us-central1/datasets/tcga-gbm/dicomStores/tcga-gbm/dicomWeb/studies/1.3.6.1.4.1.14519.5.2.1.4591.4001.292494376567537333391334418593/series
#

@app.route('/<version>/projects/<project>/locations/<location>/datasets/<path:remainder>', methods=["GET", "OPTIONS"])
def root(version, project, location, remainder):

    client_ip = request.remote_addr

    if DISABLE:
        logger.info("request from {} has been dropped: proxy disabled".format(client_ip))
        abort(404)

    url = "/{}/projects/{}/locations/{}/datasets/{}".format(version, project, location, remainder)

    if project != SUPPORTED_PROJECT:
        logger.info("request from {} has been dropped: unsupported project {}".format(client_ip, project))
        abort(404)

    credentials, gcp_project = get_credentials()
    scoped_credentials = credentials.with_scopes(["https://www.googleapis.com/auth/cloud-platform"])
    auth_session = AuthorizedSession(scoped_credentials)

    logger.info("[STATUS] Received proxy request: {}".format(url))
    #logger.info("[STATUS] Received querystring: {}".format(request.query_string.decode("utf-8")))

    #logger.info("Remote IP %s" % client_ip)
    #logger.info("Header is {}".format(request.headers.getlist("X-Forwarded-For")[0]))

    #
    # If IP is over the daily per-IP quota, we return a 429 Too Many Requests. If we are over the global quota,
    # same thing. We are happy to just read the data at this point, and will atomically increment the whole count
    # when we are done:
    #

    byte_count = 0
    delay_time = 0.0

    now_time = datetime.date.today()
    todays_date = str(now_time)
    logger.info("Time is now {}".format(now_time.ctime()))

    #logger.info("Getting data for {}".format(client_ip))

    # Get bytes for this IP and for global usage:

    curr_use_per_ip_str = redis_client.get(client_ip)
    curr_use_global_str = redis_client.get(GLOBAL_IP_ADDRESS)

    curr_use_per_ip = json.loads(curr_use_per_ip_str) if curr_use_per_ip_str is not None else None
    curr_use_global = json.loads(curr_use_global_str) if curr_use_global_str is not None else None

    logger.info("Have data for {}: {}, global: {}".format(client_ip, str(curr_use_per_ip), str(curr_use_global)))

    #
    # Even the 429 response needs to provide the cors headers to keep OHIF happy enough to process the 429
    # response cleanly. So we do this stuff here to make it available for all responses:
    #

    cors_headers = None
    if 'origin' in request.headers:
        cors_headers = {
            "Access-Control-Allow-Origin": request.headers['origin'],
            "Access-Control-Allow-Methods": "GET"
        }
        if 'access-control-request-headers' in request.headers:
            cors_headers["Access-Control-Allow-Headers"] = request.headers['access-control-request-headers']

        logger.info("REQUEST METHOD {}".format(request.method))
        logger.info("Request headers: {}".format(str(request.headers)))

    if request.method == "OPTIONS":
        resp = Response('')
        resp.headers = cors_headers
        logger.info("returning OPTION headers {}".format(str(cors_headers)))
        return resp

    # Figure out if it is a new day, bag it if we are over the limit. Note that if we need to reset the byte_count
    # to zero for a new day, we will not need to rewrite to DB yet, since the returns here will not be triggered
    # with a zero count (with sane settings):

    if curr_use_per_ip is not None:
        last_usage = curr_use_per_ip['day']
        byte_count = curr_use_per_ip['bytes']
        if last_usage != todays_date:
            byte_count = 0

        if byte_count > MAX_PER_IP_PER_DAY:
            logger.info("Current byte count {} for IP {} exceeds daily threshold on {}".format(byte_count, client_ip, todays_date))
            resp = Response(status=429)
            resp.headers = cors_headers
            return resp

        delay_time = calc_delay(byte_count)
        if delay_time > 0.0:
            time.sleep(delay_time)

    if curr_use_global is not None:
        last_global_usage = curr_use_global['day']
        last_global_byte_count = curr_use_global['bytes']
        if last_global_usage != todays_date:
            last_global_byte_count = 0

        # Delays are not supported for the global limit:
        if last_global_byte_count > MAX_TOTAL_PER_DAY:
            logger.info("Current byte count ALL IPS exceeds daily threshold IP: {} bytes: {} date: {}".format(client_ip,
                                                                                                              last_global_byte_count,
                                                                                                              todays_date))
            resp = Response(status=429)
            resp.headers = cors_headers
            return resp

    if delay_time > 0.0:
        logger.info("Current byte count for IP is: {} so delay is starting at {}".format(byte_count, delay_time))

    req_url = "{}/{}?{}".format(GOOGLE_HC_URL, url, request.query_string.decode("utf-8")) \
        if request.query_string else "{}/{}".format(GOOGLE_HC_URL, url)

    #logger.info("Request URL: {}".format(req_url))

    #
    # Will need this for the teardown. Don't bother to update the delay during this request.
    #

    g.proxy_ip_addr = client_ip
    g.proxy_date = todays_date
    g.proxy_byte_count = 0

    #logger.info("Request headers: {}".format(str(request.headers)))
    # per https://stackoverflow.com/questions/6656363/proxying-to-another-web-service-with-flask
    req = auth_session.request(request.method, req_url, stream=True,
                           headers={key: value for (key, value) in request.headers if key != 'Host'},
                           cookies=request.cookies,
                           allow_redirects=False)
    # Tried to drop content-encoding from this list, as it is returned by Google, but then the browser complains
    # that the download failed:
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection',
                        'access-control-allow-origin', "access-control-allow-methods" , "access-control-allow-headers"]
    headers = [(name, value) for (name, value) in req.raw.headers.items()
               if name.lower() not in excluded_headers]
    if cors_headers:
        for item in cors_headers.items():
            headers.append(item)

    #logger.info("Response headers: {}".format(str(headers)))
    return Response(stream_with_context(counting_wrapper(req, delay_time)), headers=headers)

root.provide_automatic_options = False

if __name__ == '__main__':
    app.run()
