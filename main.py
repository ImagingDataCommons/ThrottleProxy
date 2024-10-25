"""
Copyright 2020-2021, Institute for Systems Biology

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


from flask import Flask, abort, Response, stream_with_context, request, g, jsonify, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
from config import settings
import logging
import time
import requests
import ipaddress
from google.auth import default as get_credentials
from google.auth.transport.requests import AuthorizedSession
import datetime
import redis
import json
import re
from random import random
from urllib.parse import urlparse


#
# Configuration
#

REDIS_HOST = settings['REDIS_HOST']
REDIS_PORT = int(settings['REDIS_PORT'])

DISABLE = (settings['DISABLE'].lower() == 'true')
CHUNK_SIZE = int(settings['CHUNK_SIZE'])
GOOGLE_HC_URL = settings['GOOGLE_HC_URL']
ALLOWED_HOST = settings['ALLOWED_HOST']
DEGRADATION_LEVEL_ONE = int(settings['DEGRADATION_LEVEL_ONE'])
DEGRADATION_LEVEL_ONE_PAUSE = float(settings['DEGRADATION_LEVEL_ONE_PAUSE'])
DEGRADATION_LEVEL_TWO = int(settings['DEGRADATION_LEVEL_TWO'])
DEGRADATION_LEVEL_TWO_PAUSE = float(settings['DEGRADATION_LEVEL_TWO_PAUSE'])
MAX_PER_IP_PER_DAY = int(settings['MAX_PER_IP_PER_DAY'])
MAX_TOTAL_PER_DAY = int(settings['MAX_TOTAL_PER_DAY'])
FREE_CLOUD_REGION = settings['FREE_CLOUD_REGION']
ALLOWED_LIST = settings['ALLOWED_LIST']
DENY_LIST = settings['DENY_LIST']
UA_SECRET = settings['UA_SECRET']
RESTRICT_LIST = settings['RESTRICT_LIST']
RESTRICT_MULTIPLIER = float(settings['RESTRICT_MULTIPLIER'])
HSTS_AGE = int(settings['HSTS_AGE'])
HSTS_PRELOAD = (settings['HSTS_PRELOAD'].lower() == 'true')
USAGE_DECORATION = settings['USAGE_DECORATION']
CURRENT_STORE_PATH = settings['CURRENT_STORE_PATH']
PATH_TAIL = settings['PATH_TAIL']
ALLOWED_LEGACY_PREFIX = settings['ALLOWED_LEGACY_PREFIX']
GLOBAL_IP_ADDRESS = "192.168.255.255"
CLOUD_IP_URL = 'https://www.gstatic.com/ipranges/cloud.json'
RAND_500_RATE = float(settings['RAND_500_RATE'])
BULK_PATH_PREFIX = settings['BULK_PATH_PREFIX']
IS_BULK = (settings['IS_BULK'].lower() == 'true')
BACKOFF_COUNT = 3
ABANDON_COUNT = 10
FIX_COUNT = 3
BULK_LOG_TAG = "(BULK) " if IS_BULK else ""

app = Flask(__name__)

#
# We need to be able to extract the IP address of the actual caller, despite passing through the
# load balancer. This helps us do that cleanly:
#

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=FIX_COUNT)

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
    try:
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
    except Exception as e:
        logging.error("Exception in increment_ips: {}".format(str(e)))
        logging.exception(e)
        raise e

#
# Redis is being flaky, with lots of "connection reset by peer" errors. Do retrys inside a wrapper:
#

def redis_retry_wrapper(get_arg):

    count = 0
    retval = None
    need_answer = True
    while need_answer:
        try:
            retval = redis_client.get(get_arg)
            need_answer = False
        except Exception as e:
            logging.error("Exception in redis_retry: {}".format(str(e)))
            logging.exception(e)
            if count > ABANDON_COUNT:
                raise e
            if count > BACKOFF_COUNT:
                time.sleep(0.01 * (count - BACKOFF_COUNT))
            count += 1

    return retval


#
# Redis is being flaky, with lots of "connection reset by peer" errors. Do retrys inside a wrapper:
#

def redis_transaction_wrapper():

    count = 0
    curr_use_per_ip = None
    curr_use_global = None
    need_answer = True
    while need_answer:
        try:
            curr_use_per_ip, curr_use_global = \
                redis_client.transaction(increment_ips, g.proxy_ip_addr, GLOBAL_IP_ADDRESS, value_from_callable=True)
            need_answer = False
        except Exception as e:
            logging.error("Exception in redis_transaction_wrapper: {}".format(str(e)))
            logging.exception(e)
            if count > ABANDON_COUNT:
                raise e
            if count > BACKOFF_COUNT:
                time.sleep(0.01 * (count - BACKOFF_COUNT))
            count += 1

    return curr_use_per_ip, curr_use_global


#
# We only want to do one redis transaction per request. So we store up the data on the size and
# only update the db atomically when we are done:
#

@app.teardown_request
def teardown(request):

    try:
        if not hasattr(g, 'proxy_ip_addr'):
            if hasattr(g, 'proxy_byte_count'):
                logger.info("Skipping teardown: cloud access of %i bytes" % g.proxy_byte_count)
            return
        #logger.info("teardown_request start")
        pre_millis = int(round(time.time() * 1000))
        curr_use_per_ip, curr_use_global = redis_transaction_wrapper()
        post_millis = int(round(time.time() * 1000))
        logger.info("{}DAILY USAGE ON {} FOR IP {} is now {} bytes".format(BULK_LOG_TAG, curr_use_per_ip['day'],
                                                                         g.proxy_ip_addr, curr_use_per_ip['bytes'] ))
        logger.info("{}DAILY GLOBAL USAGE ON {} is now {} bytes".format(BULK_LOG_TAG, curr_use_global['day'], curr_use_global['bytes'] ))

        end_gb = curr_use_per_ip['bytes'] // 10737418240  # Integer divison by 10 GB

        #
        # We want to track rapid egress without flooding the system with each log message. So we look for
        # this message to send to pubsub. Note that *each* instance of this AppEngine service is going to
        # issue this message when it goes over the 10 GB thresholds.
        #
        if end_gb > g.start_gb:
            logger.info("{}DATE {} IP {} BYTES {} just chewed thru another 10 GB".format(BULK_LOG_TAG, curr_use_per_ip['day'],
                                                                                       g.proxy_ip_addr,
                                                                                       curr_use_per_ip['bytes'] ))

        logger.info("{}Transaction length ms: {}".format(BULK_LOG_TAG, str(post_millis - pre_millis)))
        logger.info("{}Chunk size was {}".format(BULK_LOG_TAG, CHUNK_SIZE))
        logger.info("{}reported bytes {}".format(BULK_LOG_TAG, g.proxy_byte_count))
        #logger.info("teardown_request done")
        return
    except Exception as e:
        logging.error("Exception in teardown: {}".format(str(e)))
        logging.exception(e)
        raise e

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

    # Originally used this structure:
    #for v in req.iter_content(chunk_size=CHUNK_SIZE):
    #    yield v
    # but it turns out that Requests decodes the stream from GZIP with that call, not
    # allowing us to pass on the gzipped stream to the caller. So, we dig down into
    # iter_content() and pull out what appears to be the relevant line from that call,
    # and change the hardwired decode_content=True argument.
    # See "def iter_content()" in https://github.com/psf/requests/blob/master/requests/models.py
    # There is some more code in there to "simulate reading small chunks of the content", which
    # appears to be irrelevant in our use case.
    # Note the comment in that function that the actual bytes returned could be different than
    # chunk size due to decoding. So by going with raw, we appear to be doing a better job of
    # tracking what goes out the door.
    #
    # (see https://requests.readthedocs.io/en/master/user/quickstart/#raw-response-content
    # and https://requests.readthedocs.io/en/master/community/faq/#encoded-data)

    try:
        for chunk in req.raw.stream(CHUNK_SIZE, decode_content=False):
            yield chunk

            g.proxy_byte_count += len(chunk)
            if delay_time > 0.0:
                time.sleep(delay_time)
    except Exception as e:
        logging.error("Exception in wrapper: {}".format(str(e)))
        logging.exception(e)
        raise e


#
# Discover the IPs living in the region where the proxy is deployed
#

def load_cidr_defs(free_region):
    cidr_defs = []
    if free_region != "NONE":
        req = requests.request("GET", CLOUD_IP_URL)
        cloud_prefixes = json.loads(req.content)
        for prefix in cloud_prefixes['prefixes']:
            if prefix['scope'] == 'us-central1':
                cidr_defs.append(ipaddress.IPv4Network(prefix['ipv4Prefix']))
    return cidr_defs

#
# Load in lists of CIDR defs for IPs we will allow or deny:
#

def load_cidr_list(list_string):
    cidr_defs = []
    if list_string == "NONE":
        return cidr_defs
    cidr_chunks = list_string.split(';')
    for cidr_chunk in cidr_chunks:
        cidr_defs.append(ipaddress.IPv4Network(cidr_chunk))
    return cidr_defs

#
# Answer if the IP address is in the given CIDR list:
#

def is_in_cidr_list(ip_addr, CIDR_defs):
    ip_addr_obj = ipaddress.IPv4Address(ip_addr)
    for cidr in CIDR_defs:
        if ip_addr_obj in cidr:
            return True
    return False

@app.route('/_ah/warmup')
def warmup():
    # We are configured with warmup requests. If we need to do something, this is the place.
    return '', 200, {}


#
# Send this back even if they just hit the server w/o a valid endpoint:
#

@app.route("/")
def return_404():
    headers = {"Strict-Transport-Security": hsts_header}
    return Response("Not Found", status=404, headers=headers)

#
# Let callers know where they stand, out of band:
#

@app.route('/quota_usage', methods=["GET", "OPTIONS"])
def quota_usage():

    client_ip = request.remote_addr

    #
    # We need to force access via our own load balancer:
    #

    hostname = urlparse(request.base_url).hostname
    if hostname != ALLOWED_HOST:
        logger.info("request from {} has been dropped: invalid hostname".format(hostname))
        abort(400)

    if DISABLE:
        logger.info("request from {} has been dropped: proxy disabled".format(client_ip))
        abort(404)

    now_time = datetime.date.today()
    todays_date = str(now_time)

    # Get bytes for this IP and for global usage:

    curr_use_per_ip_str = redis_retry_wrapper(client_ip)
    curr_use_global_str = redis_retry_wrapper(GLOBAL_IP_ADDRESS)

    curr_use_per_ip = json.loads(curr_use_per_ip_str) if curr_use_per_ip_str is not None else None
    curr_use_global = json.loads(curr_use_global_str) if curr_use_global_str is not None else None

    #logger.info("Have data for {}: {}, global: {}".format(client_ip, str(curr_use_per_ip), str(curr_use_global)))

    #
    # Always provide the cors headers to keep OHIF happy:
    #

    cors_headers = {}
    if 'origin' in request.headers:
        cors_headers = {
            "Access-Control-Allow-Origin": request.headers['origin'],
            "Access-Control-Allow-Methods": "GET",
            "Access-Control-Max-Age": "3600"
        }
        if 'access-control-request-headers' in request.headers:
            cors_headers["Access-Control-Allow-Headers"] = request.headers['access-control-request-headers']

        #logger.info("REQUEST METHOD {}".format(request.method))
        #logger.info("Request headers: {}".format(str(request.headers)))

    # Always add this:
    cors_headers["Strict-Transport-Security"] = hsts_header

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
        "date": todays_date
    }

    if curr_use_per_ip is not None:
        last_usage = curr_use_per_ip['day']
        byte_count = curr_use_per_ip['bytes']
        if last_usage != todays_date:
            byte_count = 0

        usage_return["bytes_used"] = byte_count
        usage_return["fraction_used"] = float(byte_count)/float(MAX_PER_IP_PER_DAY)

    # Suppress sending out global data!
    #if curr_use_global is not None:
    #    last_global_usage = curr_use_global['day']
    #    last_global_byte_count = curr_use_global['bytes']
    #    if last_global_usage != todays_date:
    #        last_global_byte_count = 0
    #
    #    usage_return["global_fraction_used"] = float(last_global_byte_count)/float(MAX_TOTAL_PER_DAY)

    as_json = json.dumps(usage_return)
    logger.info("[STATUS] Received usage request: {}".format(as_json))

    return Response(as_json, mimetype='application/json', headers=cors_headers)


#
# During the transition to the new request URL approach, we support the old URL pending the upgrade to the viewers.
# Note this assumes we have used the USAGE_DECORATION
#

@app.route('{}{}<path:remainder>'.format(ALLOWED_LEGACY_PREFIX, USAGE_DECORATION), methods=["GET", "OPTIONS"])
def legacy_shim(remainder):
    logger.warning("Using legacy shim for remainder: {} IP: {}".format(remainder, request.remote_addr))
    return common_core(request, '{}{}'.format(USAGE_DECORATION, remainder))

#
# The new main handler, which uses an internally configured resource path:
#

@app.route('{}/current/<path:remainder>'.format("/{}".format(BULK_PATH_PREFIX) if IS_BULK else ''), methods=["GET", "OPTIONS"])
def root(remainder):
    return common_core(request, remainder)

#
# Common core, used by both
#

def common_core(request, remainder):

    client_ip = request.remote_addr

    #
    # Even the 429, 404, and 500 responses need to provide the cors headers to keep OHIF happy enough to process these
    # errors cleanly. So we do this stuff here to make it available for all responses:
    #

    cors_headers = {}
    if 'origin' in request.headers:
        cors_headers = {
            "Access-Control-Allow-Origin": request.headers['origin'],
            "Access-Control-Allow-Methods": "GET",
            "Access-Control-Max-Age": "3600"
        }
        if 'access-control-request-headers' in request.headers:
            cors_headers["Access-Control-Allow-Headers"] = request.headers['access-control-request-headers']

    # Always add this:
    cors_headers["Strict-Transport-Security"] = hsts_header

        #logger.info("REQUEST METHOD {}".format(request.method))
        #logger.info("Request headers: {}".format(str(request.headers)))

    #
    # If an allowed hosts list exists, and the caller is not on it, we stop right here. Designed to restrict
    # access to e.g. development team:
    #

    is_denied = (len(allow_cidr_defs) > 0) and not is_in_cidr_list(client_ip, allow_cidr_defs)
    if is_denied:
        logger.info("request from {} has been dropped: not an allowed IP".format(client_ip))
        resp = Response(status=403)
        resp.headers = cors_headers
        return resp

    #
    # If a denied hosts list exists, and the caller is on it, we stop right here. Designed to block
    # IP addresses that are abusing the proxy quota system:
    #

    is_denied = (len(deny_cidr_defs) > 0) and is_in_cidr_list(client_ip, deny_cidr_defs)
    if is_denied:
        logger.info("request from {} has been dropped: a blocked IP".format(client_ip))
        resp = Response(status=403)
        resp.headers = cors_headers
        return resp

    #
    # If a restricted hosts list exists, and the caller is on it, we wre going to knock their quota down
    # by the specified amount. Allows us to throttle certain IPs to a lower level than the general public
    #

    quota_multiplier = 1.0
    is_restricted = (len(restrict_cidr_defs) > 0) and is_in_cidr_list(client_ip, restrict_cidr_defs)
    if is_restricted:
        logger.info("request from {} has restricted quota".format(client_ip))
        quota_multiplier = RESTRICT_MULTIPLIER


    #
    # If user-agent secret exists, and the user agent string does not contain it, we stop right here.
    # Another poor-man's method to restrict access to the e.g. development team:
    #

    if UA_SECRET != "NONE":
        ua_string = request.headers.get('User-Agent')
        if UA_SECRET not in ua_string:
            logger.info("request from {} has been dropped: missing UA secret".format(client_ip))
            resp = Response(status=403)
            resp.headers = cors_headers
            return resp

    #
    # We need to force access via our own load balancer:
    #

    hostname = urlparse(request.base_url).hostname
    if hostname != ALLOWED_HOST:
        logger.info("request from {} has been dropped: invalid hostname".format(hostname))
        resp = Response(status=400)
        resp.headers = cors_headers
        return resp

    if DISABLE:
        logger.info("request from {} has been dropped: proxy disabled".format(client_ip))
        resp = Response(status=404)
        resp.headers = cors_headers
        return resp

    #
    # We want to dress up the URL used by the viewers to include a usage restriction statement. If provided, this
    # MUST be present in the URL. Strip it out of the provided path, and use the rest of the path
    # to call the Healthcare API.
    #

    if USAGE_DECORATION is not None:
        if remainder.find(USAGE_DECORATION) != -1:
            remainder = remainder.replace(USAGE_DECORATION, '')
        else:
            logger.info("request from {} has been dropped: no required usage decoration in {}".format(client_ip, remainder))
            resp = Response(status=404)
            resp.headers = cors_headers
            return resp

    #
    # Ditch the expected and required path tail from the remainder:
    #

    if remainder.find(PATH_TAIL) != -1:
        remainder = remainder.replace(PATH_TAIL, '')
    else:
        logger.info("request from {} has been dropped: no required path tail in {}".format(client_ip, remainder))
        resp = Response(status=404)
        resp.headers = cors_headers
        return resp

    url = "{}/{}".format(CURRENT_STORE_PATH, remainder)

    #
    # Handle CORS:
    #

    if request.method == "OPTIONS":
        resp = Response('')
        resp.headers = cors_headers
        logger.info("returning OPTION headers {}".format(str(cors_headers)))
        return resp

    #
    # Wrap all processing so that we return CORS headers even if we fall over while processing the request:
    #

    try:
        credentials, gcp_project = get_credentials()
        scoped_credentials = credentials.with_scopes(["https://www.googleapis.com/auth/cloud-platform"])
        auth_session = AuthorizedSession(scoped_credentials)

        logger.info("[STATUS] {}Received proxy request: {}".format(BULK_LOG_TAG, url))
        #logger.info("[STATUS] Received querystring: {}".format(request.query_string.decode("utf-8")))

        #logger.info("Remote IP %s" % client_ip)
        #logger.info("Header is {}".format(request.headers.getlist("X-Forwarded-For")[0]))

        #
        # Starting in v1beta1 as of 8/2024, the Google endpoint will return the actual full enpdoint URL as the "BulkDataURI"
        # in a response for a metadata request. That's the URL that we are proxying. Thus, we need to do special handling
        # of metadata requests to recast that value into the proxy's version of the URL. Check if we have a metadata request:
        #

        need_to_rewrite = url.endswith("/metadata")

        #
        # The idea here is that a client operating in our cloud region would not have a quota, since there
        # would be no egress charge. But it turns out that bytes passing through the web app are going to get
        # charged anyway, so the functionality is of limited use:
        #

        in_our_region = is_in_cidr_list(client_ip, local_cidr_defs)

        #
        # If IP is over the daily per-IP quota, we return a 429 Too Many Requests. If we are over the global quota,
        # same thing. We are happy to just read the data at this point, and will atomically increment the whole count
        # when we are done:
        #

        delay_time = 0.0
        start_gb = 0
        if not in_our_region:
            byte_count = 0

            now_time = datetime.date.today()
            todays_date = str(now_time)
            #logger.info("Time is now {}".format(now_time.ctime()))

            #logger.info("Getting data for {}".format(client_ip))

            # Get bytes for this IP and for global usage:

            logger.info("[STATUS] Calling REDIS")
            curr_use_per_ip_str = redis_retry_wrapper(client_ip)
            curr_use_global_str = redis_retry_wrapper(GLOBAL_IP_ADDRESS)
            logger.info("[STATUS] Return from REDIS")

            curr_use_per_ip = json.loads(curr_use_per_ip_str) if curr_use_per_ip_str is not None else None
            curr_use_global = json.loads(curr_use_global_str) if curr_use_global_str is not None else None

            logger.info("{}Have data for {}: {}, global: {}".format(BULK_LOG_TAG, client_ip, str(curr_use_per_ip), str(curr_use_global)))


            # Figure out if it is a new day, bag it if we are over the limit. Note that if we need to reset the byte_count
            # to zero for a new day, we will not need to rewrite to DB yet, since the returns here will not be triggered
            # with a zero count (with sane settings):

            if curr_use_per_ip is not None:
                last_usage = curr_use_per_ip['day']
                byte_count = curr_use_per_ip['bytes']
                if last_usage != todays_date:
                    byte_count = 0

                if byte_count > (MAX_PER_IP_PER_DAY * quota_multiplier):
                    logger.info("{}Current byte count {} for IP {} exceeds daily threshold on {}".format(BULK_LOG_TAG, byte_count, client_ip, todays_date))
                    resp = Response(status=429)
                    resp.headers = cors_headers
                    return resp

                start_gb = byte_count // 10737418240  # Integer divison by 10 GB

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
                    logger.info("{}Current byte count ALL IPS exceeds daily threshold IP: {} bytes: {} date: {}".format(BULK_LOG_TAG, client_ip,
                                                                                                                      last_global_byte_count,
                                                                                                                      todays_date))
                    resp = Response(status=429)
                    resp.headers = cors_headers
                    return resp

            if delay_time > 0.0:
                logger.info("Current byte count for IP is: {} so delay is starting at {}".format(byte_count, delay_time))

            #
            # Will need this for the teardown. Don't bother to update the delay during this request.
            #

            g.proxy_ip_addr = client_ip
            g.proxy_date = todays_date
            g.start_gb = start_gb

        #
        # Both free and quota use this:
        #

        g.proxy_byte_count = 0

        #
        # It is useful to test how well the OHIF viewer handles 500 return codes. 500 returns are not uncommon when
        # App Engine needs to quickly spool up new instances when a big load appears out of the blue. So we can
        # configure the proxy to return 500s at some specified random return rate
        #

        if RAND_500_RATE > 0.0:
            rand_num = random()
            if rand_num <= RAND_500_RATE:
                logger.warning("Returning a test 500 (rate {}, val {}) to: {}".format(RAND_500_RATE, rand_num, client_ip))
                resp = Response(status=500)
                resp.headers = cors_headers
                return resp


        req_url = "{}/{}?{}".format(GOOGLE_HC_URL, url, request.query_string.decode("utf-8")) \
            if request.query_string else "{}/{}".format(GOOGLE_HC_URL, url)

        if request.query_string:
            logger.info("Request URL with query: {}".format(req_url))

        # For debug:
        #for name, value in request.headers.items():
        #    logger.info("OHIF ASK: {}: {}".format(name, value))

        #logger.info("Request headers: {}".format(str(request.headers)))
        # per https://stackoverflow.com/questions/6656363/proxying-to-another-web-service-with-flask

        stream_val = not need_to_rewrite
        req = auth_session.request(request.method, req_url, stream=stream_val,
                               headers={key: value for (key, value) in request.headers if key != 'Host'},
                               cookies=request.cookies,
                               allow_redirects=False)

        #
        # We have seen Google Healthcare API return 429s when the Healthcare API exceeds their per-minute throughput
        # quota. This produces an ambiguous situation for the viewer, since it interprets 429s as *our* daily quota.
        # We resolve this by mapping a Google Healthcare API 429 to a 500 (it is an internal error in this case,
        # kinda...). Viewer should be designed to backoff and retry with a 500, since that also happens when
        # App Engine spoolups are falling behind...
        #

        if req.status_code == 429:
            logger.warning("{}Google returned a 429, mapping to 500, for IP: {}".format(BULK_LOG_TAG, client_ip))
            resp = Response(status=500)
            resp.headers = cors_headers
            return resp

        #
        # If the Google backend has a problem and returns a 500, we want to know that *we* are not responsible for
        # the problem:
        #

        if req.status_code >= 500:
            logger.warning("ERROR: Google returned a 500 that we are passing through")
            resp = Response(status=req.status_code)
            resp.headers = cors_headers
            return resp

        #
        # NO! excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection',
        #                         'access-control-allow-origin', "access-control-allow-methods" , "access-control-allow-headers"]
        # In first iteration, included 'content-encoding' and 'content-length' in the excluded headers, since "Tried to drop
        # content-encoding from this list, as it is returned by Google, but then the browser complains that the download failed".
        # Proabably because Google said it was gzip encoded, but (see above comments on iter_content) we were unencoding the
        # zipped content before sending it out. That is fixed, so sending the headers along:
        #
        #excluded_headers = ['transfer-encoding', 'connection',

        if need_to_rewrite:
            excluded_headers = ['content-encoding', 'transfer-encoding', 'connection', 'access-control-allow-origin', "access-control-allow-methods" , "access-control-allow-headers"]
        else:
            excluded_headers = ['connection', 'access-control-allow-origin', "access-control-allow-methods" , "access-control-allow-headers"]

        # For debug
        #logger.info("GOOGLE RETURNS STATUS: {}".format(req.status_code))

        # For debug
        #for name, value in req.raw.headers.items():
        #    logger.info("GOOGLE RETURNS: {}: {}".format(name, value))

        headers = [(name, value) for (name, value) in req.raw.headers.items()
                   if name.lower() not in excluded_headers]
        if cors_headers:
            for item in cors_headers.items():
                headers.append(item)

        if need_to_rewrite:
            try:
                backend_url = '{}{}'.format(GOOGLE_HC_URL, CURRENT_STORE_PATH)
                if backend_url in req.text:
                    sub1 = r', "\w{8}": {"vr": "OB", "BulkDataURI": "'f'{backend_url}'r'/[\w/\.]*"}'
                    sub2 = r'{"\w{8}": {"vr": "OB", "BulkDataURI": "'f'{backend_url}'r'/[\w/\.]*"},'
                    logger.info(sub1)
                    logger.info(sub2)
                    patched_first_pass = re.sub(sub1, "", req.text)
                    if patched_first_pass == req.text:
                        logger.info("first pass unchanged")
                    patched_text = re.sub(sub2, "{", patched_first_pass)
                    if patched_first_pass == patched_text:
                        logger.info("second pass unchanged")
                        if "BulkDataURI" not in req.text:
                            logger.info("Have suppressed a bulk data key-value for: {}".format(backend_url))
                        else:
                            logger.info("Have NOT suppressed a bulk data key-value for: {}".format(backend_url))
                else:
                    patched_text = req.text
                json_metadata = json.loads(patched_text)
            except requests.JSONDecodeError as e:
                logging.error("Exception parsing JSON Metadata: {}".format(str(e)))
                logging.exception(e)
                resp = Response(status=500)
                resp.headers = cors_headers
                return resp
            resp_as_json = json.dumps(json_metadata)
            g.proxy_byte_count += len(resp_as_json)
            res = make_response(resp_as_json, req.status_code)
            res.headers = headers
            return res
        else:
            #logger.info("Response headers: {}".format(str(headers)))
            return Response(stream_with_context(counting_wrapper(req, delay_time)), headers=headers, status=req.status_code)
    except Exception as e:
        logging.error("Exception processing request: {}".format(str(e)))
        logging.exception(e)
        resp = Response(status=500)
        resp.headers = cors_headers
        return resp

root.provide_automatic_options = False

#
# Load in the info on what IP addresses are in a zone that we will allow unlimited access
#

local_cidr_defs = load_cidr_defs(FREE_CLOUD_REGION)
allow_cidr_defs = load_cidr_list(ALLOWED_LIST)
deny_cidr_defs = load_cidr_list(DENY_LIST)
restrict_cidr_defs = load_cidr_list(RESTRICT_LIST)
hsts_preload_directive = "; preload" if HSTS_PRELOAD else ""
hsts_header = 'max-age={}; includeSubDomains{}'.format(HSTS_AGE, hsts_preload_directive)


if __name__ == '__main__':
    app.run()
