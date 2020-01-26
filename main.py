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

from flask import Flask, abort, Response, stream_with_context, request
from config import settings
import logging
import time
from google.auth import default as get_credentials
from google.auth.transport.requests import AuthorizedSession
from datetime import date

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main.py")

#
# Configuration
#

CHUNK_SIZE = int(settings['CHUNK_SIZE'])
GOOGLE_HC_URL = settings['GOOGLE_HC_URL']
DEGRADATION_LEVEL_ONE = int(settings['DEGRADATION_LEVEL_ONE'])
DEGRADATION_LEVEL_ONE_PAUSE = float(settings['DEGRADATION_LEVEL_ONE_PAUSE'])
DEGRADATION_LEVEL_TWO = int(settings['DEGRADATION_LEVEL_TWO'])
DEGRADATION_LEVEL_TWO_PAUSE = float(settings['DEGRADATION_LEVEL_TWO_PAUSE'])
MAX_PER_IP_PER_DAY = int(settings['MAX_PER_IP_PER_DAY'])
MAX_TOTAL_PER_DAY = int(settings['MAX_TOTAL_PER_DAY'])

#
# In-memory storage of usage per IP. If we want to make it more robust, use persistent storage instead:
#

usage = {}

#
# We have a global cap across all IPs as well
#

all_ip_bytes_today = 0
date_for_byte_count = date.today()

def counting_wrapper(req, ip_addr, count_usage):

    global date_for_byte_count
    global all_ip_bytes_today

    # This is too simple; current Python 3 uses "yield from". But we need to
    # do stuff on each call. So should implement full yield from semantics shown at
    # https://www.python.org/dev/peps/pep-0380/


    for v in req.iter_content(chunk_size=CHUNK_SIZE):
        yield v
        curr_use_per_ip = count_usage[ip_addr] if ip_addr in count_usage else {}
        today = date.today()
        #
        # We keep a count of bytes per day per IP. If the date has changed, we zero the bytes, reset
        # the day, and start again.
        #
        last_usage = curr_use_per_ip['day'] if 'day' in curr_use_per_ip else today
        byte_count = curr_use_per_ip['bytes'] if 'bytes' in curr_use_per_ip else 0
        if date_for_byte_count != today:
            date_for_byte_count = today
            all_ip_bytes_today = 0

        if last_usage != today:
            last_usage = today
            byte_count = 0

        curr_use_per_ip['day'] = last_usage
        new_byte_count = byte_count + CHUNK_SIZE
        curr_use_per_ip['bytes'] = new_byte_count
        count_usage[ip_addr] = curr_use_per_ip
        all_ip_bytes_today += CHUNK_SIZE

        #
        # We will permit the current request to complete even if it goes over the threshold. Next call
        # will fail, however.
        #

        if new_byte_count > DEGRADATION_LEVEL_TWO:
            delay_time = DEGRADATION_LEVEL_TWO_PAUSE
        elif new_byte_count > DEGRADATION_LEVEL_ONE:
            delay_time = DEGRADATION_LEVEL_ONE_PAUSE
        else:
            delay_time = 0.0

        if delay_time > 0.0:
            time.sleep(delay_time)


@app.route('/<path:url>')
def root(url):

    credentials, project = get_credentials()
    scoped_credentials = credentials.with_scopes(["https://www.googleapis.com/auth/cloud-platform"])
    auth_session = AuthorizedSession(scoped_credentials)

    logger.info("[STATUS] Received proxy request: {}".format(url))
    logger.info("[STATUS] Received querystring: {}".format(request.query_string))

    client_ip = request.remote_addr
    logger.info("Remote IP %s" % client_ip)

    #
    # If IP is over the daily quota, we return a 429 Too Many Requests:
    #
    byte_count = 0
    delay_time = 0.0

    todays_date = date.today()
    curr_use_per_ip = usage[client_ip] if client_ip in usage else None
    if curr_use_per_ip is not None:
        last_usage = curr_use_per_ip['day']
        byte_count = curr_use_per_ip['bytes']
        if last_usage != todays_date:
            byte_count = 0

        if byte_count > MAX_PER_IP_PER_DAY:
            logger.info("Current byte count for IP exceeds daily threshold".format(byte_count))
            return Response(status=429)

        elif byte_count > DEGRADATION_LEVEL_TWO:
            delay_time = DEGRADATION_LEVEL_TWO_PAUSE
        elif byte_count > DEGRADATION_LEVEL_ONE:
            delay_time = DEGRADATION_LEVEL_ONE_PAUSE

    if (date_for_byte_count == todays_date) and (all_ip_bytes_today > MAX_TOTAL_PER_DAY):
        logger.info("Current byte count ALL IPS exceeds daily threshold".format(all_ip_bytes_today))
        return Response(status=429)

    logger.info("Current byte count for IP is: {} so delay is starting at {}".format(byte_count, delay_time))

    req_url = "{}/{}?{}".format(GOOGLE_HC_URL, url, request.query_string) \
        if request.query_string else "{}/{}".format(GOOGLE_HC_URL, url)

    logger.info("Request URL: {}".format(req_url))

    req = auth_session.get(req_url, stream=True)
    return Response(stream_with_context(counting_wrapper(req, client_ip, usage)), content_type=req.headers['content-type'])

if __name__ == '__main__':
    app.run()