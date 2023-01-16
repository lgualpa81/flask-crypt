import re
import requests
import time
import base64
import json, uuid
import string
import random
from datetime import datetime, timedelta


def call_endpoint(_url, _kdata={}, **dict_extra):
    # requests_toolbelt.adapters.appengine.monkeypatch()
    http_method = 'POST' if not 'http_method' in dict_extra else str(
        dict_extra['http_method'])
    timeout_seconds = 60 if not 'timeout' in dict_extra else int(
        dict_extra['timeout'])
    headers = dict_extra['headers'] if 'headers' in dict_extra else {
        'Content-Type': 'application/json'}
    ssl_on = True if 'ssl_on' not in dict_extra else dict_extra["ssl_on"]

    resp = requests.request(
        http_method, url=_url, json=_kdata, timeout=timeout_seconds, headers=headers, verify=ssl_on)
    total_seconds = resp.elapsed.total_seconds()

    return {"req_headers": resp.request.headers, "resp_headers": resp.headers,
            "resp_text": resp.text, "resp_json": resp.json(), "status_code": resp.status_code, "tlapse": total_seconds}


def filter_string(str):
    return re.sub(r"[^a-zA-Z0-9]+", '', str.strip())


def encode_b64(s):
    if isinstance(s, dict):
        s = json.dumps(s)
    return base64.b64encode(s.encode()).decode()


def decode_b64(s):
    return base64.b64decode(s).decode()


def current_utc():
    return datetime.utcnow()


def dayofyear():
    today_utc = datetime.utcnow()
    day_of_year = (today_utc - datetime(today_utc.year, 1, 1)).days + 1
    return day_of_year


def daily_parity():
    return ((datetime.utcnow().year+dayofyear()) % 2)


def is_json(json_data):
    try:
        json.loads(json_data)
    except ValueError as err:
        return False
    return True


def check_integer_list(mylist):
    # https://stackoverflow.com/questions/13252333/python-check-if-all-elements-of-a-list-are-the-same-type
    return all(isinstance(x, int) for x in mylist)


def generate_ticket_number(tag=""):
    return tag + time.strftime("%y%m%d%H%M%S") + str(datetime.utcnow().strftime("%f"))[-6:]


def future_utc(f, d):
    frequencies = {"h": "hours", "d": "days", "m": "minutes"}
    kargs = {frequencies[f]: d}
    return datetime.utcnow() + timedelta(**kargs)


def random_string(self, length=10):
    """Generate a random string with the combination of lowercase and uppercase letters """

    alpha_num = string.ascii_letters + string.digits
    return ''.join(random.choice(alpha_num) for i in range(length))


def file_get_contents(filename):
    with open(filename) as f:
        return f.read()

def get_uuid():
    return str(uuid.uuid4())