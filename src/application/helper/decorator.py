from functools import wraps
from flask import jsonify, request, g
from flask import current_app as app
from . import tools

def jwt_required_custom(fn):
    '''
    Middleware JWT required
    '''
    @wraps(fn)
    def wrapper(*args, **kwargs):
        headers = request.headers
        if ("X-Auth" in headers) and len(headers['X-Auth'])>0 :
            url = app.config['URL_AUTHORIZER_JWT']
            dextra = {"http_method":"POST", "headers": {'Content-Type':'application/json',
                "X-Auth": headers["X-Auth"]}}
            check_result = tools.call_endpoint(url, {}, **dextra)
            if check_result["status_code"] != 200:
                message = check_result['resp_json']['msg'] if 'msg' in check_result['resp_json'] else check_result['resp_json']['message']
                return jsonify({'code': 401, 'message': message}), 401
            return fn(*args, **kwargs)
        else:
            return jsonify({'code': 401, 'message': 'Unauthorized'}), 401
    return wrapper


def jwt_optional_custom(fn):
    '''
    Middleware JWT optional
    '''
    @wraps(fn)
    def wrapper(*args, **kwargs):
        headers = request.headers
        if ("X-Auth" in headers) and len(headers['X-Auth'])>0 :
            url = app.config['URL_AUTHORIZER_JWT']
            dextra = {"http_method":"POST", "headers": {'Content-Type':'application/json',
                "X-Auth": headers["X-Auth"]}}
            check_result = tools.call_endpoint(url, {}, **dextra)
            if check_result["status_code"] != 200:
                message = check_result['resp_json']['msg'] if 'msg' in check_result['resp_json'] else check_result['resp_json']['message']
                return jsonify({'code': 401, 'message': message}), 401
        return fn(*args, **kwargs)
    return wrapper


def fresh_jwt_required_custom(fn):
    '''
    Middleware JWT required
    '''
    @wraps(fn)
    def wrapper(*args, **kwargs):
        headers = request.headers
        if ("X-Refresh-Auth" in headers) and len(headers['X-Refresh-Auth'])>0 :
            url = app.config['URL_AUTHORIZER_REFRESH_JWT']
            dextra = {"http_method":"POST", "headers": {'Content-Type':'application/json',
                "X-Auth": headers["X-Refresh-Auth"]}}
            check_result = tools.call_endpoint(url, {}, **dextra)
            if check_result["status_code"] != 200:
                message = check_result['resp_json']['msg'] if 'msg' in check_result['resp_json'] else check_result['resp_json']['message']
                return jsonify({'code': 401, 'message': message}), 401
            g.decorator_new_jwt = check_result["resp_headers"]["X-Auth"]
            return fn(*args, **kwargs)
        else:
            return jsonify({'code': 401, 'message': 'Unauthorized'}), 401
    return wrapper

