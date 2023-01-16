"""Initialize app."""
from flask import Flask, jsonify, make_response, request, g
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm.exc import NoResultFound
from multiprocessing import Process, current_process
from .helper import tools

from flask_cors import CORS
from os import path, mkdir
import logging
import traceback
import time
import json
from time import strftime
from datetime import datetime
from config import app_config, DEFAULT_ENV

db = SQLAlchemy()


def async_monitor_tracer(_logname, _loglevel, _payload):
    # Task queue monitor tracer
    try:
        pcs_name = current_process().name
        pcs_id = current_process().pid
        # print("async_monitor_tracer", pcs_name, pcs_id, "starting")

        _url_notification = current_app.config['MONITOR_TASKS_TRACER']
        _pl_notification = {"event": "cluster_process_microservice_tracer",
                            "payload": {"log_name": _logname, "level": _loglevel, "payload": _payload}}
        r = tools.call_endpoint(_url_notification, _pl_notification)

        # print("async_monitor_tracer", pcs_name, pcs_id, "ending", r['tlapse'])
    except Exception as e:
        print("Oops! async_monitor_tracer ", e.__class__, "occurred.")
        message = [str(x) for x in e.args]
        print(message)


def register_handler_exceptions(app):
    @app.before_request
    def start_timer():
        g.start = time.time()
        g.exclude_log = {}
        g.log_correlationid = 'guest'
        g.request_id = ''

    @app.after_request
    def log_request(response):
        "Log HTTP request details"

        if (
            request.path == "/favicon.ico"
            or request.path.startswith("/static")
            or request.path.startswith("/admin/static")
        ):
            return response
        g.request_id = request.headers.get(
            "X-Request-Id", "") if 'X-Request-Id' in request.headers else (tools.get_uuid() if g.request_id == "" else g.request_id)
        g.log_correlationid = request.headers.get(
            "X-Correlation", "") if 'X-Correlation' in request.headers else (tools.get_uuid() if g.log_correlationid == "" else g.log_correlationid)
        now = time.time()
        duration = round(now - g.start, 6)  # to the microsecond
        ip_address = request.headers.get(
            "X-Forwarded-For", request.remote_addr)
        method = request.method
        host = request.host.split(":", 1)[0]
        params = dict(request.args)
        json_params = request.get_json() if request.get_json() is not None else ''

        if len(g.exclude_log):
            exclude = g.exclude_log

            if request.path in exclude["route"]:
                if len(exclude["attr_exclude"]) > 0:
                    for field in exclude["attr_exclude"]:
                        del json_params[field]

        endpoint_result = response.get_json()
        custom_response = {
            "code": endpoint_result['code'],
            "message": endpoint_result['message']
        }

        rsp_status_code = response.status_code
        log_level = "INFO" if rsp_status_code == 200 else (
            "WARNING" if rsp_status_code in [400, 401, 404, 405] else "ERROR")

        log_name = "tracer-microservice-tokenizer"
        klog = {
            "log_name": log_name,
            "level": log_level,
            "service": {
                "type": "microservice",
                "group": "tokenizer",
                "cluster": "cluster-process"
            },
            "correlation_id": g.log_correlationid,
            "request_id": g.request_id,
            "headers": dict(request.headers),
            "request": {
                "method": method,
                "function": request.endpoint,
                "path": request.path,
                "ip": ip_address,
                "host": host,
                "uri_params": params,
                "json_params": json_params,
                "user_agent": str(request.user_agent)
            },
            "tlapse": duration,
            "response": {
                "status": rsp_status_code,
                "result": custom_response,
                "content_length": response.content_length,
                "referrer": request.referrer
            },
            "created_at": tools.current_utc().isoformat()
        }

        # task monitor async
        log_tracer = Process(  # Create a daemonic process with heavy "my_func"
            name="tokenizer_log_tracer",
            target=async_monitor_tracer,
            args=(
                log_name, log_level, klog,),
            daemon=True
        )
        log_tracer.start()

        return response

    @app.errorhandler(404)
    def page_not_found(error):
        message = [str(x) for x in error.args]
        return make_response(jsonify({'code': 404, 'message': "Ups not found!!"}), 404)

    @app.errorhandler(405)
    def method_not_allowed(error):
        message = [str(x) for x in error.args]
        return make_response(jsonify({'code': 405, 'message': "Method not allowed"}), 405)

    @app.errorhandler(500)
    def server_error(e):
        message = [str(x) for x in e.args]
        app.logger.error(message)
        return make_response(jsonify({'code': 500, 'message': "An internal error occurred. " + str(e.code)}), 500)

    @app.errorhandler(Exception)
    def exceptions(e):
        """ Logging after every Exception. """
        message = [str(x) for x in e.args]
        app.logger.error(message)
        ts = strftime('[%Y-%b-%d %H:%M]')
        tb = traceback.format_exc()
        return make_response(
            jsonify({'code': 500, 'message': "An internal error occurred."}), 500)


def create_app():
    """Construct the core application."""
    app = Flask(__name__, instance_relative_config=False)
    cors = CORS(app)  # codigo para aceptar CORS
    app.config['CORS_HEADERS'] = "Content-Type"  # codigo para aceptar CORS

    # Application Configuration
    app.config.from_object(app_config[DEFAULT_ENV])

    db.init_app(app)
    register_handler_exceptions(app)

    # Registro de los Blueprints
    from .keys import keys_bp

    app.register_blueprint(keys_bp)

    return app
