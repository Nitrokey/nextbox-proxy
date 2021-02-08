import os
import sys
import re
from pathlib import Path
from functools import wraps
import signal

import shutil
import socket
import urllib.request, urllib.error
import ssl
import json
import logging

from flask import Flask, render_template, request, flash, redirect, Response, \
    url_for, send_file, Blueprint, render_template, jsonify, make_response


REGISTER_PARAMS = ["token", "subdomain", "public_key"]
LOG_FILENAME = "/var/logs/token-server.log"
LOGGER_NAME = "token-server"
MAX_LOG_SIZE = 2**20

SUBDOMAIN_CONFIGS_PATH = "/etc/nginx/available-sites"
SUBDOMAIN_CONFIGS_ENABLED_PATH = "/etc/nginx/enabled-sites"
SUBDOMAIN_CONFIG_FN_TMPL = "proxy-{subdomain}-{port}"

INITIAL_PORT = 14792

ALLOWED_TOKENS = [
  "12345678900000000001",
  "12345678900000000002",
  "12345678900000000003",
  "12345678900000000004",
]


app = Flask(__name__)
app.secret_key = "123456-nextbox-proxy-123456"


# logger setup
log = logging.getLogger(LOGGER_NAME)
log.setLevel(logging.DEBUG)
log_handler = logging.handlers.RotatingFileHandler(
        LOG_FILENAME, maxBytes=MAX_LOG_SIZE, backupCount=5)
log.addHandler(log_handler)
log_format = logging.Formatter("{asctime} {module} {levelname} => {message}", style='{')
log_handler.setFormatter(log_format)

log.info("starting token-server")


def error(msg, data=None):
    msg = [msg]
    return jsonify({
        "result": "error",
        "msg": msg,
        "data": data
    })


def success(msg=None, data=None):
    msg = [msg] if msg else []
    return jsonify({
        "result": "success",
        "msg": msg,
        "data": data
    })


@app.route("/register", methods=["POST"])
@requires_auth
def register():
    """
    register new `subdomain` using `token` auth with `public_key`
    """
    data = {}
    restart_nginx = False

    # unknown parameter found
    for key in request.form:
        val = request.form.get(key)
        if key not in REGISTER_PARAMS:
            msg = "unknown parameter"
            log.error(msg)
            return error(msg)
        data[key] = val

    # check for all parameters
    if not(all(key in data for key in REGISTER_PARAMS)):
        msg = "not all parameters provided"
        log.error(msg)
        return error(msg)

    # determine port for token
    try:
        token_idx = ALLOWED_TOKENS.index(data["token"])
    except ValueError:
        msg = "invalid token"
        log.error(msg)
        return error(msg)

    # this is the port we are targetting (associated with token)
    my_port = INITIAL_PORT + token_idx

    # create mappings for subdomains/ports
    port2subdomain = {}
    subdomain2port = {}
    for fn in Path(SUBDOMAIN_CONFIGS_PATH).iterdir():
        toks = fn.split("-")
        if len(toks) == 3 and toks[0] == "proxy":
            _, subdomain, port = toks
            port2subdomain[int(port)] = subdomain
            subdomain2port[subdomain] = int(port)

    # subdomain exist (but other port, thus not available)
    existing_port = subdomain2port.get(data["subdomain"])
    if existing_port is not None and existing_port != my_port:
        msg = f"subdomain already registered: {data['subdomain']}"
        log.error(msg)
        return error(msg)

    # port exists, but subdomain differs: delete subdomain
    existing_domain = port2subdomain.get(my_port)
    if existing_domain != data["subdomain"]:
        del_data = {"subdomain": existing_domain, "port": my_port}
        del_fn = SUBDOMAIN_CONFIG_FN_TMPL.format(**del_data)
        p1 = Path(SUBDOMAINS_CONFIG_PATH) / del_fn
        p2 = Path(SUBDOMAIN_CONFIGS_ENABLED_PATH) / del_fn
        p1.unlink()
        p2.unlink()
        # @todo: remove public key from authorized keys...



    # @todo: can we validate the public key ????

    # ok, from here on we are ready to do all the stuff needed:
    # -> create proxy-<domain>-<port> inside /etc/nginx-available-sites
    # -> create link to available sites
    # -> add public key to authorized keys (maybe also add it as comment to proxy-<dom>-<port> file)
    #    -> include restricted stuff for tunneling only ...
    # -> restart nginx




    with open("nginx-proxy.tmpl") as fd:
        tmpl = fd.read()



    # return json with: port, proxy-server-ip(?)





