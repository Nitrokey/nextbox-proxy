"""
Token server to handle the NextBox backwards proxy.

The following steps have to be done on the client side to realize this:
* `register` with the proxy server using:
  * `token`, `subdomain`
* use received port to write a client rtun.yaml

* the client can now connect to the proxy-server and the nextbox instance shall be
  available using `subdomain.nextbox.link`

The server has to set up different components in order to realize this concept.

* Maintain a config for each proxied NextBox within nginx-sites-path (available + enabled)
  * file template: proxy-<subdomain>-<port>

* Maintain rtun.yaml with agents' 'auth_key' being the token + assigned port for token


"""

import os
import sys
import re
from pathlib import Path
from functools import wraps
import signal
import time
import yaml
import shutil
import socket
import urllib.request, urllib.error
import ssl
import json
import logging
import logging.handlers

from filelock import FileLock

from flask import Flask, render_template, request, flash, redirect, Response, \
    url_for, send_file, Blueprint, render_template, jsonify, make_response


REGISTER_PARAMS = ["token", "subdomain", "scheme"]
LOG_FILENAME = "/srv/nextbox-proxy/token-server.log"
LOGGER_NAME = "token-server"
MAX_LOG_SIZE = 2**20

SUBDOMAIN_CONFIGS_PATH = "/srv/nextbox-proxy/sites"
SUBDOMAIN_CONFIG_FN_TMPL = "proxy.{subdomain}.{port}"
SUBDOMAIN_CONFIG_TMPL = "/srv/nextbox-proxy/nginx-proxy.tmpl"

SUBDOMAIN_PAT = re.compile("^[a-zA-Z0-9\-]*$")

INITIAL_PORT = 14799

TOKEN_PATH = "/srv/nextbox-proxy/nextcloud-proxy.tokens"

RTUN_CONF_PATH = "/srv/nextbox-proxy/rtun.yaml"
rtun_lock = FileLock(RTUN_CONF_PATH + ".lock", timeout=10)


with open(TOKEN_PATH) as fd:
    ALLOWED_TOKENS = [tok.strip() for tok in fd.readlines()]

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

def reload_services(tunnel=False):
    os.system("sudo /bin/systemctl reload nginx.service")
    if tunnel:
        os.system("sudo /bin/systemctl restart reverse-tunnel.service")


@app.route("/register", methods=["POST"])
def register():
    """
    register new `subdomain` using `token`
    """
    data = {}
    restart_tunnel_server = False

    # check for unknown parameter
    for key in request.json:
        val = request.json.get(key)
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

    # validate subdomain
    if not SUBDOMAIN_PAT.match(data["subdomain"]):
        msg = "invalid subdomain provided"
        log.error(msg)
        return error(msg)

    # validate scheme
    if not data["scheme"] in ["http", "https"]:
        msg = f"invalid scheme provided: {data['scheme']}"
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
        toks = fn.as_posix().split(".")
        if len(toks) == 3 and toks[0].endswith("proxy"):
            _, subdomain, port = toks

            # hard delete any evil entries!
            if subdomain in subdomain2port or int(port) in port2subdomain:
                fn.unlink()
                reload_services()
                log.warning("found double entry (port or subdomain) - deleted!")
                continue

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
    if existing_domain is not None and existing_domain != data["subdomain"]:
        del_data = {"subdomain": existing_domain, "port": my_port}
        del_fn = SUBDOMAIN_CONFIG_FN_TMPL.format(**del_data)
        p = Path(SUBDOMAIN_CONFIGS_PATH) / del_fn
        p.unlink()
        log.info(f"port already assigned to other subdomain, deleted...")

    # read rtun.yaml config
    with rtun_lock:
        with open(RTUN_CONF_PATH) as fd:
            rtun_conf = yaml.load(fd)
    # check if config contains auth_key already (token), add if needed
    rtun_tokens = set(agent["auth_key"] for agent in rtun_conf["agents"])
    if data["token"] not in rtun_tokens:
        rtun_conf["agents"].append({
            "auth_key": data["token"],
            "ports": [f"{my_port}/tcp"],
        })
        # and write to .yaml if updated
        with rtun_lock:
            with open(RTUN_CONF_PATH, "w") as fd:
                yaml.dump(rtun_conf, fd)
        restart_tunnel_server = True

    # write nginx proxy-config file
    with open(SUBDOMAIN_CONFIG_TMPL) as fd:
        nginx_contents = fd.read() \
          .replace("%%REMOTE_PORT%%", str(my_port)) \
          .replace("%%SUBDOMAIN%%", data["subdomain"]) \
          .replace("%%REMOTE_SCHEME%%", data["scheme"])

    nginx_fn = SUBDOMAIN_CONFIG_FN_TMPL.format(port=my_port, subdomain=data["subdomain"])
    conf_path = Path(SUBDOMAIN_CONFIGS_PATH) / nginx_fn
    with conf_path.open("w") as fd:
        fd.write(nginx_contents)

    reload_services(restart_tunnel_server)

    return success(data={"port": my_port, "subdomain": data["subdomain"], "scheme": data["scheme"]})


if __name__ == "__main__":
    app.run("127.0.0.1", 8080)

