"""
Token server to handle the NextBox backwards proxy.

Access to a remote NextBox is realized by an backwards-ssh-tunnel, which is initiated
using `ssh` from the client side, like this:
```
ssh -o StrictHostKeyChecking=accept-new -p {ssh_port} -f -N -i {key_path} -R {remote_port}:localhost:{local_port} {user}@{host}
```

The following steps have to be done on the client side to realize this:
* create a asymmetric key pair using ssh-keygen
  * `ssh-keygen -b 4096 -t rsa -f /path/to/sshkey -q -N ""`
* `register` with the proxy server using:
  * `token`, `subdomain` and the contents of /path/to/sshkey.pub (`public_key`)
* the client can now connect to the proxy-server and the nextbox instance shall be
  available using `subdomain.nextbox.link`

The server has to set up different components in order to realize this concept.

* Maintain public-keys inside `authorized_keys` with all registered users
  * line template: "ssh-rsa <public-key len:544> <token>@nextbox <@TODO: correct addition for tunneling only>"
  * don't keep subdomain here, thus changing the subdomain does not require changing `authorized_keys`

* Maintain a config for each proxied NextBox within nginx-sites-path (available + enabled)
  * file template: proxy-<subdomain>-<port>


"""

import os
import sys
import re
from pathlib import Path
from functools import wraps
import signal
import time

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


REGISTER_PARAMS = ["token", "subdomain", "public_key"]
LOG_FILENAME = "/srv/nextbox-proxy/token-server.log"
LOGGER_NAME = "token-server"
MAX_LOG_SIZE = 2**20

SUBDOMAIN_CONFIGS_PATH = "/srv/nextbox-proxy/sites"
SUBDOMAIN_CONFIG_FN_TMPL = "proxy-{subdomain}-{port}"
SUBDOMAIN_CONFIG_TMPL = "/srv/nextbox-proxy/nginx-proxy.tmpl"

SUBDOMAIN_PAT = re.compile("^[a-zA-Z0-9\-]*$")

AUTH_KEYS = (Path(os.environ["HOME"]) / ".ssh" / "authorized_keys").as_posix()
AUTH_KEYS_LOCK = (Path(os.environ["HOME"]) / ".ssh" / "authorized_keys.lock").as_posix()
AUTH_LINE_TMPL = "ssh-rsa {public_key} {token}@nextbox\n"

auth_lock = FileLock(AUTH_KEYS_LOCK, timeout=10)

INITIAL_PORT = 14799

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
def register():
    """
    register new `subdomain` using `token` auth with `public_key`
    """
    data = {}
    restart_nginx = False

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

    # validate public key
    if not data["public_key"].startswith("AAAAB") or len(data["public_key"]) != 716:
        msg = "invalid public key provided"
        log.error(msg)
        return error(msg)

    # validate subdomain
    if not SUBDOMAIN_PAT.match(data["subdomain"]):
        msg = "invalid subdomain provided"
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
    if existing_domain is not None and existing_domain != data["subdomain"]:
        del_data = {"subdomain": existing_domain, "port": my_port}
        del_fn = SUBDOMAIN_CONFIG_FN_TMPL.format(**del_data)
        p = Path(SUBDOMAIN_CONFIGS_PATH) / del_fn
        p.unlink()

    # search public key in `keys`, either:
    # * add it: new token
    # * replace it token and pub-key don't match
    # * do nothing: token and pub-key combination found
    buf = ""
    auth_line = "ssh-rsa"
    changed = False
    found = False
    with auth_lock:
        with open(AUTH_KEYS) as fd:
            for line in fd:
                if data["token"] in line:
                    if data["public_key"] in line:
                        buf += line
                        found = True
                    else:
                        buf += AUTH_LINE_TMPL.format(**data)
                        changed = True
                else:
                    buf += line
        # to add, just append
        if not found and not changed:
            with open(AUTH_KEYS, "a") as fd:
                fd.write(AUTH_LINE_TMPL.format(**data))
        # if changed, re-write file using buf (without old line) adding new line
        if changed:
            buf += AUTH_LINE_TMPL.format(**data)
            with open(AUTH_KEYS, "w") as fd:
                fd.write(buf)

    # write nginx proxy-config file
    with open(SUBDOMAIN_CONFIG_TMPL) as fd:
        nginx_contents = fd.read() \
          .replace("%%REMOTE_PORT%%", str(my_port)) \
          .replace("%%SUBDOMAIN%%", data["subdomain"])
    nginx_fn = SUBDOMAIN_CONFIG_FN_TMPL.format(port=my_port, subdomain=data["subdomain"])
    conf_path = Path(SUBDOMAIN_CONFIGS_PATH) / nginx_fn
    with conf_path.open("w") as fd:
        fd.write(nginx_contents)

    # reload nginx (what happens on error?)
    os.system("systemctl reload nginx")

    return success(data={"port": my_port, "subdomain": data["subdomain"]})


if __name__ == "__main__":
    app.run("0.0.0.0", 8080)

