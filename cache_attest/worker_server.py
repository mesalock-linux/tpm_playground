from flask import Flask, escape, request
from flask import jsonify
import secrets
import base64
import os
import logging
import hashlib
import binascii
import time
import json

logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)

REPORT_CACHE = None

def xsystem(cmd):
    logging.info("[XSYSTEM] %s", cmd)
    return os.system(cmd)

@app.route('/')
def hello():
    return "this is worker_server!"

@app.route('/attestation_report')
def attestation_report():
    global REPORT_CACHE
    # verify report
    if REPORT_CACHE is None or REPORT_CACHE:
        # TODO: file lock
        xsystem('sudo python3 worker_client.py')
        with open('/tmp/attestation_report') as f:
            REPORT_CACHE = json.load(f)
    return jsonify(REPORT_CACHE)
