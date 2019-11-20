# -*- coding: utf-8 -*-
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

KNOWN_GOOD_DATABASE = {
    "boot_aggregate": "49ca2880a26af32886ecebc040c56393a7ae94d5",
    "/init": "f89d73ddf9c1ee2a829fa84d9b3ccad4416fe346",
    "/bin/sha1": "8445cb38b1f299117aee34c943ab20b3089b84a1",
}

logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)

UPLOAD_DIR = '/tmp/ttp_upload'

def xsystem(cmd):
    logging.info("[XSYSTEM] %s", cmd)
    return os.system(cmd)

@app.route('/')
def hello():
    # name = request.args.get("name", "World")
    # return f'Hello, {escape(name)}!'
    return "this is ttp!"

@app.route('/get_nonce')
def get_nonce():
    NONCE_SIZE=20
    nonce = secrets.token_bytes(NONCE_SIZE)
    ret = { "nonce": binascii.hexlify(nonce).decode('utf8') }
    return jsonify(ret)


def checkquote(nonce, quote_path, sig_path, pcr_path, ak_pub_pem_path):
    cmd = 'tpm2_checkquote -u {ak_pub_pem_path} -m {quote_path} -s {sig_path} -f {pcr_path} -g sha256 -q {nonce}'.format(
        ak_pub_pem_path=ak_pub_pem_path, nonce=nonce, quote_path=quote_path, sig_path=sig_path, pcr_path=pcr_path
    )
    if 0 != xsystem(cmd):
        return "failed to check quote"
    # return None on success

def extend(x, y):
    m = hashlib.sha1()
    m.update(x)
    m.update(y)
    return m.digest()

def verify_linkability(quote_path, ima_log_path):
    cur = b'\x00' * 20
    with open(quote_path, 'rb') as f:
        quote_content = f.read()
    with open(ima_log_path) as f:
        for line in f:
            items = line.strip().split(' ')
            entry_hash = items[1]
            entry_hash_b = binascii.unhexlify(entry_hash)
            fhash = items[3].replace('sha1:', '')
            fpath = items[4]
            if fpath not in KNOWN_GOOD_DATABASE or KNOWN_GOOD_DATABASE[fpath] != fhash.lower():
                logging.warning('Unknown image:', fpath, fhash)
                return "image not in known good database"
            cur = extend(cur, entry_hash_b)
    m_quote = hashlib.sha256()
    m_quote.update(cur)

    # print('quote_content', binascii.hexlify(quote_content))
    # print('hash256_of_pcr10', m_quote.hexdigest())

    if not quote_content.endswith(m_quote.digest()):
        return "quote doesn't match with ima log"
    # return None on success

def sign(report):
    report_text = json.dumps(report, indent=4)# ""
    # for key in sorted(report.keys()):
    #     report_text += key + ": " + report[key] + "\n"
    with open("/tmp/report", 'w') as f:
        f.write(report_text)
    cmd = "openssl dgst -sha256 -sign ttp/privateKey.key -out /tmp/sign.sha256 /tmp/report"
    xsystem(cmd)
    return base64.b64encode(open('/tmp/sign.sha256', 'rb').read()).decode('utf8')
    # return "SIGN_UNIMPLEMENTED"

'''
{
    data: { nonce: "40len_str" },
    files: ['ima_log', 'quote', 'sig', 'ak_pub_pem', 'pcr']
}
RESPONSE
{
    report:  {
        ak_pub_pem: "",
        nonce: "",
        result: "yes",
        timestamp: "",
    },
    signature: ""
}
'''
@app.route('/gen_report', methods=['POST'])
def gen_report():
    # TODO: handle parameter errros
    # print(request.json['nonce'])
    print(request.form)
    print(request.files)
    # TODO: check if nonce is leagal as a folder name
    nonce = request.form["nonce"]
    folder = os.path.join(UPLOAD_DIR, nonce)
    xsystem('mkdir -p ' + folder)
    
    ima_log_path = os.path.join(folder, 'ima_log')
    ak_pub_pem_path = os.path.join(folder, 'ak_pub_pem')
    quote_path = os.path.join(folder, 'quote')
    sig_path = os.path.join(folder, 'sig')
    pcr_path = os.path.join(folder, 'pcr')
    # ctx_ak_path = 
    request.files['ima_log'].save(ima_log_path)
    # request.files['ctx_ak'].save(os.path.join(folder, 'ctx_ak'))
    request.files['ak_pub_pem'].save(ak_pub_pem_path)
    request.files['quote'].save(quote_path)
    request.files['sig'].save(sig_path)
    request.files['pcr'].save(pcr_path)
    # print('nonce:', request.json['nonce'])
    # print('ima_log', request.json['ima_log'][:50])
    # print('quote', request.json['quote'])
    # print('sig', request.json['sig'])

    fail_reason = checkquote(nonce=nonce, quote_path=quote_path, sig_path=sig_path, pcr_path=pcr_path, ak_pub_pem_path=ak_pub_pem_path)
    if fail_reason:
        return jsonify({"status": "failure", "reason": fail_reason})
    fail_reason = verify_linkability(ima_log_path=ima_log_path, quote_path=quote_path)
    if fail_reason:
        return jsonify({"status": "failure", "reason": fail_reason})

    report = {
        "ak_pub_pem": open(ak_pub_pem_path).read(),
        "nonce": nonce,
        "result": "yes",
        "timestamp": str(time.time())
    }

    res = {
        "status": "success",
        "report": json.dumps(report, indent=4),
        "signature": sign(report)
    }

    print(res)

    # return jsonify({"status": "success"})
    return jsonify(res)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
