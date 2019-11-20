import requests
import logging
import os
import struct
import binascii
import hashlib
import subprocess
import base64
import json

logging.basicConfig(level=logging.DEBUG)
CONTEXT_AK='/root/ak.ctx'
AK_PUB_PEM='/root/akpub.pem'
os.environ['TPM2TOOLS_TCTI'] = 'tabrmd:bus_name=com.intel.tss2.Tabrmd'

def in_docker():
    with open('/proc/1/cgroup') as f:
        return 'docker' in f.read()

# if in docker, ima is not available, so use mock imalog for testing
def get_imalog_path():
    if in_docker():
        return '/root/mock_ascii_runtime_measurements'
    else:
        return '/sys/kernel/security/ima/ascii_runtime_measurements'

IMALOG_PATH = get_imalog_path()

def xsystem(cmd):
    logging.info("[XSYSTEM] %s", cmd)
    return os.system(cmd)

def quote(nonce='1234', quote_path='/tmp/quote.out', sig_path='/tmp/quotesig.out', akpass='akpass'):
    cmd = 'tpm2_quote -c {CONTEXT_AK} -l sha1:10 -q {nonce} -m {quote_path} -s {sig_path} -o /tmp/quotepcr.out -g sha256 -p {akpass}'.format(
        CONTEXT_AK=CONTEXT_AK, nonce=nonce, quote_path=quote_path, sig_path=sig_path, akpass=akpass)
    return xsystem(cmd)

def get_quote_sig(nonce):
    QUOTE_PATH='/tmp/quote.out'
    SIG_PATH='/tmp/quotesig.out'
    quote(nonce=nonce, quote_path=QUOTE_PATH, sig_path=SIG_PATH)
    
    quote_bytes = None
    sig_bytes = None
    with open(QUOTE_PATH, 'rb') as f:
        quote_bytes = f.read()
    with open(SIG_PATH, 'rb') as f:
        sig_bytes = f.read()
    return quote_bytes, sig_bytes

def get_imalog_str():
    with open(IMALOG_PATH) as f:
        return f.read()

# def get_report_params(nonce):
#     # prepare params
#     bquote, bsig = get_quote_sig(nonce)
#     params = {
#         "nonce": nonce,
#         "ima_log": get_imalog_str(),
#         "quote": base64.b64encode(bquote),
#         "sig": base64.b64encode(bsig)
#     }
#     return params

def get_report_params(nonce):
    # prepare params
    bquote, bsig = get_quote_sig(nonce)
    files = {
        'ima_log': open(IMALOG_PATH, 'rb'),
        'quote': open('/tmp/quote.out', 'rb'),
        'ak_pub_pem': open(AK_PUB_PEM, 'rb'),
        'sig': open('/tmp/quotesig.out', 'rb'),
        'pcr': open('/tmp/quotepcr.out', 'rb')}
    data = {'nonce': nonce}
    ret = {
        "files": files,
        "data": data
    }
    return ret

def main():
    # get nonce
    r = requests.get("http://localhost:5001/get_nonce")
    nonce = r.json()["nonce"]
    logging.debug('nonce %s', nonce)

    r = requests.post("http://localhost:5001/gen_report", **get_report_params(nonce))
    logging.debug("report: %s", r.text)
    # with open('/tmp/attestation_report', 'w') as f:
    #     json.dump(f)
    with open('/tmp/attestation_report', 'w') as f:
        f.write(r.text)

if __name__ == '__main__':
    main()