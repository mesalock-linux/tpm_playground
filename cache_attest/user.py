'''
1. request attestation report
2. verify report
'''
import requests
import base64
import logging
import os

logging.basicConfig(level=logging.INFO)

def xsystem(cmd):
    logging.info("[XSYSTEM] %s", cmd)
    return os.system(cmd)


def verify_report(report, sig):
    with open('/tmp/verify_report', 'w') as f:
        f.write(report)
    with open('/tmp/verify_sig', 'wb') as f:
        f.write(base64.b64decode(sig))
    cmd = 'openssl dgst -sha256 -verify ttp/pubkey.pem -signature /tmp/verify_sig /tmp/verify_report'
    return xsystem(cmd)


def main():
    # get nonce
    r = requests.get("http://127.0.0.1:5002/attestation_report")
    res = verify_report(r.json()["report"], r.json()["signature"])
    print('verify return', res)

if __name__ == '__main__':
    main()