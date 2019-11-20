#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import struct
import binascii
import hashlib
import subprocess

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
print('IMALOG_PATH', IMALOG_PATH)

def xsystem(cmd):
    print("[XSYSTEM]", cmd)
    return os.system(cmd)

# tpm2_quote -Q -c $context_ak -l $digestAlg:$debug_pcr_list -q $loaded_randomness -m $output_quote -s $output_quotesig -o $output_quotepcr -g $digestAlg -p "$akpw"
# tpm2_quote -c ak.ctx -l sha256:15,16,22 -q 821abe028260f44de90d436076c2c00dab0b7b06 -m quote.out -s quotesig.out -o quotepcr.out -g sha256 -p akpass


# Verify quote
# tpm2_checkquote -Q -u $output_ak_pub_pem -m $output_quote -s $output_quotesig -f $output_quotepcr -g $digestAlg -q $loaded_randomness
# tpm2_checkquote -u akpub.pem -m quote.out -s quotesig.out -f quotepcr.out -g sha256 -q 821abe028260f44de90d436076c2c00dab0b7b06

def quote(nonce='1234', quote_path='/tmp/quote.out', akpass='akpass'):
    cmd = 'tpm2_quote -c {CONTEXT_AK} -l sha1:10 -q {nonce} -m {quote_path} -s /tmp/quotesig.out -o /tmp/quotepcr.out -g sha256 -p {akpass}'.format(
        CONTEXT_AK=CONTEXT_AK, nonce=nonce, quote_path=quote_path, akpass=akpass)
    #cmd = 'tpm2_quote -c {CONTEXT_AK} -l sha256:15,16,22 -q {nonce} -m /tmp/quote.out -s /tmp/quotesig.out -o /tmp/quotepcr.out -g sha256 -p {akpass}'.format(
    #    CONTEXT_AK=CONTEXT_AK, nonce=nonce, akpass=akpass)
    return xsystem(cmd)

def checkquote(nonce='1234'):
    cmd = 'tpm2_checkquote -u {AK_PUB_PEM} -m /tmp/quote.out -s /tmp/quotesig.out -f /tmp/quotepcr.out -g sha256 -q {nonce}'.format(
        AK_PUB_PEM=AK_PUB_PEM, nonce=nonce
    )
    return xsystem(cmd)

def read_quote_content():
    with open('/tmp/quote.out', 'rb') as f:
        return f.read()

# ima log format
# {reg_num(10)} {hash} ima-ng sha1:{image_hash} {image_path}

# IMA LOG HASH COMPUTATION
# let mut pcr_hasher = Sha1::new();

# let mut hasher = Sha1::new();


# '{algo_digest_len:4_byte_binary}sha1:\0{file_hash_binval}{file_len:4_byte_binary}{file}\0'

# # algo_digest_len = len("sha1") + 2 + hash.len()/2
# algo_digest_len = len("sha1:\0{file_hash_binval})
# file_len = len("{file}\0")

# run tpm2_pcrread to get bin val of pcr10
def read_pcr10():
    output = subprocess.check_output('tpm2_pcrread sha1:10', shell=True).decode('utf8') # e.g. 'sha1:\n  10: 0x0000000000000000000000000000000000000000\n'
    hash = output.split('\n')[1]
    hash = hash[hash.find('0x')+2:]
    return binascii.unhexlify(hash)

def gen_nonce(length=20):
    cmd = 'tpm2_getrandom --hex {}'.format(length)
    output = subprocess.check_output(cmd, shell=True).decode('utf8')
    return output


def test_hash(fhash, fpath):
    # fhash = 'f89d73ddf9c1ee2a829fa84d9b3ccad4416fe346'
    # fpath = '/init'

    fhash_b = binascii.unhexlify(fhash)
    len_fhashb = len(fhash_b)
    len_hash = len('sha1:\0') + len_fhashb
    len_hash_b = struct.pack('<I', len_hash)

    fpath_b = (fpath + '\0').encode('utf8')
    len_fpath_b = struct.pack('<I', len(fpath_b))
    
    hash_content = len_hash_b + 'sha1:\0'.encode() + fhash_b + len_fpath_b + fpath_b

    m = hashlib.sha1()
    m.update(hash_content)
    final_hash = m.hexdigest()
    print(final_hash)

# 10 ae0bdba7cdf0e00655bd7d16ec203d9d66b96bb4 ima-ng sha1:f89d73ddf9c1ee2a829fa84d9b3ccad4416fe346 /init


# def verify_linkability():
#     m = hashlib.sha1()
#     # m.update(b'\x00' * 20)
#     with open('/sys/kernel/security/ima/ascii_runtime_measurements') as f:
#         for line in f:
#             items = line.strip().split(' ')
#             entry_hash = items[1]
#             entry_hash_b = binascii.unhexlify(entry_hash)
#             fhash = items[3].replace('sha1:', '')
#             fpath = items[4]
#             m.update(entry_hash_b)
#             print('intermediate_pcr_value', m.hexdigest())
#             # print(fhash, fpath)
#             # test_hash(fhash, fpath)
#     print('final_pcr_value', m.hexdigest())
#     m_quote = hashlib.sha1()
#     m_quote.update(m.digest())
#     print('hash_in_quote', m_quote.hexdigest())

def extend(x, y):
    m = hashlib.sha1()
    m.update(x)
    m.update(y)
    return m.digest()

def verify_linkability(quote_content):
    global IMALOG_PATH
    cur = b'\x00' * 20
    with open(IMALOG_PATH) as f:
        for line in f:
            items = line.strip().split(' ')
            entry_hash = items[1]
            entry_hash_b = binascii.unhexlify(entry_hash)
            fhash = items[3].replace('sha1:', '')
            fpath = items[4]
            # m.update(entry_hash_b)
            cur = extend(cur, entry_hash_b)
            # print('intermediate_pcr_value', binascii.hexlify(cur))
            # print(fhash, fpath)
            # test_hash(fhash, fpath)
    # if cur == read_pcr10():
    #     return 0
    # else:
    #     return -1
    
    # print('final_pcr_value', cur)
    m_quote = hashlib.sha256()
    m_quote.update(cur)

    # print('quote_content', binascii.hexlify(quote_content))
    # print('hash256_of_pcr10', m_quote.hexdigest())

    if quote_content.endswith(m_quote.digest()):
        return 0
    return -1
    



def main():
    # test_hash()
    # test_hash('d3a21675a8f19518d8b8f3cef0f6a21de1da6cc7', '/home/xk/repos/bnotes/mesatee/tpm/pyattestation/你好')
    NONCE = gen_nonce()
    print('NONCE:', NONCE)

    if 0 != quote(nonce=NONCE):
        print('\nfailed to get quote')
        return -1
    if 0 != checkquote(nonce=NONCE):
        print('\nfailed to check quote')
        return -1
    if 0 != verify_linkability(quote_content=read_quote_content()):
        print('\nfailed to verify linkability')
        return -1
    print('\nAttestation Success!')

if __name__ == '__main__':
    exit(main())


# 10 87c481afdd767fc58d015dae271838e64cf3dd33 ima-ng sha1:d3a21675a8f19518d8b8f3cef0f6a21de1da6cc7 