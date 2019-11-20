#!/bin/bash
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# copy everything in mock_data/ into /root
# start_tpm

setup_mock_ima_log()
{
  CONTENT='10 007cf89b280596c7fe1dfa6940f4d64e85b6c011 ima-ng sha1:49ca2880a26af32886ecebc040c56393a7ae94d5 boot_aggregate\n10 ae0bdba7cdf0e00655bd7d16ec203d9d66b96bb4 ima-ng sha1:f89d73ddf9c1ee2a829fa84d9b3ccad4416fe346 /init\n10 50e56be3a2e06b86912d5a8cc6bfc9da2048b2a4 ima-ng sha1:8445cb38b1f299117aee34c943ab20b3089b84a1 /bin/sha1\n'
  printf "${CONTENT}" > /root/mock_ascii_runtime_measurements
}

setup_tpm_pcr10()
{
  tpm2_pcrextend 10:sha1=007cf89b280596c7fe1dfa6940f4d64e85b6c011
  tpm2_pcrextend 10:sha1=ae0bdba7cdf0e00655bd7d16ec203d9d66b96bb4
  tpm2_pcrextend 10:sha1=50e56be3a2e06b86912d5a8cc6bfc9da2048b2a4
}


cd /root
start_tpm.sh
setup_mock_ima_log
setup_tpm_pcr10

# setup ek & ak
handle_ek=0x81010009
context_ak=ak.ctx
handle_nv=0x1500018
handle_hier=0x40000001
ek_alg=rsa
ak_alg=rsa
digestAlg=sha256
signAlg=rsassa
ownerpw=ownerpass
endorsepw=endorsepass
ekpw=ekpass
akpw=akpass
rand_pcr_value=6ea40aa7267bb71251c1de1c3605a3df759b86b22fa9f62aa298d4197cd88a38
debug_pcr=16
debug_pcr_list=15,16,22

file_input_data=secret.data
file_input_key=nv.data
output_ek_pub_pem=ekpub.pem
output_ek_pub=ek.pub
output_ak_pub_pem=akpub.pem
output_ak_pub=ak.pub
output_ak_pub_name=ak.name
output_mkcredential=mkcred.out
output_actcredential=actcred.out
output_quote=quote.out
output_quotesig=quotesig.out
output_quotepcr=quotepcr.out

tpm2_clear
tpm2_changeauth -c o "$ownerpw"
tpm2_changeauth -c e "$endorsepw"

tpm2_createek -Q -c $handle_ek -G $ek_alg -u $output_ek_pub_pem -f pem -p "$ekpw" -w "$ownerpw" -P "$endorsepw"
tpm2_readpublic -Q -c $handle_ek -o $output_ek_pub

tpm2_createak -Q -C $handle_ek -c $context_ak -G $ak_alg -g $digestAlg\
  -s $signAlg -u $output_ak_pub_pem -f pem -n $output_ak_pub_name -p "$akpw"\
  -P "$endorsepw"
tpm2_readpublic -Q -c $context_ak -o $output_ak_pub

# clean files unused in testing
rm -f $output_ek_pub_pem $output_ak_pub $output_ek_pub $output_ak_pub_name
