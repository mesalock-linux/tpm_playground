#!/bin/bash
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

pgrep tpm_server > /dev/null || tpm_server &
mkdir -p /var/run/dbus
pgrep dbus-daemon > /dev/null || (rm -f /var/run/dbus/pid && dbus-daemon --config-file=/usr/share/dbus-1/system.conf --print-address)
pgrep tpm2-abrmd > /dev/null || tpm2-abrmd --allow-root --tcti=mssim:port=2321 --dbus-name=com.intel.tss2.Tabrmd -f &
sleep 1
