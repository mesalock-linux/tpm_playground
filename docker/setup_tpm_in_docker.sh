#!/bin/bash

IBMTPM=ibmtpm1332
TPM2_TOOLS_REV=af53407dec18b6f46646ed40b94f97cb240c2f43
TPM2_TSS_REV=1d4a956e27dfe135239d5489c5a82af02d0d9dcf
TPM2_ABRMD_REV=ac2a5a4b5a4e548177ed7a5b74cea23e00fd30b4
ROOT_DIR=$HOME 

# install deps
sudo apt-get update
sudo apt-get -y install curl libglib2.0-dev libdbus-1-dev libgcrypt20-dev \
  autoconf-archive \
  libcmocka0 \
  libcmocka-dev \
  procps \
  iproute2 \
  build-essential \
  git \
  pkg-config \
  gcc \
  libtool \
  automake \
  libssl-dev \
  uthash-dev \
  autoconf \
  doxygen \
  libltdl-dev \
  dbus-x11 \
  libcurl4-gnutls-dev

python -m pip install pyyaml

sudo useradd --system --user-group tss

# install TSS itself
cd $ROOT_DIR
git clone https://github.com/tpm2-software/tpm2-tss.git
cd tpm2-tss
git checkout $TPM2_TSS_REV
./bootstrap
./configure
make
sudo make install
sudo ldconfig

cd $ROOT_DIR

# Install abrmd itself
git clone https://github.com/tpm2-software/tpm2-abrmd.git
cd tpm2-abrmd
git checkout $TPM2_ABRMD_REV
./bootstrap
# ./configure --enable-unit --with-dbuspolicydir=/etc/dbus-1/system.d # --enable-integration
sudo mkdir -p /usr/share/dbus-1/system.d && ./configure --with-dbuspolicydir=/etc/dbus-1/system.d
# dbus-launch make
make
sudo make install

cd $ROOT_DIR

wget https://downloads.sourceforge.net/project/ibmswtpm2/${IBMTPM}.tar.gz
mkdir ${IBMTPM}
cd ${IBMTPM}
tar -xavf ../${IBMTPM}.tar.gz
cd src
make
sudo cp tpm_server /usr/local/bin

cd $ROOT_DIR

# Install tools itself
git clone https://github.com/tpm2-software/tpm2-tools.git
cd tpm2-tools
git checkout $TPM2_TOOLS_REV
./bootstrap
./configure
# ./configure --disable-hardening --with-tcti-socket --with-tcti-device && make
make
sudo make install
sudo ldconfig
cp test/integration/helpers.sh $HOME
sed -i 's/^trap /#trap /g' $HOME/helpers.sh
 
cd $ROOT_DIR

# install rust
# curl https://sh.rustup.rs -sSf | bash /dev/stdin -y



# Failed to acquire DBus name com.intel.tss2.Tabrmd

# tpm2-abrmd --allow-root --tcti=mssim:port=2321 --session --dbus-name=com.intel.tss2.Tabrmd2321



# dbus-send --system --dest=com.intel.tss2.Tabrmd --type=method_call --print-reply /com/intel/tss2/Tabrmd/Tcti org.freedesktop.DBus.Introspectable.Introspect

# dbus-daemon --config-file=/usr/share/dbus-1/system.conf --print-address

# dbus-daemon --config-file=/usr/share/dbus-1/session.conf --print-address



# export TPM2_ABRMD="tpm2-abrmd"
# export TPM2_SIM="tpm_server"
# source helpers.sh
# start_up
# set +e





### Works


# ibmtpm1332
# tpm2_tools:  af53407dec18b6f46646ed40b94f97cb240c2f43
# tpm2-tss: 1d4a956e27dfe135239d5489c5a82af02d0d9dcf
# tpm2-abrmd: ac2a5a4b5a4e548177ed7a5b74cea23e00fd30b4


# tpm_server &
# mkdir -p /var/run/dbus && dbus-daemon --config-file=/usr/share/dbus-1/system.conf --print-address
# tpm2-abrmd --allow-root --tcti=mssim:port=2321 --dbus-name=com.intel.tss2.Tabrmd -f

# export TPM2TOOLS_TCTI=tabrmd:bus_name=com.intel.tss2.Tabrmd
