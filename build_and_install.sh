#!/usr/bin/bash

set -e

ubbd_path=`pwd`

# install requirments
./install_dep.sh
git submodule update --init --recursive

./configure --enable-rbd-backend --enable-s3-backend --enable-cache-backend --enable-ssh-backend --enable-debug --enable-asan
# build
make

# install
make install

# post install
ldconfig
systemctl daemon-reload
systemctl restart ubbdd
