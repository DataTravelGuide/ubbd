#!/usr/bin/bash

set -e

ubbd_path=`pwd`

# install requirments
./install_dep.sh
git submodule update --init --recursive

# build
make

# install
make install

# post install
ldconfig
systemctl daemon-reload
systemctl restart ubbdd
