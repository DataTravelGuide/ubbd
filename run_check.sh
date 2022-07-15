#!/bin/bash
set -e

ubbd_path=`pwd`

# install requirments
apt install -y librbd-dev libc-dev libnl-3-dev libnl-genl-3-dev

apt install -y libcmocka-dev valgrind lcov cmake pkg-config

apt install -y libcurl4-openssl-dev libxml2-dev

git submodule update --init --recursive

# build
make

cd ${ubbd_path}/unittests/
# run kmods unittests
bash -x kmod_ut.sh

# run userspace unittests
cd ${ubbd_path}/unittests/
bash -x run_test.sh
