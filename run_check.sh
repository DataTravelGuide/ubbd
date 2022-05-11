#!/bin/bash
set -e

ubbd_path=`pwd`

# install requirments
apt install -y librbd-dev libc-dev libnl-3-dev libnl-genl-3-dev

apt install -y libcmocka-dev valgrind lcov cmake pkg-config

# build
make

# run userspace unittests
cd ${ubbd_path}/unittests/
bash -x run_test.sh

cd ${ubbd_path}/unittests/
# run kmods unittests
bash -x kmod_ut.sh
