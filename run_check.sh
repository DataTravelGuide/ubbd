#!/bin/bash
set -e

ubbd_path=`pwd`

# install requirments
./install_dep.sh
git submodule update --init --recursive

# build
make

# run userspace unittests
cd ${ubbd_path}/unittests/
bash -x run_test.sh
