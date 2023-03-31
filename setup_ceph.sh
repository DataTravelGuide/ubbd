#!/bin/bash
set -x

apt install -y ninja-build
git clone https://github.com/ceph/ceph

cd ceph
git checkout ubbd

./install-deps.sh


ARGS="-DWITH_SPDK=OFF -DWITH_MGR=OFF -DWITH_GTEST_PARALLEL=OFF -DWITH_LIBURING=OFF -DWITH_CEPHFS=OFF -DWITH_RBD_UBBD=ON -DWITH_FIO=OFF" ./do_cmake.sh

cd build
ninja -j 24 install
