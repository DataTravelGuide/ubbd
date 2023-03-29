#!/bin/bash

git clone https://github.com/yangdongsheng/ceph.git

cd ceph
git checkout ubbd

./run-make-check.sh  -DWITH_SPDK=OFF -DWITH_MGR=OFF -DWITH_GTEST_PARALLEL=OFF -DWITH_LIBURING=OFF -DWITH_CEPHFS=OFF -DWITH_RBD_UBBD=ON -DWITH_FIO=OFF
