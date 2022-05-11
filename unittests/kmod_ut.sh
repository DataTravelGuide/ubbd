#!/bin/bash

unittest_dir=`pwd`

git submodule update

cd googletest/
mkdir build
cd build
cmake ../

make
make install


cd ${unittest_dir}
cd ktf
autoreconf

mkdir build
cd build
${unittest_dir}/ktf/configure KVER=`uname -r`

make
insmod kernel/ktf.ko
make install

cd ${unittest_dir}/../
make unittest
modprobe uio
insmod kmods/ubbd.ko
insmod kmods/ubbd_ut.ko

ktfrun

rmmod ubbd_ut
rmmod ubbd
rmmod uio