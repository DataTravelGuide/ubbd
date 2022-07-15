#!/bin/bash

unittest_dir=`pwd`

git submodule update --init --recursive

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
make kmod_ut
modprobe uio
insmod kmods/ubbd_ut.ko

LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/ ktfrun
if [ $? -ne 0 ]; then
	exit -1
fi

rmmod ubbd_ut
rmmod uio
rmmod ktf
