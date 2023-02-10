#!/bin/bash
set -e

replace_option()
{
	file=$1
	old=$2
	new=$3
	sed -i "s#${old}#${new}#" ${file}
}

./run_check.sh

git clone https://github.com/ubbd/ubbd-tests

git clone https://github.com/ubbd/ubbd-kernel

git clone https://github.com/kdave/xfstests

UBBD_DIR=`pwd`
UBBD_TESTS_DIR="${UBBD_DIR}/ubbd-tests"
UBBD_KERNEL_DIR="${UBBD_DIR}/ubbd-kernel"
XFSTESTS_DIR="${UBBD_DIR}/xfstests"

cd ubbd-tests
mkdir test
mkdir scratch

cp local_conf.example local_conf

replace_option local_conf "UBBD_DIR=.*" "UBBD_DIR=\"${UBBD_DIR}\""
replace_option local_conf "UBBD_TESTS_DIR=.*" "UBBD_TESTS_DIR=\"${UBBD_TESTS_DIR}\""
replace_option local_conf "UBBD_KERNEL_DIR=.*" "UBBD_KERNEL_DIR=\"${UBBD_KERNEL_DIR}\""
replace_option local_conf "UBBD_TESTS_XFSTESTS_DIR=.*" "UBBD_TESTS_XFSTESTS_DIR=\"${XFSTESTS_DIR}\""
replace_option local_conf "XFSTESTS_SCRATCH_MNT=.*" "XFSTESTS_SCRATCH_MNT=\"${UBBD_TESTS_DIR}/scratch\""
replace_option local_conf "XFSTESTS_TEST_MNT=.*" "XFSTESTS_TEST_MNT=\"${UBBD_TESTS_DIR}/test\""
replace_option local_conf "FIOTEST_OUTFILE=.*" "FIOTEST_OUTFILE=\"fio_output.cvs\""

cat local_conf

./test_all.sh quick
