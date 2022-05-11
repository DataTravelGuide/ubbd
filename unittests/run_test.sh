#!/bin/bash

make

valgrind --leak-check=full ./utils_test
if [ $? -ne 0 ]; then
	exit -1
fi

valgrind --leak-check=full ./ubbd_uio_test
if [ $? -ne 0 ]; then
	exit -1
fi

rm -rf result
mkdir result
mv *gcda result/
mv *gcno result/


cd result
lcov --directory . --capture  --output-file info
genhtml ./info

