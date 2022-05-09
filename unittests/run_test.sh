#!/bin/bash

make

valgrind --leak-check=full ./utils_test
valgrind --leak-check=full ./ubbd_uio_test

rm -rf result
mkdir result
mv *gcda result/
mv *gcno result/


cd result
lcov --directory . --capture  --output-file info
genhtml ./info

