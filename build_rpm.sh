#!/bin/bash

set -e

./install_dep.sh
version=`cat VERSION`

make dist
cp ubbd-${version}.tar.gz ~/rpmbuild/SOURCES/
cp rpm/ubbd.spec ~/rpmbuild/SPECS/
rpmbuild -ba ~/rpmbuild/SPECS/ubbd.spec
