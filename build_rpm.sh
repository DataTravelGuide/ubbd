#!/bin/bash

set -e

version=`cat VERSION`

make dist
cp ubbd-${version}.tar.gz ~/rpmbuild/SOURCES/
cp rhel/ubbd.spec ~/rpmbuild/SPECS/
rpmbuild -ba ~/rpmbuild/SPECS/ubbd.spec
