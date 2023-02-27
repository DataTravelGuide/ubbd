#!/bin/bash

set -e

ARCH=`dpkg --print-architecture`
source /etc/os-release

./install_dep.sh
git submodule update --init --recursive

sed "s/@ARCH@/${ARCH}/g" debian/control.in > debian/control
sed "s/@CODENAME@/${VERSION_CODENAME}/g" debian/changelog.in > debian/changelog
dpkg-buildpackage -uc -us
