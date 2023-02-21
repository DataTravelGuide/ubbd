#!/bin/bash

set -e

./install_dep.sh
git submodule update --init --recursive
dpkg-buildpackage -uc -us
