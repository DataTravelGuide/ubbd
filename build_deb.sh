#!/bin/bash

set -e

git submodule update --init --recursive
dpkg-buildpackage -uc -us
