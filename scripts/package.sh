#!/bin/bash -ex

#
# Copyright (c) 2021 Michael Morris. All Rights Reserved.
#
# Licensed under the MIT license (the "License"). You may not use this file except in compliance
# with the License. A copy of the License is located at
#
# https://github.com/mmmorris1975/aws-runas/blob/master/LICENSE
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
# for the specific language governing permissions and limitations under the License.
#

PKG_DIR=/var/tmp/pkg
BUILD_DIR=`realpath $(dirname $0)/..`

cd $BUILD_DIR
mkdir -p $PKG_DIR/etc/bash_completion.d
mkdir -p $PKG_DIR/usr/local/bin $PKG_DIR/usr/local/share/aws-runas

# The circleci ruby image provides all required packages. On a debian:stable docker image
# you will need to also install the following packages: build-essential ruby-dev rubygems git
sudo apt-get update && sudo apt-get -y install alien
gem install fpm -v 1.12.0

cp $BUILD_DIR/build/linux/$ARCH/aws-runas ${PKG_DIR}/usr/local/bin/aws-runas
cp $BUILD_DIR/extras/aws-runas-*-completion ${PKG_DIR}/usr/local/share/aws-runas/
cp $BUILD_DIR/extras/aws-runas-bash-completion ${PKG_DIR}/etc/bash_completion.d/aws-runas

chmod a+x ${PKG_DIR}/usr/local/bin/aws-runas
chmod a+r ${PKG_DIR}/usr/local/share/aws-runas/* ${PKG_DIR}/etc/bash_completion.d/aws-runas

# fpm handles translation of amd64 between rpm and deb, but we need to also translate the
# arm and arm64 architectures as well.  Assume 32-bit arm builds are v7 (hard float) only.
# Mapping created from Fedora and Debian official disto mirrors
# RPM: amd64 = x86_64, arm = armv7hl, arm64 = aarch64
# DEB: amd64 = amd64, arm = armhf, arm64 = arm64
RPMARCH=$ARCH
DEBARCH=$ARCH
if [ $ARCH == "arm64" ]
then
  RPMARCH="aarch64"
elif [ $ARCH == "arm" ]
then
  RPMARCH="armv7hl"
  DEBARCH="armhf"
fi

# Build RPM package
fpm --verbose -s dir -t rpm --name aws-runas --version $VER --license MIT --architecture $RPMARCH --provides 'aws-runas' \
  --description 'aws-runas' --url 'https://github.com/mmmorris1975/aws-runas' --maintainer 'mmmorris1975@github' \
  --rpm-user bin --rpm-group bin --rpm-digest sha1 --after-install $BUILD_DIR/scripts/pkg-post-install.sh \
  --depends libcap --prefix / -C $PKG_DIR -p ${BUILD_DIR}/pkg/

# Build DEB (Debian's "alien" package conversion tool didn't seem to preserve the RPM post-install script)
fpm --verbose -s dir -t deb --name aws-runas --version $VER --license MIT --architecture $DEBARCH --provides 'aws-runas' \
  --description 'aws-runas' --url 'https://github.com/mmmorris1975/aws-runas' --maintainer 'mmmorris1975@github' \
  --deb-user bin --deb-group bin --after-install $BUILD_DIR/scripts/pkg-post-install.sh \
  --deb-pre-depends libcap2-bin --prefix / -C $PKG_DIR -p ${BUILD_DIR}/pkg/