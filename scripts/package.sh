#!/bin/bash -e

BUILD_DIR=`realpath $(dirname $0)/..`

cd $BUILD_DIR

apt-get update && apt-get -y install build-essential alien ruby-dev rubygems git
gem install --no-ri --no-rdoc fpm

cp $BUILD_DIR/aws-runas-*-linux-amd64 /var/tmp/aws-runas

# Build RPM package
fpm --verbose -s dir -t rpm --name aws-runas --version $VER --license MIT --architecture 'x86_64' --provides 'aws-runas' \
  --description 'aws-runas' --url 'https://github.com/mmmorris1975/aws-runas' --maintainer 'mmmorris1975@github' \
  --rpm-user bin --rpm-group bin --rpm-digest sha1 --after-install $BUILD_DIR/scripts/pkg-post-install.sh \
  --depends libcap --prefix /usr/local/bin -C /var/tmp aws-runas

# Build DEB (Debian's "alien" package conversion tool didn't seem to preserve the RPM post-install script)
fpm --verbose -s dir -t deb --name aws-runas --version $VER --license MIT --architecture 'x86_64' --provides 'aws-runas' \
  --description 'aws-runas' --url 'https://github.com/mmmorris1975/aws-runas' --maintainer 'mmmorris1975@github' \
  --deb-user bin --deb-group bin --after-install $BUILD_DIR/scripts/pkg-post-install.sh \
  --deb-pre-depends libcap2-bin --prefix /usr/local/bin -C /var/tmp aws-runas
