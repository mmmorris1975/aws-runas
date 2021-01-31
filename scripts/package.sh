#!/bin/bash -e

PKG_DIR=/var/tmp/pkg
BUILD_DIR=`realpath $(dirname $0)/..`

cd $BUILD_DIR
mkdir -p $PKG_DIR/etc/bash_completion.d
mkdir -p $PKG_DIR/usr/local/bin $PKG_DIR/usr/local/share/aws-runas

apt-get update && apt-get -y install build-essential alien ruby-dev rubygems git
gem install --no-ri --no-rdoc fpm

cp $BUILD_DIR/aws-runas-*-linux-amd64 ${PKG_DIR}/usr/local/bin/aws-runas
cp $BUILD_DIR/extras/aws-runas-*-completion ${PKG_DIR}/usr/local/share/aws-runas/
cp $BUILD_DIR/extras/aws-runas-bash-completion ${PKG_DIR}/etc/bash_completion.d/aws-runas

chmod a+x ${PKG_DIR}/usr/local/bin/aws-runas
chmod a+r ${PKG_DIR}/usr/local/share/aws-runas/* ${PKG_DIR}/etc/bash_completion.d/aws-runas

# Build RPM package
fpm --verbose -s dir -t rpm --name aws-runas --version $VER --license MIT --architecture 'x86_64' --provides 'aws-runas' \
  --description 'aws-runas' --url 'https://github.com/mmmorris1975/aws-runas' --maintainer 'mmmorris1975@github' \
  --rpm-user bin --rpm-group bin --rpm-digest sha1 --after-install $BUILD_DIR/scripts/pkg-post-install.sh \
  --depends libcap --prefix / -C $PKG_DIR

# Build DEB (Debian's "alien" package conversion tool didn't seem to preserve the RPM post-install script)
fpm --verbose -s dir -t deb --name aws-runas --version $VER --license MIT --architecture 'x86_64' --provides 'aws-runas' \
  --description 'aws-runas' --url 'https://github.com/mmmorris1975/aws-runas' --maintainer 'mmmorris1975@github' \
  --deb-user bin --deb-group bin --after-install $BUILD_DIR/scripts/pkg-post-install.sh \
  --deb-pre-depends libcap2-bin --prefix / -C $PKG_DIR