#!/usr/bin/env bash

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

# Only release if the commit is associated with a tag (maybe only matches a semver-like tag?)
git describe --tags --exact-match --first-parent || exit 0
VER=$(git describe --tags --exact-match --first-parent)

#wget -O - https://github.com/cli/cli/releases/download/v1.4.0/gh_1.4.0_linux_amd64.tar.gz | tar xzf - -C /var/tmp
wget -O - https://github.com/cli/cli/releases/download/v2.81.0/gh_2.81.0_linux_386.tar.gz | tar xzf - -C /var/tmp

GH=$(find /var/tmp/gh* -name gh)

cd ${1:-.}

NAME="aws-runas"

sha256sum aws-runas*.zip aws-runas*.deb aws-runas*.rpm >${NAME}_${VER}.sha256sum
cat *.sha256sum

$GH release create $VER *.deb *.rpm *.zip *.sha256sum -R mmmorris1975/$NAME -n "release $VER"
