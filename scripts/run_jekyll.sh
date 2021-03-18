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

set -eo pipefail

cd docs

if [ -d vendor/cache ]
then
  bundle install --local || bundle install
else
  bundle install && bundle cache
fi

bundle exec jekyll build
bundle exec jekyll serve -H 0.0.0.0 $@