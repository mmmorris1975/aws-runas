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

require 'spec_helper'

describe command('aws-runas --help') do
    its(:exit_status) { should eq 0 }
    its(:stdout) { should match /^USAGE:\s+aws-runas/m }
end

describe command ('aws-runas --version') do
  its(:exit_status) { should eq 0 }
  its(:stdout) { should match /\d+\.\d+(\.\d+)?(-\d+-\w+)?/ }
end

describe command ('aws-runas -vu') do
  its(:exit_status) { should eq 0 }
  its(:stdout) { should match /^New version of aws-runas available:\s+\d+\.\d+\.\d+/ }
end

describe command ('aws-runas -D circleci') do
    its(:exit_status) { should eq 0 }
    its(:stderr) { should match /INFO region is configured in profile or environment variable$/ }
    its(:stderr) { should match /INFO system time is within spec/ }
    its(:stdout) { should match /^PROFILE:\s+\w+/ }
end