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