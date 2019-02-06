require 'spec_helper'

describe command ('aws-runas --help') do
  its(:exit_status) { should eq 0 }
  its(:stderr) { should match /^usage:\s+aws-runas/ }
end

describe command ('aws-runas --version') do
  its(:exit_status) { should eq 0 }
  its(:stderr) { should match /^\d+\.\d+\.\d+(-\d+-\w+)?/ }
end

describe command ('aws-runas -vu') do
  its(:exit_status) { should eq 0 }
  its(:stdout) { should match /^New version of aws-runas available:/ }
  its(:stderr) { should match /\s+Update check/ }
end