require 'spec_helper'

describe 'tests using a profile without a role' do
    #before(:each) do
    #  ENV['AWS_PROFILE']='circleci'
    #end

    #after(:each) do
    #  ENV.delete('AWS_PROFILE')
    #end

    describe command ('aws-runas -vl') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^Available role ARNs for circleci/ }
      its(:stdout) { should match /^\s+arn:aws:iam::\d+:role\/circleci-role$/ }
      its(:stderr) { should match /\s+List Roles/ }
    end

    describe command ('aws-runas -vm') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^arn:aws:iam::\d+:mfa\/circleci$/ }
      its(:stderr) { should match /\s+List MFA/ }
    end

    describe command ('aws-runas -vs') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.*'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should_not match /\s+ASSUME ROLE OUTPUT:/ }
    end

    describe command ('aws-runas -vse') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.*'$/ }
      its(:stderr) { should match /\s+Found cached session token credentials/ }
      its(:stderr) { should match /^Session credentials will expire on/ }
    end

    describe command ('aws-runas -vsrd 10m') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.*'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should match /\s+Detected expired or unset session token credentials, refreshing/ }
    end

    describe command ('aws-runas -vsrd 360h') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.*'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should match /\s+Detected expired or unset session token credentials, refreshing/ }
    end

    describe command ('aws-runas -vsrd 1d') do
      its(:exit_status) { should_not eq 0 }
      its(:stderr) { should match /\s+unknown unit d in duration 1d/ }
    end
end
