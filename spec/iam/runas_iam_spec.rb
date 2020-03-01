require 'spec_helper'

describe 'test default profile' do
    before(:each) do
      ENV['AWS_PROFILE']='default'
    end

    after(:each) do
      ENV.delete('AWS_PROFILE')
    end

    describe command ('aws-runas -v') do
      its(:exit_status) { should eq 0 }
      its(:stderr) { should_not match /InvalidParameter: 1 validation error/ }
    end
end

describe 'tests using a profile without a role' do
    before(:each) do
      ENV['AWS_PROFILE']='circleci'
    end

    after(:each) do
      ENV.delete('AWS_PROFILE')
    end

    describe command ('aws-runas -vl') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^Available role ARNs for circleci/ }
      its(:stdout) { should match /^\s+arn:aws:iam::\d+:role\/circleci-role$/ }
    end

    describe command ('aws-runas -vm') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^arn:aws:iam::\d+:mfa\/circleci$/ }
    end

    describe command ('aws-runas -vs') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should_not match /\s+ASSUME ROLE OUTPUT:/ }
    end

    describe command ('aws-runas -vse') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stderr) { should match /^Credentials will expire on/ }
    end

    describe command ('aws-runas -vsrd 10m') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should match /\s+Detected expired or unset session token credentials, refreshing/ }
      its(:stderr) { should match /\s+Session token duration too short/ }
    end

    describe command ('aws-runas -vsrd 360h') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should match /\s+Detected expired or unset session token credentials, refreshing/ }
      its(:stderr) { should match /\s+Session token duration too long/ }
    end

    describe command ('aws-runas -vsrd 1d') do
      its(:exit_status) { should_not eq 0 }
      its(:stderr) { should match /\s+unknown unit d in duration 1d/ }
    end

    describe command ('aws-runas -O json') do
      its(:exit_status) { should eq 0 }
      its (:stdout) { should match /{"AccessKeyId":"ASIA.*","SecretAccessKey":".*"/}
    end

    describe 'and setting duration with too short env var' do
      before(:each) do
        ENV['SESSION_TOKEN_DURATION'] = '10m'
      end

      after(:each) do
        ENV.delete('SESSION_TOKEN_DURATION')
      end

      describe command ('aws-runas -vsr') do
        its(:exit_status) { should eq 0 }
        its(:stdout) { should match /^export AWS_REGION='.+'$/ }
        its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
        its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
        its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
        its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
        its(:stderr) { should match /\s+Detected expired or unset session token credentials, refreshing/ }
        its(:stderr) { should match /\s+Session token duration too short/ }
      end
    end

    describe 'and setting duration with too long env var' do
      before(:each) do
        ENV['SESSION_TOKEN_DURATION'] = '360h'
      end

      after(:each) do
        ENV.delete('SESSION_TOKEN_DURATION')
      end

      describe command ('aws-runas -vsr') do
        its(:exit_status) { should eq 0 }
        its(:stdout) { should match /^export AWS_REGION='.+'$/ }
        its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
        its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
        its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
        its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
        its(:stderr) { should match /\s+Detected expired or unset session token credentials, refreshing/ }
        its(:stderr) { should match /\s+Session token duration too long/ }
      end
    end

    describe 'and setting duration with invalid env var' do
      before(:each) do
        ENV['SESSION_TOKEN_DURATION'] = '1d'
      end

      after(:each) do
        ENV.delete('SESSION_TOKEN_DURATION')
      end

      describe command ('aws-runas -vsr') do
        its(:exit_status) { should_not eq 0 }
        its(:stderr) { should match /\s+unknown unit d in duration 1d/ }
      end
    end

    describe command('aws-runas --whoami') do
        its(:exit_status) { should eq 0 }
        its(:stderr) { should match /^\s+Account: "686784119290",$/}
        its(:stderr) { should match /^\s+Arn: "arn:aws:iam::686784119290:user\/circleci",$/}
    end
end
