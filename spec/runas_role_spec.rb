require 'spec_helper'

# CircleCI passes credentials as env vars (and not as a credentials file as indicated on their site)
# This throws a small wrench into our testing for Assume Role operations, and we won't be able to test
# all desired scenarios

describe 'tests using a profile with a role' do
    before(:each) do
      ENV['AWS_PROFILE']='arn:aws:iam::686784119290:role/circleci-role'
    end

    after(:each) do
      ENV.delete('AWS_PROFILE')
    end

    describe command ('aws-runas -v') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should match /\s+ASSUME ROLE OUTPUT:/ }
    end

    describe command ('aws-runas -ve') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stderr) { should match /\s+Found cached session token credentials/ }
      its(:stderr) { should match /^Session credentials will expire on/ }
      its(:stderr) { should match /\s+ASSUME ROLE OUTPUT:/ }
    end

    describe command ('aws-runas -vrd 10m') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should match /\s+Detected expired or unset session token credentials, refreshing/ }
      its(:stderr) { should match /\s+ASSUME ROLE OUTPUT:/ }
    end

    describe command ('aws-runas -vrd 360h') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should match /\s+Detected expired or unset session token credentials, refreshing/ }
      its(:stderr) { should match /\s+ASSUME ROLE OUTPUT:/ }
    end

    describe command ('aws-runas -vrd 1d') do
      its(:exit_status) { should_not eq 0 }
      its(:stderr) { should match /\s+unknown unit d in duration 1d/ }
    end
end