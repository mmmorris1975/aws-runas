require 'spec_helper'

describe 'tests using a profile with a role' do
    before(:each) do
      ENV['AWS_PROFILE']='arn:aws:iam::686784119290:role/circleci-role'
    end

    after(:each) do
      ENV.delete('AWS_PROFILE')
    end

    #describe command ('aws-runas -vs') do
    #  its(:exit_status) { should eq 0 }
    #  its(:stdout) { should match /^export AWS_REGION='.*'$/ }
    #  its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
    #  its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
    #  its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
    #  its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
    #  its(:stderr) { should match /\s+Found cached session token credentials/ }
    #  its(:stderr) { should_not match /\s+ASSUME ROLE OUTPUT:/ }
    #end

    #describe command ('aws-runas -vse') do
    #  its(:exit_status) { should eq 0 }
    #  its(:stdout) { should match /^export AWS_REGION='.*'$/ }
    #  its(:stderr) { should match /\s+Found cached session token credentials/ }
    #  its(:stderr) { should match /^Session credentials will expire on/ }
    #end

    #describe command ('aws-runas -vsrd 10m') do
    #  its(:exit_status) { should eq 0 }
    #  its(:stdout) { should match /^export AWS_REGION='.*'$/ }
    #  its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
    #  its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
    #  its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
    #  its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
    #  its(:stderr) { should match /\s+Detected expired or unset session token credentials, refreshing/ }
    #end

    #describe command ('aws-runas -vsrd 360h') do
    #  its(:exit_status) { should eq 0 }
    #  its(:stdout) { should match /^export AWS_REGION='.*'$/ }
    #  its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
    #  its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
    #  its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
    #  its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
    #  its(:stderr) { should match /\s+Detected expired or unset session token credentials, refreshing/ }
    #end

    #describe command ('aws-runas -vsrd 1d') do
    #  its(:exit_status) { should_not eq 0 }
    #  its(:stderr) { should match /\s+unknown unit d in duration 1d/ }
    #end


    describe command ('aws-runas -v') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.*'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should match /\s+ASSUME ROLE OUTPUT:/ }
    end

    describe command ('aws-runas -ve') do
      its(:exit_status) { should eq 0 }
      its(:stderr) { should match /\s+Found cached session token credentials/ }
      its(:stderr) { should match /^Session credentials will expire on/ }
      its(:stderr) { should match /\s+ASSUME ROLE OUTPUT:/ }
    end

    #    describe command ('aws-runas -vrd 10m') do
    #      its(:exit_status) { should eq 0 }
    #      its(:stdout) { should match /^export AWS_REGION='.*'$/ }
    #      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
    #      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
    #      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
    #      its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
    #      its(:stderr) { should match /\s+Detected expired or unset session token credentials, refreshing/ }
    #      its(:stderr) { should match /\s+ASSUME ROLE OUTPUT:/ }
    #    end

    #    describe command ('aws-runas -vrd 360h') do
    #      its(:exit_status) { should eq 0 }
    #      its(:stdout) { should match /^export AWS_REGION='.*'$/ }
    #      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
    #      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
    #      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
    #      its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
    #      its(:stderr) { should match /\s+Detected expired or unset session token credentials, refreshing/ }
    #      its(:stderr) { should match /\s+ASSUME ROLE OUTPUT:/ }
    #    end

    #    describe command ('aws-runas -vrd 1d') do
    #      its(:exit_status) { should_not eq 0 }
    #      its(:stderr) { should match /\s+unknown unit d in duration 1d/ }
    #    end
end

describe 'run command using a role arn instead of profile name'