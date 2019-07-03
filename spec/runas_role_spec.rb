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
      its(:stderr) { should match /\s+ASSUME ROLE CREDENTIALS:/ }
    end

    describe command ('aws-runas -ve') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stderr) { should match /\s+Found cached assume role credentials/ }
      its(:stderr) { should match /^Credentials will expire on/ }
      its(:stderr) { should match /\s+ASSUME ROLE CREDENTIALS:/ }
    end

    describe command ('aws-runas -vra 10m') do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should match /\s+Detected expired or unset assume role credentials, refreshing/ }
      its(:stderr) { should match /\s+ASSUME ROLE CREDENTIALS:/ }
      its(:stderr) { should match /\s+Assume role duration too short/ }
    end

    describe command ('aws-runas -vra 360h') do
      its(:exit_status) { should_not eq 0 }
      its(:stderr) { should match /\s+Detected expired or unset assume role credentials, refreshing/ }
      its(:stderr) { should match /\s+Assume role duration too long/ }
      its(:stderr) { should match /\s+The requested DurationSeconds exceeds the MaxSessionDuration/ }
    end

    describe command ('aws-runas -vra 1d') do
      its(:exit_status) { should_not eq 0 }
      its(:stderr) { should match /\s+unknown unit d in duration 1d/ }
    end

    describe 'and setting duration with too short env var' do
      before(:each) do
        ENV['CREDENTIALS_DURATION'] = '10m'
      end

      after(:each) do
        ENV.delete('CREDENTIALS_DURATION')
      end

      describe command ('aws-runas -vr') do
        its(:exit_status) { should eq 0 }
        its(:stdout) { should match /^export AWS_REGION='.+'$/ }
        its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
        its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
        its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
        its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
        its(:stderr) { should match /\s+Detected expired or unset assume role credentials, refreshing/ }
        its(:stderr) { should match /\s+ASSUME ROLE CREDENTIALS:/ }
        its(:stderr) { should match /\s+Assume role duration too short/ }
      end
    end

    describe 'and setting duration with too long env var' do
      before(:each) do
        ENV['CREDENTIALS_DURATION'] = '360h'
      end

      after(:each) do
        ENV.delete('CREDENTIALS_DURATION')
      end

      describe command ('aws-runas -vr') do
        its(:exit_status) { should_not eq 0 }
        its(:stderr) { should match /\s+Detected expired or unset assume role credentials, refreshing/ }
        its(:stderr) { should match /\s+Assume role duration too long/ }
        its(:stderr) { should match /\s+The requested DurationSeconds exceeds the MaxSessionDuration/ }
      end
    end

    describe 'and setting duration with invalid env var' do
      before(:each) do
        ENV['CREDENTIALS_DURATION'] = '1d'
      end

      after(:each) do
        ENV.delete('CREDENTIALS_DURATION')
      end

      describe command ('aws-runas -vr') do
        its(:exit_status) { should_not eq 0 }
        its(:stderr) { should match /\s+unknown unit d in duration 1d/ }
      end
    end

    if ENV.fetch("CIRCLECI", false).to_s === "false"; then
        describe 'and setting invalid credentials as environment variables' do
            before(:each) do
                ENV['AWS_ACCESS_KEY_ID'] = 'AKIAMOCK123'
                ENV['AWS_SECRET_ACCESS_KEY'] = 'o0oMOCK/Keyo0o'
            end

            after(:each) do
                ENV.delete('AWS_ACCESS_KEY_ID')
                ENV.delete('AWS_SECRET_ACCESS_KEY')
            end

            describe command ('aws-runas -v') do
                its(:exit_status) { should eq 0 }
                its(:stderr) { should match /\s+WARN Error getting IAM user info, retrying with AWS credential env vars unset/ }
                its(:stdout) { should match /^export AWS_REGION='.+'$/ }
                its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
                its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
                its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
                its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
            end
        end
    end
end