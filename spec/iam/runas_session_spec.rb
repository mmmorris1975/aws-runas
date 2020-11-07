require 'spec_helper'

# let's leave AWS_SECURITY_TOKEN (legacy env var) out of the credentials and see if anyone complains

shared_examples_for 'iam session credentials' do |profile|
    describe command ("aws-runas -vs #{profile}") do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      #its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should_not match /\s+ASSUME ROLE OUTPUT:/ }
    end

    describe command ("aws-runas -vse #{profile}") do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stderr) { should match /^Credentials will expire on/ }
    end

    describe command ("aws-runas -O json #{profile}") do
      its(:exit_status) { should eq 0 }
      its (:stdout) { should match /{"AccessKeyId":"ASIA.*","SecretAccessKey":".*"/}
    end

    describe command("aws-runas --whoami #{profile}") do
        its(:exit_status) { should eq 0 }
        its(:stderr) { should match /^\s+Account: "686784119290",$/}
        its(:stderr) { should match /^\s+Arn: "arn:aws:iam::686784119290:user\/circleci",$/}
    end
end

shared_examples_for 'iam session credentials with short duration' do |profile, duration|
    describe command ("aws-runas -vsr #{duration} #{profile}") do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      #its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should match /\s+Detected expired or unset session token credentials, refreshing/ }
      its(:stderr) { should match /\s+provided duration too short, setting to minimum value/ }
    end
end

shared_examples_for 'iam session credentials with long duration' do |profile, duration|
    describe command ("aws-runas -vsr #{duration} #{profile}") do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      #its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should match /\s+Detected expired or unset session token credentials, refreshing/ }
      its(:stderr) { should match /\s+provided duration too long, setting to maximum value/ }
    end
end

shared_examples_for 'iam session credentials with invalid duration' do |profile, duration|
    describe command ("aws-runas -vsr #{duration} #{profile}") do
      its(:exit_status) { should_not eq 0 }
      its(:stderr) { should match /\s+(invalid value|could not parse) "7d"/}
    end
end

describe 'tests using IAM user session token credentials' do
    after(:each) do
        FileUtils.rm_f(Pathname.glob(Pathname($config_path).join(".aws_session_token_*")))
    end

    describe 'with default duration' do
        describe 'using profile command argument' do
          it_should_behave_like 'iam session credentials', 'circleci'
        end

        describe 'using profile environment variable' do
            before(:all) do
              ENV['AWS_PROFILE']='circleci'
            end

            after(:all) do
              ENV.delete('AWS_PROFILE')
            end

            it_should_behave_like 'iam session credentials'
        end
    end

    describe 'with non-default duration' do
        describe 'using command arguments' do
            it_should_behave_like 'iam session credentials with short duration', 'circleci', '-d 10m'
            it_should_behave_like 'iam session credentials with long duration', 'circleci', '-d 360h'
            it_should_behave_like 'iam session credentials with invalid duration', 'circleci', '-d 7d'
        end

        describe 'using environment variables' do
            before(:all) do
              ENV['AWS_PROFILE']='circleci'
            end

            after(:all) do
              ENV.delete('AWS_PROFILE')
            end

            describe 'set too short' do
                before(:each) do
                    ENV['SESSION_TOKEN_DURATION']='10m'
                end

                after(:each) do
                    ENV.delete('SESSION_TOKEN_DURATION')
                end

                it_should_behave_like 'iam session credentials with short duration'
            end

            describe 'set too long' do
                before(:each) do
                    ENV['SESSION_TOKEN_DURATION']='360h'
                end

                after(:each) do
                    ENV.delete('SESSION_TOKEN_DURATION')
                end

                it_should_behave_like 'iam session credentials with long duration'
            end

            describe 'set with invalid duration' do
                before(:each) do
                    ENV['SESSION_TOKEN_DURATION']='7d'
                end

                after(:each) do
                    ENV.delete('SESSION_TOKEN_DURATION')
                end

                it_should_behave_like 'iam session credentials with invalid duration'
            end
        end
    end
end
