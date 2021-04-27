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

shared_examples_for 'iam role credentials' do |profile|
    describe command ("aws-runas -v #{profile}") do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      #its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should_not match /\s+ASSUME ROLE OUTPUT:/ }
    end

    describe command ("aws-runas -ve #{profile}") do
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
        its(:stderr) { should match /\s+Account:686784119290/}
        its(:stderr) { should match /\s+Arn:arn:aws:sts::686784119290:assumed-role\/aws-runas-testing\/circleci/}
    end

    describe command ("aws-runas -v #{profile} true") do
      its(:exit_status) { should eq 0 }
      its(:stderr) { should match /\s+ASSUME ROLE CREDENTIALS: \{AccessKeyID:\s*\w+/ }
      its(:stderr) { should match /\s+DEBUG ECS credential endpoint set to http:\/\/127\.0\.0\.1:\d{4,5}\/credentials$/ }
      its(:stderr) { should match /\s+DEBUG WRAPPED CMD: \[true\]$/ }
    end

    describe command ("aws-runas -Ev #{profile} true") do
      its(:exit_status) { should eq 0 }
      its(:stderr) { should match /\s+ASSUME ROLE CREDENTIALS: \{AccessKeyID:\s*\w+/ }
      its(:stderr) { should_not match /\s+DEBUG ECS credential endpoint set to http:\/\/127\.0\.0\.1:\d{4,5}\/credentials$/ }
      its(:stderr) { should match /\s+DEBUG WRAPPED CMD: \[true\]$/ }
    end
end

shared_examples_for 'iam role credentials with short duration' do |profile, duration|
    describe command ("aws-runas -vr #{duration} #{profile}") do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      #its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should match /\s+Detected expired or unset assume role credentials, refreshing/ }
      its(:stderr) { should match /\s+provided duration too short, setting to minimum value/ }
    end
end

shared_examples_for 'iam role credentials with long duration' do |profile, duration|
    describe command ("aws-runas -vr #{duration} #{profile}") do
      its(:exit_status) { should_not eq 0 }
      its(:stderr) { should match /\s+Detected expired or unset assume role credentials, refreshing/ }
      its(:stderr) { should match /\s+provided duration too long, setting to maximum value/ }
      its(:stderr) { should match /\s+The requested DurationSeconds exceeds the MaxSessionDuration set for this role/ }
    end
end

shared_examples_for 'iam role credentials with invalid duration' do |profile, duration|
    describe command ("aws-runas -vr #{duration} #{profile}") do
      its(:exit_status) { should_not eq 0 }
      its(:stderr) { should match /\s+(invalid value|could not parse) "7d"/ }
    end
end

shared_examples_for 'iam role credentials with extended duration' do |profile, duration|
    describe command ("aws-runas -vr #{duration} #{profile}") do
      its(:exit_status) { should eq 0 }
      its(:stderr) { should_not match /\s+DEBUG SESSION TOKEN CREDENTIALS:\s+/ }
      its(:stderr) { should match /\s+DEBUG ASSUME ROLE CREDENTIALS:\s+/ }
    end
end

shared_examples_for 'iam role credentials with extended duration and command' do |profile, duration, cmd|
    describe command ("aws-runas -vr #{duration} #{profile} #{cmd}") do
      its(:exit_status) { should eq 0 }
      its(:stderr) { should_not match /\s+DEBUG SESSION TOKEN CREDENTIALS:\s+/ }
      its(:stderr) { should match /\s+DEBUG ASSUME ROLE CREDENTIALS:\s+/ }
      its(:stderr) { should match /\s+DEBUG ECS endpoint ready\s*$/ }
      its(:stderr) { should match /\s+DEBUG WRAPPED CMD:\s+/ }
    end
end

describe 'tests using IAM user role credentials' do
    after(:each) do
        FileUtils.rm_f(Pathname.glob(Pathname($config_path).join(".aws_assume_role_*")))
        FileUtils.rm_f(Pathname.glob(Pathname($config_path).join(".aws_session_token_*")))
    end

    describe 'with default duration' do
        describe 'using named profile command argument' do
            it_should_behave_like 'iam role credentials', 'iam-role'
        end

        describe 'using named profile environment variable' do
            before(:all) do
              ENV['AWS_PROFILE']='iam-role'
            end

            after(:all) do
              ENV.delete('AWS_PROFILE')
            end

            it_should_behave_like 'iam role credentials'
        end

        # using ARN profile requires that we supply credentials in the environment or default profile
        if ENV.fetch("CIRCLECI", false).to_s === "true"; then
            before(:all) do
                ENV['AWS_ACCESS_KEY_ID'] = ENV['AWS_ACCESSKEY']
                ENV['AWS_SECRET_ACCESS_KEY'] = ENV['AWS_SECRETKEY']
            end

            after(:all) do
                ENV.delete('AWS_ACCESS_KEY_ID')
                ENV.delete('AWS_SECRET_ACCESS_KEY')
            end

            describe 'using ARN profile command argument' do
                it_should_behave_like 'iam role credentials', 'arn:aws:iam::686784119290:role/aws-runas-testing'
            end

            describe 'using ARN profile environment variable' do
                before(:all) do
                  ENV['AWS_PROFILE']='arn:aws:iam::686784119290:role/aws-runas-testing'
                end

                after(:all) do
                  ENV.delete('AWS_PROFILE')
                end

                it_should_behave_like 'iam role credentials'
            end
        end
    end

    describe 'with non-default duration' do
        describe 'using command arguments' do
            it_should_behave_like 'iam role credentials with short duration', 'iam-role', '-a 10m'
            it_should_behave_like 'iam role credentials with long duration', 'iam-role', '-a 360h'
            it_should_behave_like 'iam role credentials with invalid duration', 'iam-role', '-a 7d'
            it_should_behave_like 'iam role credentials with extended duration', 'iam-role', '-a 1h1m'
            it_should_behave_like 'iam role credentials with extended duration and command', 'iam-role', '-a 1h1m', 'pwd'
        end

        describe 'using environment variables' do
            before(:all) do
              ENV['AWS_PROFILE']='iam-role'
            end

            after(:all) do
              ENV.delete('AWS_PROFILE')
            end

            describe 'set too short' do
                before(:each) do
                    ENV['CREDENTIALS_DURATION']='10m'
                end

                after(:each) do
                    ENV.delete('CREDENTIALS_DURATION')
                end

                it_should_behave_like 'iam role credentials with short duration'
            end

            describe 'set too long' do
                before(:each) do
                    ENV['CREDENTIALS_DURATION']='360h'
                end

                after(:each) do
                    ENV.delete('CREDENTIALS_DURATION')
                end

                it_should_behave_like 'iam role credentials with long duration'
            end

            describe 'set with invalid duration' do
                before(:each) do
                    ENV['CREDENTIALS_DURATION']='7d'
                end

                after(:each) do
                    ENV.delete('CREDENTIALS_DURATION')
                end

                it_should_behave_like 'iam role credentials with invalid duration'
            end
        end
    end

    describe 'and setting invalid credentials as environment variables' do
        before(:each) do
            ENV['AWS_ACCESS_KEY_ID'] = 'AKIAMOCK123'
            ENV['AWS_SECRET_ACCESS_KEY'] = 'o0oMOCK/Keyo0o'
        end

        after(:each) do
            ENV.delete('AWS_ACCESS_KEY_ID')
            ENV.delete('AWS_SECRET_ACCESS_KEY')
        end

        describe command ('aws-runas -v iam-role') do
            its(:exit_status) { should eq 0 }
            #its(:stderr) { should match /\s+WARN Error getting IAM user info, retrying with AWS credential env vars unset/ }
            its(:stdout) { should match /^export AWS_REGION='.+'$/ }
            its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
            its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
            its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
            #its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
        end
    end
end