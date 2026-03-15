#
# Copyright (c) 2026 Michael Morris. All Rights Reserved.
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

# Isolated writable credentials file so tests never touch the read-only testdata mount.
# The real credentials are copied here before each test group so IAM authentication
# continues to work while STS output is written here.
$write_creds_file = "/tmp/aws_runas_write_credentials_test_#{Process.pid}"

def setup_fresh_creds
    FileUtils.rm_f($write_creds_file)
    FileUtils.rm_f($write_creds_file + '.lock')

    if ENV.fetch("CIRCLECI", false).to_s === "true"; then
        FileUtils.cp('build/aws_credentials', $write_creds_file)
    else
        FileUtils.cp('testdata/aws_credentials', $write_creds_file)
    end

    FileUtils.chmod(0600, $write_creds_file)
end

def cleanup_write_creds_test
    FileUtils.rm_f($write_creds_file)
    FileUtils.rm_f($write_creds_file + '.lock')
    FileUtils.rm_f(Pathname.glob(Pathname($config_path).join(".aws_session_token_*")))
    FileUtils.rm_f(Pathname.glob(Pathname($config_path).join(".aws_assume_role_*")))
end

# Verifies that normal credential output is unaffected when --write-credentials is used.
shared_examples_for 'write credentials unaffected stdout' do |flag, profile|
    ENV['AWS_SHARED_CREDENTIALS_FILE']=$write_creds_file
    describe command("aws-runas #{flag} -s #{profile}") do
        its(:exit_status) { should eq 0 }
        its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
        its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.+'$/ }
        its(:stdout) { should match /^export AWS_SESSION_TOKEN='.+'$/ }
        its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.+'$/ }
    end
    ENV.delete('AWS_SHARED_CREDENTIALS_FILE')
end

# Verifies that STS session token credentials are written to the credentials file.
shared_examples_for 'write session token credentials to file' do |profile|
    describe file($write_creds_file) do
        it { should exist }
        it { should be_mode 600 }
        its(:content) { should match /^\[#{Regexp.escape(profile)}\]$/ }
        its(:content) { should match /^aws_access_key_id\s*=\s*ASIA\w+/ }
        its(:content) { should match /^aws_secret_access_key\s*=\s*.+/ }
        its(:content) { should match /^aws_session_token\s*=\s*.+/ }
    end
end

# Verifies that STS assume role credentials are written to the credentials file.
shared_examples_for 'write role credentials to file' do |profile|
    describe file($write_creds_file) do
        it { should exist }
        it { should be_mode 600 }
        its(:content) { should match /^\[#{Regexp.escape(profile)}\]$/ }
        its(:content) { should match /^aws_access_key_id\s*=\s*ASIA\w+/ }
        its(:content) { should match /^aws_secret_access_key\s*=\s*.+/ }
        its(:content) { should match /^aws_session_token\s*=\s*.+/ }
    end
end

# Verifies that existing credential file sections are not disturbed by a write.
shared_examples_for 'existing sections preserved' do |written_profile|
    describe file($write_creds_file) do
        its(:content) { should match /^\[pre-existing\]$/ }
        its(:content) { should match /^aws_access_key_id\s*=\s*AKIAPREEXISTING/ }
        its(:content) { should match /^aws_secret_access_key\s*=\s*preexistingsecret/ }
        its(:content) { should match /^\[#{Regexp.escape(written_profile)}\]$/ }
        its(:content) { should match /^aws_access_key_id\s*=\s*ASIA\w+/ }
    end
end

# Verifies that repeated writes do not produce duplicate profile sections.
shared_examples_for 'no duplicate sections on repeated runs' do |profile|
    describe file($write_creds_file) do
        it { should exist }
        its(:content) { should match /^\[#{Regexp.escape(profile)}\]$/ }
        it "contains exactly one [#{profile}] section" do
            expect(subject.content.scan(/^\[#{Regexp.escape(profile)}\]$/).length).to eq(1)
        end
    end
end

describe 'tests for --write-credentials flag' do

    # describe 'stdout output is unaffected when using long flag name' do
    #     before(:all) { setup_fresh_creds }
    #     after(:all)  { cleanup_write_creds_test }

    #     it_should_behave_like 'write credentials unaffected stdout', '--write-credentials', 'circleci'
    # end

    # describe 'stdout output is unaffected when using short flag alias -c' do
    #     before(:all) { setup_fresh_creds }
    #     after(:all)  { cleanup_write_creds_test }

    #     it_should_behave_like 'write credentials unaffected stdout', '-c', 'circleci'
    # end

    # describe 'session token credentials written to credentials file' do
    #     before(:all) do
    #         setup_fresh_creds
    #         system("AWS_SHARED_CREDENTIALS_FILE=#{$write_creds_file} build/aws-runas --write-credentials -s circleci > /dev/null 2>&1")
    #     end

    #     after(:all) { cleanup_write_creds_test }

    #     it_should_behave_like 'write session token credentials to file', 'circleci'
    # end

    describe 'role credentials written to credentials file' do
        before(:all) do
            setup_fresh_creds
            system("AWS_SHARED_CREDENTIALS_FILE=#{$write_creds_file} build/aws-runas --write-credentials iam-role > /dev/null 2>&1")
        end

        after(:all) { cleanup_write_creds_test }

        it_should_behave_like 'write role credentials to file', 'iam-role'
    end

    # describe 'RUNAS_WRITE_CREDENTIALS env var triggers credentials file write' do
    #     before(:all) do
    #         setup_fresh_creds
    #         system("RUNAS_WRITE_CREDENTIALS=true AWS_SHARED_CREDENTIALS_FILE=#{$write_creds_file} build/aws-runas -s circleci > /dev/null 2>&1")
    #     end

    #     after(:all) { cleanup_write_creds_test }

    #     it_should_behave_like 'write session token credentials to file', 'circleci'
    # end

    describe '--write-credentials with -O json writes file and outputs JSON' do
        before(:all) do
            setup_fresh_creds
        end

        after(:all) { cleanup_write_creds_test }

        describe command("AWS_SHARED_CREDENTIALS_FILE=#{$write_creds_file} aws-runas --write-credentials -O json iam-role") do
            its(:exit_status) { should eq 0 }
            its(:stdout) { should match /\{"AccessKeyId":"ASIA.*","SecretAccessKey":".*"/ }
        end

        it_should_behave_like 'write role credentials to file', 'iam-role'
    end

    describe 'existing sections in credentials file are preserved' do
        before(:all) do
            setup_fresh_creds
            File.open($write_creds_file, 'a') do |f|
                f.puts "\n[pre-existing]\naws_access_key_id = AKIAPREEXISTING\naws_secret_access_key = preexistingsecret"
            end
            system("AWS_SHARED_CREDENTIALS_FILE=#{$write_creds_file} build/aws-runas --write-credentials iam-role > /dev/null 2>&1")
        end

        after(:all) { cleanup_write_creds_test }

        it_should_behave_like 'existing sections preserved', 'iam-role'
    end

    describe 'credentials file section is not duplicated on repeated runs' do
        before(:all) do
            setup_fresh_creds
            system("AWS_SHARED_CREDENTIALS_FILE=#{$write_creds_file} build/aws-runas --write-credentials iam-role > /dev/null 2>&1")
            system("AWS_SHARED_CREDENTIALS_FILE=#{$write_creds_file} build/aws-runas --write-credentials iam-role > /dev/null 2>&1")
        end

        after(:all) { cleanup_write_creds_test }

        it_should_behave_like 'no duplicate sections on repeated runs', 'iam-role'
    end

end
