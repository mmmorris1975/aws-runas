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
require_relative 'shared_examples'

describe 'okta saml credentials' do
    before(:all) do
        # !!!! command to test is echoed in the output, don't put password as a cmdline option !!!!
        ENV['SAML_PASSWORD'] = ENV['OKTA_PASSWORD']
    end

    after(:each) do
        FileUtils.rm_f(Pathname.glob(Pathname($config_path).join(".aws_saml_role_*")))
    end

    after(:all) do
        FileUtils.rm_f(Pathname.glob(Pathname($config_path).join(".aws_runas.cookies")))
        ENV.delete('SAML_PASSWORD')
    end

    describe 'with command line config' do
        if ENV.has_key?('OKTA_SAML_URL')
            it_should_behave_like 'saml role credentials', 'okta-saml', "-S '#{ENV['OKTA_SAML_URL']}'"
        else
            skip 'OKTA_SAML_URL not set, skipping'
        end
    end

    describe 'with env var config' do
        before(:all) do
            ENV['AWS_PROFILE'] = 'okta-saml'
            ENV['SAML_AUTH_URL'] = ENV['OKTA_SAML_URL']
        end

        if ENV.has_key?('OKTA_SAML_URL')
            it_should_behave_like 'saml role credentials'
        else
            skip 'OKTA_SAML_URL not set, skipping'
        end

        after(:all) do
            ENV.delete('SAML_AUTH_URL')
            ENV.delete('AWS_PROFILE')
        end
    end
end

describe 'okta web identity credentials' do
    before(:all) do
        # !!!! command to test is echoed in the output, don't put password as a cmdline option !!!!
        ENV['WEB_PASSWORD'] = ENV['OKTA_PASSWORD']
    end

    after(:each) do
        FileUtils.rm_f(Pathname.glob(Pathname($config_path).join(".aws_web_role_*")))
    end

    after(:all) do
        FileUtils.rm_f(Pathname.glob(Pathname($config_path).join(".aws_runas.cookies")))
        FileUtils.rm_f(Pathname.glob(Pathname($config_path).join(".aws_runas_identity_token.cache")))

        ENV.delete('WEB_PASSWORD')
    end

    describe 'with command line config' do
        if ENV.has_key?('OKTA_OIDC_URL')
            opts = "-W '#{ENV['OKTA_OIDC_URL']}' -C '#{ENV['OKTA_OIDC_CLIENT_ID']}'"
            it_should_behave_like 'web identity role credentials', 'okta-oidc', opts
        else
            skip 'OKTA_OIDC_URL not set, skipping'
        end
    end

    describe 'with env var config' do
        before(:all) do
            ENV['AWS_PROFILE'] = 'okta-oidc'
            ENV['WEB_AUTH_URL'] = ENV['OKTA_OIDC_URL']
            ENV['WEB_CLIENT_ID'] = ENV['OKTA_OIDC_CLIENT_ID']
        end

        if ENV.has_key?('OKTA_OIDC_URL')
            it_should_behave_like 'web identity role credentials'
        else
            skip 'OKTA_OIDC_URL not set, skipping'
        end

        after(:all) do
            ENV.delete('WEB_AUTH_URL')
            ENV.delete('WEB_CLIENT_ID')
            ENV.delete('AWS_PROFILE')
        end
    end
end