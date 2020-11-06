require 'spec_helper'

# This should hopefully be sufficient to validate that using a profile command arg, or the env variable,
# is returning the correct info.  Hoping to avoid needing to do similar tests for every little piece

shared_examples_for 'iam user attributes' do |profile|
    describe command ("aws-runas -vl #{profile}") do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^Available role ARNs for circleci/ }
      its(:stdout) { should match /^\s+arn:aws:iam::\d+:role\/circleci-role$/ }
    end

    describe command ("aws-runas -v list roles #{profile}") do
          its(:exit_status) { should eq 0 }
          its(:stdout) { should match /^Available role ARNs for circleci/ }
          its(:stdout) { should match /^\s+arn:aws:iam::\d+:role\/circleci-role$/ }
        end

    describe command ("aws-runas -vm #{profile}") do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^arn:aws:iam::\d+:mfa\/circleci$/ }
    end

    describe command ("aws-runas -v list mfa #{profile}") do
          its(:exit_status) { should eq 0 }
          its(:stdout) { should match /^arn:aws:iam::\d+:mfa\/circleci$/ }
        end
end

describe 'tests for IAM user attributes' do
  describe 'using profile command argument' do
    it_should_behave_like 'iam user attributes', 'circleci'
  end

  describe 'using profile environment variable' do
      before(:all) do
        ENV['AWS_PROFILE']='circleci'
      end

      after(:all) do
        ENV.delete('AWS_PROFILE')
      end

      it_should_behave_like 'iam user attributes'
  end
end