require 'spec_helper'

describe command('true') do
  its(:exit_status) { should eq 0 }
  its(:stdout) { should match /^$/ }
  its(:stderr) { should match /^$/ }
end