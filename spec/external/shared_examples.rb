require 'serverspec'

shared_examples_for 'saml role credentials' do |profile, params|
    describe command ("aws-runas -ve #{params} #{profile}") do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      #its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should match /\s+SAML ROLE CREDENTIALS:/ }
      its(:stderr) { should match /^Credentials will expire on/ }
    end

    describe command("aws-runas --whoami #{params} #{profile}") do
        its(:exit_status) { should eq 0 }
        its(:stderr) { should match /\s+Account:686784119290/}
        its(:stderr) { should match /\s+Arn:arn:aws:sts::686784119290:assumed-role\/aws-runas-testing\//}
    end

    describe command ("aws-runas -vl #{params} #{profile}") do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^Available role ARNs for/ }
      its(:stdout) { should match /^\s+arn:aws:iam::\d+:role\/aws-runas-testing$/ }
    end
end

shared_examples_for 'web identity role credentials' do |profile, params|
    describe command ("aws-runas -ve #{params} #{profile}") do
      its(:exit_status) { should eq 0 }
      its(:stdout) { should match /^export AWS_REGION='.+'$/ }
      its(:stdout) { should match /^export AWS_ACCESS_KEY_ID='ASIA\w+'$/ }
      its(:stdout) { should match /^export AWS_SECRET_ACCESS_KEY='.*'$/ }
      its(:stdout) { should match /^export AWS_SESSION_TOKEN='.*'$/ }
      #its(:stdout) { should match /^export AWS_SECURITY_TOKEN='.*'$/ }
      its(:stderr) { should match /\s+WEB IDENTITY ROLE CREDENTIALS:/ }
      its(:stderr) { should match /^Credentials will expire on/ }
    end

    describe command("aws-runas --whoami #{params} #{profile}") do
        its(:exit_status) { should eq 0 }
        its(:stderr) { should match /\s+Account:686784119290/}
        its(:stderr) { should match /\s+Arn:arn:aws:sts::686784119290:assumed-role\/aws-runas-testing\//}
    end

    describe command ("aws-runas -vl #{params} #{profile}") do
      its(:exit_status) { should_not eq 0 }
      its(:stdout) { should_not match /^Available role ARNs for/ }
      its(:stderr) { should match /\s+detected Web Identity profile, only IAM and SAML profiles support role enumeration$/ }
    end
end