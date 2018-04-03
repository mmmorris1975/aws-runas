require 'serverspec'

set :backend, :exec
set :path, 'build:$PATH'

RSpec.configure do |config|
  config.before(:each) do
    ENV['AWS_CONFIG_FILE']='.aws/config'
  end

  config.after(:each) do
    ENV.delete('AWS_CONFIG_FILE')
  end
end
