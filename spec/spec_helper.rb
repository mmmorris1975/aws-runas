require 'serverspec'

set :backend, :exec
set :path, 'build:$PATH'

ENV['AWS_CONFIG_FILE']='.aws/config'
ENV['AWS_REGION'] = 'us-east-2'