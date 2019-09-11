require 'serverspec'

set :backend, :exec
set :path, 'build:$PATH'

ENV['AWS_CONFIG_FILE']='.aws/config'

print ENV['AWS_ACCESS_KEY_ID']