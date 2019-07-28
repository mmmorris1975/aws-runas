require 'serverspec'

set :backend, :exec
set :path, 'build:$PATH'

ENV['AWS_CONFIG_FILE']='.aws/config'

ENV.delete('AWS_ACCESS_KEY_ID')
ENV.delete('AWS_SECRET_ACCESS_KEY')