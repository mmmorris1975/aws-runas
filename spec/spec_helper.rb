require 'serverspec'

set :backend, :exec
set :path, 'build:$PATH'

ENV['AWS_CONFIG_FILE'] = 'testdata/aws_config'

$config_path = Pathname(ENV['HOME']).join(".aws")
$config_path = Pathname(ENV['AWS_CONFIG_FILE']).dirname() if ENV.has_key?('AWS_CONFIG_FILE')