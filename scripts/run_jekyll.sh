#!/usr/bin/env bash
set -eo pipefail

cd docs

if [ -d vendor/cache ]
then
  bundle install --local || bundle install
else
  bundle install && bundle cache
fi

bundle exec jekyll build
bundle exec jekyll serve -H 0.0.0.0 $@