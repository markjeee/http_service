require 'pp'
require 'rubygems'
require 'test/unit'

gem 'curb'
require 'curb'

gem 'yajl-ruby'
require 'yajl'

# let's load http_service
require File.expand_path(File.join(File.dirname(__FILE__), '../lib/palmade/http_service.rb'))
