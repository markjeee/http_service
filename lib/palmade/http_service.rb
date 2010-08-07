HTTP_SERVICE_LIB_DIR = File.dirname(__FILE__) unless defined?(HTTP_SERVICE_LIB_DIR)
HTTP_SERVICE_ROOT_DIR = File.join(HTTP_SERVICE_LIB_DIR, '../..') unless defined?(HTTP_SERVICE_ROOT_DIR)

require 'rubygems'
require 'logger'

module Palmade
  module HttpService
    def self.logger; @logger; end
    def self.logger=(l); @logger = l; end

    autoload :Http, File.join(HTTP_SERVICE_LIB_DIR, 'http_service/http')
    autoload :Service, File.join(HTTP_SERVICE_LIB_DIR, 'http_service/service')
    autoload :Utils, File.join(HTTP_SERVICE_LIB_DIR, 'http_service/utils')
    autoload :Patches, File.join(HTTP_SERVICE_LIB_DIR, 'http_service/patches')
  end
end
