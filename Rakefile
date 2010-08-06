require 'rubygems'
gem 'echoe'
require 'echoe'

Echoe.new("http_service") do |p|
  p.author="markjeee"
  p.project = "palmade"
  p.summary = "HTTP Service"

  p.dependencies = [ ]

  p.need_tar_gz = false
  p.need_tgz = true

  p.clean_pattern += [ "pkg", "lib/*.bundle", "*.gem", ".config" ]
  p.rdoc_pattern = [ 'README', 'LICENSE', 'COPYING', 'lib/**/*.rb', 'doc/**/*.rdoc' ]
end

task :test do

end

task :default => :test
