module Palmade::HttpService
  module Patches
    autoload :CurbRequest, File.join(HTTP_SERVICE_LIB_DIR, 'http_service/patches/curb_request')
  end
end
