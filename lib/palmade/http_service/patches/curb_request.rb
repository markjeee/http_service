# -*- coding: utf-8 -*-
# encoding: utf-8

module Palmade::HttpService
  module Patches
    # This is a patch to OAuth's default Curl::Easy proxy code.
    # As of version, v0.4.1, it's not getting the request method,
    # since Curb::Easy don't set the method until it's time to perform
    # it. So, it's almost impossible to determine the HTTP method just
    # by the Curl::Easy object. I added a specific option (you pass it
    # with the Curl::Client::Helper.new method), :http_method, that
    # will be used as sort of an override, just in case the method
    # can't be retrieved. The mixin CurbRequest below then factors this in.
    #
    # Another fix is the post parameters, if the keys and value are
    # individually escaped, the re-parsing don't unescape
    # them. Unescaping is necessary here to properly produce the
    # correct signature base string.
    class CurbRequest < OAuth::RequestProxy::Curl::Easy
      proxies ::Curl::Easy

      def method
        options[:http_method] || 'GET'
      end

      def content_type
        if request.headers.include?('Content-Type')
          request.headers['Content-Type'].split(/\s*[;,]\s*/, 2).first.downcase
        else
          nil
        end
      end

      def post_parameters
        post_body = { }
        # Post params are only used if posting form data
        if content_type == 'application/x-www-form-urlencoded'
          request.post_body.split("&").each do |str|
            param = str.split("=")
            post_body[unescape(param[0])] = unescape(param[1])
          end
        end
        post_body
      end
    end
  end
end
