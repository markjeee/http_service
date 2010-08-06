require 'uri'

module Palmade::HttpService
  class Service
    class Response < Palmade::HttpService::Http::Response; end
    class UnsupportedScheme < StandardError; end

    DEFAULT_HEADERS = {
      'Connection' => 'Keep-Alive',
      'Keep-Alive' => '300'
    }

    attr_reader :http
    attr_reader :logger
    attr_reader :headers
    attr_reader :base_url

    attr_writer :log_activity
    def log_activity(&block)
      if block_given?
        yield if log_activity?
      else
        !logger.nil? && defined?(@log_activity) && @log_activity
      end
    end
    alias :log_activity? :log_activity

    def initialize(root_url, logger)
      if root_url.is_a?(URI)
        u = root_url
      else
        u = URI.parse(root_url)
      end

      if [ 443, 80 ].include?(u.port)
        @base_url = "#{u.scheme}://#{u.host}"
      else
        @base_url = "#{u.scheme}://#{u.host}:#{u.port}"
      end

      @http = Curl::Easy.new
      @http.ssl_verify_peer = false

      # this line requires the modified curb version found at:
      # http://github.com/markjeee/curb
      @http.use_easy_perform = true

      @logger = logger
      @headers = DEFAULT_HEADERS.merge({ })
    end

    def get(path, query = nil, io = nil)
      url = URI.join(@base_url, path)
      url += "?#{query_string(query)}" unless query.nil?

      if log_activity?
        resp = nil
        rt = Benchmark.measure { resp = http_get(url, io) }
        log_response("GET", url, rt, resp) unless resp.nil?
        resp
      else
        http_get(url, io)
      end
    end

    def get_json(path, query = nil)
      resp = get(path, query, nil)
      if resp.success?
        resp.json_read
      else
        resp.raise_http_error
      end
    end

    def post(path, params = nil, query = nil, io = nil)
      url = URI.join(@base_url, path)
      url += "?#{query_string(query)}" unless query.nil?

      if log_activity?
        resp = nil
        rt = Benchmark.measure { resp = http_post(url, params, io) }
        log_response("POST", url, rt, resp) unless resp.nil?
        resp
      else
        http_post(url, params, io)
      end
    end

    def post_json(path, params = nil, query = nil)
      resp = post(path, params, query, nil)
      if resp.success?
        resp.json_read
      else
        resp.raise_http_error
      end
    end

    def put(path, data, query = nil)
      url = URI.join(@base_url, path)
      url += "?#{query_string(query)}" unless query.nil?

      if log_activity?
        resp = nil
        rt = Benchmark.measure { resp = http_put(url, data) }
        log_response("PUT", url, rt, resp) unless resp.nil?
        resp
      else
        http_put(url, data)
      end
    end

    def put_json(path, obj, query = nil)
      resp = put(path, obj, query)
      if resp.success?
        resp.json_read
      else
        resp.raise_http_error
      end
    end

    def delete(path, query = nil)
      url = URI.join(@base_url, path)
      url += "?#{query_string(query)}" unless query.nil?

      if log_activity?
        resp = nil
        rt = Benchmark.measure { resp = http_delete(url) }
        log_response("DELETE", url, rt, resp) unless resp.nil?
        resp
      else
        http_put(url)
      end
    end

    def reset
      http_reset
    end

    def basic_auth(username, password)
      auth(username, password, :basic)
    end

    protected

    def auth(username, password = nil, scheme = :basic)
      case scheme
      when :basic, 'basic'
        @http.http_auth_types = :basic
        @http.userpwd = "#{username}:#{password}"
      else
        raise UnsupportedScheme, "Unsupported auth scheme. Supports only :basic now."
      end
    end

    def query_string(params, sep = '&')
      Palmade::HttpService::Http.query_string(params, sep)
    end

    def contains_files?(params)
      params.each do |name, value|
        return true if value.kind_of? File or value.kind_of? Tempfile
      end
      return false
    end

    def convert_to_post_fields(params)
      params.collect do |name, value|
        if value.is_a? File or value.is_a? Tempfile
          Curl::PostField.file(name.to_s, value.path)
        else
          Curl::PostField.content(name.to_s, value.to_s)
        end
      end
    end

    def convert_to_post_data(params, sep = '&')
      Palmade::HttpService::Http.convert_to_post_data(params, sep)
    end

    def http_get(url, io = nil, override_headers = { })
      @http.headers = @headers.merge(override_headers)
      @http.url = url.to_s

      if io.nil?
        @http.http_get
        io = StringIO.new(@http.body_str)
        wrtn = io.size
      else
        wrtn = 0
        @http.on_body { |s| wrtn += io.write(s) }
        @http.http_get
      end
      io.rewind

      Response.new(io, wrtn, @http.response_code, "", @http.header_str)
    end

    def http_head(url, override_headers = { })
      @http.headers = @headers.merge(override_headers)
      @http.url = url.to_s

      @http.http_head
      io = StringIO.new(@http.body_str)
      wrtn = io.size
      io.rewind

      Response.new(io, wrtn, @http.response_code, "", @http.header_str)
    end

    def http_post(url, params = nil, io = nil, override_headers = { })
      @http.headers = @headers.merge(override_headers)
      @http.url = url.to_s

      unless params.nil?
        if contains_files?(params)
          @http.multipart_form_post = true
        end
        pb = convert_to_post_fields(params)
      else
        pb = []
      end

      if io.nil?
        @http.http_post(*pb)
        io = StringIO.new(@http.body_str)
        wrtn = io.size
      else
        wrtn = 0
        @http.on_body { |s| wrtn += io.write(s) }
        @http.http_post(*pb)
      end
      io.rewind

      @http.multipart_form_post = false
      Response.new(io, wrtn, @http.response_code, "", @http.header_str)
    end

    def http_put(url, data, override_headers = { })
      @http.headers = @headers.merge(override_headers)
      @http.url = url.to_s

      if data.respond_to?('read')
        req_data = data.read
      else
        req_data = data.to_s
      end

      @http.http_put(req_data)
      io = StringIO.new(@http.body_str)
      wrtn = io.size

      Response.new(io, wrtn, @http.response_code, "", @http.header_str)
    end

    def http_delete(url, override_headers = { })
      @http.headers = @headers.merge(override_headers)
      @http.url = url.to_s

      @http.http_delete
      io = StringIO.new(@http.body_str)
      wrtn = io.size

      Response.new(io, wrtn, @http.response_code, "", @http.header_str)
    end

    def http_reset
      @http.reset unless @http.nil?
    end

    def log_response(method, url, rt, resp)
      logger.debug { "  HTTP Service (#{sprintf("%.5f", rt.real)}) #{method} #{url} #{resp.code} (Headers: #{@headers.inspect})" }
    end
  end
end
