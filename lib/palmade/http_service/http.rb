# -*- coding: utf-8 -*-
# encoding: utf-8

require 'uri'
require 'cgi'
require 'net/http'

module Palmade::HttpService
  # this HTTP library, will use HTTP 1.1 by default!
  module Http
    DEFAULT_HEADERS = { 'Connection' => 'Close' }

    class HttpError < StandardError
      attr_reader :response

      def initialize(msg = nil, response = nil)
        super(msg)
        @response = response
      end

      def http_error?
        true
      end
    end

    def self.use_curb?
      if defined?(@@use_curb)
        @@use_curb
      elsif defined?(::Curl) && defined?(::Curl::Easy)
        @@use_curb = true
      else
        @@use_curb = false
      end

      @@use_curb
    end

    def self.json_encode(obj = nil, &block)
      if defined?(::Yajl) && defined?(::Yajl::Encoder)
        ::Yajl::Encoder.encode(block_given? ? block.call : obj)
      elsif defined?(::JSON)
        ::JSON.encode(block_given? ? block.call : obj)
      else
        raise "Yajl or JSON not defined. Please fix!"
      end
    end

    def self.json_parse(buf = nil, &block)
      if defined?(::Yajl) && defined?(::Yajl::Parser)
        ::Yajl::Parser.parse(block_given? ? block.call : buf)
      elsif defined?(::JSON)
        ::JSON.parse(block_given? ? block.call : buf)
      else
        raise "Yajl or JSON not defined. Please fix!"
      end
    end

    def self.xml_parse(bd = nil, options = { }, &block)
      if defined?(::LibXML)
        bd = block_given? ? block.call : bd

        xml_p = LibXML::XML::Parser.io(bd, options)
        xml_p.context.disable_cdata = true
        xml_p.parse
      else
        raise "LibXML not defined. Please fix!"
      end
    end

    # Call this method, to load the curb_request proxy
    # found on OAuth's gem. Also, loads a patch to a bug as of
    # OAuth v.0.4.1
    def self.use_oauth
      if defined?(OAuth)
        unless defined?(OAuth::RequestProxy::Curl::Easy)
          require 'oauth/request_proxy/curb_request.rb'
        end

        # just load our own class
        Palmade::HttpService::Patches::CurbRequest
      else
        raise "OAuth not defined. Please fix!"
      end
    end

    class Response
      attr_accessor :body, :size, :code, :message
      alias :status :message

      def initialize(body, size, code, message, headers = { })
        @body = body
        @size = size

        @code = code.to_i
        @message = message
        @headers = headers

        if @body.respond_to?(:set_encoding) && !content_charset.nil?
          @body.set_encoding(Encoding.find(content_charset) || 'BINARY')
        end
      end
      def http_response?; true; end

      def headers
        if @headers.is_a?(Hash)
          @headers
        else
          @headers = Palmade::HttpService::Http.parse_header_str(@headers)
        end
      end

      def method_missing(name, *args, &block)
        @body.send(name, *args, &block)
      end

      def raise_http_error
        raise HttpError.new("Http failed #{@code} #{@message}", self)
      end

      def success?
        @code == 200
      end
      alias :success :success?

      def fail?
        !success?
      end

      def read
        @body.read
      end

      def json_read
        Palmade::HttpService::Http.json_parse { @body.rewind; @body.read }
      end

      def xml_read(options = { })
        Palmade::HttpService::Http.xml_parse { @body.rewind; @body }
      end

      def to_s
        "HTTP #{@code} #{message}".strip
      end

      def last_modified
        if defined?(@last_modified)
          @last_modified
        else
          if headers.include?('Last-Modified')
            @last_modified = headers['Last-Modified'].to_time
          else
            @last_modified = nil
          end
        end
      end

      def content_length
        if defined?(@content_length)
          @content_length
        else
          if headers.include?('Content-Length')
            if headers['Content-Length'].is_a?(Array)
              @content_length = headers['Content-Length'].first.to_i
            else
              @content_length = headers['Content-Length'].to_i
            end
          else
            @content_length = nil
          end
        end
      end

      def content_type
        if defined?(@content_type)
          @content_type
        else
          if headers.include?('Content-Type')
            @content_type = headers['Content-Type']
          else
            @content_type = nil
          end
        end
      end

      def media_type
        if defined?(@media_type)
          @media_type
        else
          if content_type
            @media_type = content_type.split(/\s*[;,]\s*/, 2).first.downcase
          else
            @media_type = nil
          end
        end
      end

      def media_type_params
        if defined?(@media_type_params)
          @media_type_params
        else
          if content_type
            @media_type_params = content_type.split(/\s*[;,]\s*/)[1..-1].
              collect { |s| s.split('=', 2) }.
              inject({ }) { |hash,(k,v)| hash[k.downcase] = v ; hash }
          else
            @media_type_params = { }
          end
        end
      end

      def content_charset
        if defined?(@content_charset)
          @content_charset
        else
          @content_charset = media_type_params['charset']
        end
      end
    end

    def self.get_json(uri, options = { }, &block)
      resp_json = nil
      resp = get(uri, nil, options, &block)
      unless resp.nil?
        if resp.success?
          resp_json = resp.json_parse
        end
      end
      resp_json
    end

    def self.put_json(uri, obj, options = { }, &block)
      put(uri, json_encode(obj), options, &block)
    end

    def self.get_yaml(uri, options = { }, &block)
      resp_yaml = nil
      resp = get(uri, nil, options, &block)
      unless resp.nil?
        if resp.success?
          resp_yaml = YAML.load(resp.read)
        end
      end
      resp_yaml
    end

    def self.put_yaml(uri, obj, options = { }, &block)
      put(uri, YAML.dump(obj), options, &block)
    end

    def self.get(uri, io = nil, options = { }, &block)
      make_request(:get, uri, io, options, &block)
    end

    def self.post(uri, query = { }, io = nil, options = { }, &block)
      options = { }.merge(options)

      options[:query] = query
      make_request(:post, uri, io, options, &block)
    end

    def self.head(uri, options = { }, &block)
      make_request(:head, uri, nil, options, &block)
    end

    def self.delete(uri, options = { }, &block)
      make_request(:delete, uri, nil, options, &block)
    end

    def self.put(uri, value, options = { }, &block)
      options = { }.merge(options)

      options[:body] = value
      make_request(:put, uri, nil, options, &block)
    end

    def self.put_io(uri, io, size, options = { }, &block)
      options = { }.merge(options)

      options[:body] = io
      options[:headers] ||= { }
      options[:headers]["Content-Length"] = size.to_s

      make_request(:put, uri, nil, options, &block)
    end

    def self.make_oauth_authorization(meth, uri, options = { })
      uri = URI.parse(uri) unless uri.is_a?(URI)

      verb = nil
      case meth
      when :get
        verb = ::Net::HTTP::Get
      when :post
        verb = ::Net::HTTP::Post
      when :put
        verb = ::Net::HTTP::Put
      when :delete
        verb = ::Net::HTTP::Delete
      when :head
        verb = ::Net::HTTP::Head
      else
        raise "Unknown or unsupported HTTP method: #{meth}"
      end

      # let's create the request object
      r = verb.new(uri.request_uri)

      # let's set form data, if this is a POST and includes a query data
      if verb == ::Net::HTTP::Post &&
          options.include?(:query)
        r.set_form_data(options[:query])
      end

      if options.include?(:headers)
        r.initialize_http_header(options[:headers])
      end

      oauth_params = options[:oauth_params] || { }
      oauth_authorization(r,
                          options[:oauth_consumer],
                          options[:oauth_token],
                          meth,
                          uri,
                          oauth_params)
    end

    def self.oauth_authorization(r, consumer, token, meth, uri, oauth_params = { })
      oauth_helper = OAuth::Client::Helper.new(r,
                                               { :http_method => meth.to_s.upcase,
                                                 :consumer => consumer,
                                                 :token => token,
                                                 :request_uri => uri.to_s }.merge(oauth_params))

      oauth_helper.header
    end

    def self.make_request(meth, uri, io, options = { }, &block)
      if use_curb?
        make_curb_request(meth, uri, io, options, &block)
      else
        make_builtin_request(meth, uri, io, options, &block)
      end
    end

    def self.make_curb_request(meth, uri, io, options = { }, &block)
      uri = URI.parse(uri) unless uri.is_a?(URI)
      options = prepare_options(options)

      c = Curl::Easy.new(uri.to_s)
      c.ssl_verify_peer = false

      block.call(:init, c, uri, options) if block_given?

      # set proxy settings, for this connection
      if options.include?(:http_proxyaddr)
        proxy_addr = options[:http_proxyaddr]
        proxy_port = options[:http_proxyport] || 8080

        c.proxy_url = "#{proxy_addr}:#{proxy_port}"
      end

      # set some cookie
      if options[:headers].include?(:cookie)
        c.cookies = options[:headers][:cookie]
        options[:headers].delete(:cookie)
      end

      if options.include?(:charset_encoding)
        charset_encoding = options[:charset_encoding]
      else
        charset_encoding = nil
      end

      # set form post
      # TODO: support multipart post data (e.g. uploading files via POST)
      if meth == :post && options.include?(:query)
        pb = convert_to_post_data(options[:query])

        unless options[:headers].include?("Content-Type")
          if !charset_encoding.nil?
            post_encoding = charset_encoding
            pb.force_encoding(Encoding.find(charset_encoding)) if pb.respond_to?(:force_encoding)
          elsif pb.respond_to?(:encoding)
            post_encoding = pb.encoding.name
          else
            post_encoding = 'ISO-8859-1'
          end

          options[:headers]["Content-Type"] = "application/x-www-form-urlencoded; charset=#{post_encoding}"
        end

        c.post_body = pb
      else
        pb = nil
      end

      # set request BODY
      bdstream = nil
      case
      when options[:body].nil?
        # do nothing
      when options[:body].is_a?(Hash)
        # body is assumed to be a hash of form data
        bdstream = convert_to_post_data(options[:body])
      when options[:body].respond_to?(:read)
        bdstream = options[:body]

        # let's convert it back to string, since
        # curb tries to interpret it as a file by default
        # if it responds to the read method
        if bdstream.is_a?(StringIO)
          bdstream.rewind
          bdstream = bdstream.read
        end
      else
        # the body is assumed to be already formatted
        # as a post form data
        bdstream = options[:body].to_s
      end

      # setup Content-Length, if needed
      unless bdstream.nil?
        unless options[:headers].include?("Content-Length")
          if bdstream.respond_to?(:length)
            options[:headers]["Content-Length"] = bdstream.length.to_s
          elsif bdstream.respond_to?(:size)
            options[:headers]["Content-Length"] = bdstream.size.to_s
          elsif bdstream.respond_to?(:stat)
            options[:headers]["Content-Length"] = bdstream.stat.size.to_s
          else
            raise ArgumentError, "Please specify the Content-Length"
          end
        end
      end

      # let's setup the headers
      c.headers = DEFAULT_HEADERS.merge(options[:headers])

      unless options[:headers].include?("Authorization")
        # setup basic auth
        if options.include?(:basic_auth)
          case options[:basic_auth]
          when Hash
            c.userpwd = "#{options[:basic_auth][:username]}:#{options[:basic_auth][:password]}"
          when Array
            c.userpwd = "#{options[:basic_auth][0]}:#{options[:basic_auth][1]}"
          else
            c.userpwd = "#{options[:basic_auth]}"
          end

        # add oauth authorization key
        elsif options.include?(:oauth_consumer) &&
            options.include?(:oauth_token)

          oauth_params = options[:oauth_params] || { }
          c.headers["Authorization"] = oauth_authorization(c,
                                                           options[:oauth_consumer],
                                                           options[:oauth_token],
                                                           meth,
                                                           uri,
                                                           oauth_params)
        end
      end

      block.call(:start, c, uri, options) if block_given?

      bd = io.nil? ? StringIO.new : io
      bd.set_encoding('BINARY') if bd.respond_to?(:set_encoding)

      recvd = 0
      if block_given?
        c.on_body do |s|
          wrtn = block.call(:segment, s, c, uri, options)
          wrtn = 0 if wrtn.nil?

          unless s.nil? || s.empty?
            wrtn = bd.write(s) if wrtn == 0
            recvd += wrtn
          end
          wrtn
        end
      else
        c.on_body do |s|
          wrtn = 0
          unless s.nil? || s.empty?
            wrtn = bd.write(s)
            recvd += wrtn
          end
          wrtn
        end
      end

      case meth
      when :get
        c.http_get
      when :post
        c.http_post(pb)
      when :put
        c.http_put(bdstream)
      when :delete
        c.http_delete
      when :head
        c.http_head
      else
        raise "Unknown or unsupported HTTP method: #{meth}"
      end

      bd.rewind # rewind our respond body

      # let's get the headers
      headers = parse_header_str(c.header_str)

      # get response
      block.call(:respond, bd, recvd, headers, c, uri, options) if block_given?

      Response.new(bd, recvd, c.response_code, "", headers)
    end

    def self.make_builtin_request(meth, uri, io, options = { }, &block)
      uri = URI.parse(uri) unless uri.is_a?(URI)
      options = prepare_options(options)

      # let's build up the request object
      http = ::Net::HTTP.new(uri.host, uri.port, options[:http_proxyaddr], options[:http_proxyport])

      # let's enable SSL support, if applicable
      if uri.port == 443
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end

      verb = nil
      case meth
      when :get
        verb = ::Net::HTTP::Get
      when :post
        verb = ::Net::HTTP::Post
      when :put
        verb = ::Net::HTTP::Put
      when :delete
        verb = ::Net::HTTP::Delete
      when :head
        verb = ::Net::HTTP::Head
      else
        raise "Unknown or unsupported HTTP method: #{meth}"
      end

      request = verb.new(uri.request_uri)

      block.call(:init, request, http, uri, options) if block_given?

      # let's set form data, if this is a POST and includes a query data
      if verb == ::Net::HTTP::Post &&
          options.include?(:query)
        request.set_form_data(options[:query])
      end

      # setup body, if needed
      # NOTE: this will override the POST query above, if specified
      bdstream = nil
      case
      when options[:body].nil?
        # do nothing
      when options[:body].is_a?(Hash)
        request.body = convert_to_post_data(options[:body])
      when options[:body].respond_to?(:read)
        bdstream = options[:body]
        request.body_stream = bdstream
      else
        request.body = options[:body].to_s
      end

      # setup Content-Length, if needed
      unless options[:body].nil?
        unless options[:headers].include?("Content-Length")
          if options[:body].respond_to?(:length)
            options[:headers]["Content-Length"] = options[:body].length.to_s
          elsif options[:body].respond_to?(:size)
            options[:headers]["Content-Length"] = options[:body].size.to_s
          else
            raise ArgumentError, "Please specify the Content-Length"
          end
        end
      end

      # setup basic auth
      if options.include?(:basic_auth)
        case options[:basic_auth]
        when Hash
          request.basic_auth(options[:basic_auth][:username], options[:basic_auth][:password])
        when Array
          request.basic_auth(options[:basic_auth][0], options[:basic_auth][1])
        else
          request.basic_auth(*options[:basic_auth].split(":", 2))
        end
      end

      # setup HTTP headers
      request.initialize_http_header(options[:headers])

      # send request
      block.call(:start, request, http, uri, options) if block_given?
      response = nil

      recvd = 0
      bd = io || StringIO.new

      slow_down_evm do
        http.start do |h|
          response = h.request(request) do |r|
            r.read_body do |s|
              wrtn = 0
              if block_given?
                wrtn = block.call(:segment, s, r, request, h, uri, options)
                wrtn = 0 if wrtn.nil_or_empty?
              end

              wrtn = bd.write(s) if wrtn == 0
              recvd += wrtn
            end
          end
        end
      end

      bd.rewind # let's rewind

      # get response
      block.call(:respond, bd, recvd, response, request, http, uri, options) if block_given?

      Response.new(bd, recvd, response.code, response.message, response.to_hash)
    end

    def self.prepare_options(passed_opt)
      options = passed_opt.nil? ? { } : { }.merge(passed_opt)
      options[:headers] ||= { }

      unless options[:headers].include?(:cookie)
        if options.include?(:cookies)
          options[:headers][:cookie] = convert_to_cookie_string(options[:cookies])
          options.delete(:cookies)
        end
      end

      options
    end

    def self.query_string(params, sep = '&')
      convert_to_post_data(params, sep)
    end

    def self.convert_to_post_data(params, sep = '&')
      params.map { |k,v| "#{escape(k.to_s)}=#{escape(v.to_s)}" }.join(sep)
    end

    def self.convert_to_cookie_string(cookies)
      cookies.collect { |k, v| "#{k}=#{v}" }.join("; ")
    end

    def self.urlencode(s)
      escape(s)
    end

    def self.urldecode(s)
      unescape(s)
    end

    def self.slow_down_evm(&block)
      working = true
      sleeper = lambda do
        if working
          sleep(0.1) # default tick in EV is 90 milliseconds (0.09)
          EventMachine.next_tick(&sleeper)
        end
      end

      if defined?(EventMachine) && EventMachine.reactor_running? &&
          !EventMachine.reactor_thread?
        begin
          EventMachine.next_tick(&sleeper)
          yield
        ensure
          working = false
        end
      else
        yield
      end
    end

    # TODO: Investigate why OAuth uses a special code to encode
    # params, while Rack uses a different one!
    #
    # These two were stolen from OAuth, for some reason OAuth
    # signature uses a different encoding scheme, that produces a
    # different signature if we don't use this one. So for now, let's
    # just use this one.
    def self.escape(s)
      CGI.escape(s.to_s).gsub("%7E", '~').gsub("+", "%20")
    end

    def self.unescape(s)
      URI.unescape(s.gsub('+', '%2B'))
    end

    # # I ALSO STOLE these from Rack::Utils
    # # Performs URI escaping so that you can construct proper
    # # query strings faster.  Use this rather than the cgi.rb
    # # version since it's faster.  (Stolen from Camping).
    # def self.escape(s)
    #   s.to_s.gsub(/([^ a-zA-Z0-9_.-]+)/n) {
    #     '%'+$1.unpack('H2'*bytesize($1)).join('%').upcase
    #   }.tr(' ', '+')
    # end

    # # Unescapes a URI escaped string. (Stolen from Camping).
    # def self.unescape(s)
    #   s.tr('+', ' ').gsub(/((?:%[0-9a-fA-F]{2})+)/n){
    #     [$1.delete('%')].pack('H*')
    #   }
    # end

    # # Return the bytesize of String; uses String#length under Ruby 1.8 and
    # # String#bytesize under 1.9.
    # if ''.respond_to?(:bytesize)
    #   def self.bytesize(string)
    #     string.bytesize
    #   end
    # else
    #   def self.bytesize(string)
    #     string.size
    #   end
    # end

    def self.parse_header_str(head_str)
      headers = { }

      header_lines = head_str.split("\n").collect { |l| l.sub(/\s+\z/, '') }
      header_lines.each do |l|
        break if l.empty?

        if m = /\A([^:]+):\s*/.match(l)
          # header key: m[1]
          # header val: m.post_match

          k = m[1]
          v = m.post_match

          if headers.include?(k)
            if headers[k].is_a?(Array)
              headers[k].push(v)
            else
              headers[k] = [ headers[k], v ]
            end
          else
            headers[k] = v
          end
        end
      end

      headers
    end
  end
end
