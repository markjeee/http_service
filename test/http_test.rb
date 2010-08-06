class HttpTest < Test::Unit::TestCase
  def setup
  end

  def teardown
  end

  def test_class_load
    Palmade::HttpService
    Palmade::HttpService::Http
    Palmade::HttpService::Service
    Palmade::HttpService::Utils
  end

  def test_via_curb
    assert(Palmade::HttpService::Http.use_curb?, "Curb not loaded, and is preferred")
  end

  def test_via_yajl
    assert(defined?(::Yajl), "Yajl gem not loaded or defined")
    assert(Yajl::Parser.parse("\"ok\"") == "ok", "Yajl test ok parse failed")
  end

  def test_http_get
    resp = Palmade::HttpService::Http.get('http://simpleteq.com')
    assert_kind_of(StringIO, resp)
  end

  def test_twitter_api
    resp = Palmade::HttpService::Http.get('http://api.twitter.com/1/help/test.json')
    assert_kind_of(StringIO, resp)

    resp_s = resp.json_read
    assert(resp_s == "ok", "expecting 'ok', got '#{resp_s}' instead")
  end
end
