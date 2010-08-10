class ServiceTest < Test::Unit::TestCase
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

  def test_service_get
    svc = Palmade::HttpService::Service.new('http://simpleteq.com')
    r = svc.get('/')
    assert(r.code == 200, "Service did not returned a HTTP 200 OK, returned #{r.code}")
  end
end
