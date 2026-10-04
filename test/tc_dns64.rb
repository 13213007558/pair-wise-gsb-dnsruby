require_relative 'spec_helper'

# Tests for the optional DNS64 synthesis layer (RFC 6147 / RFC 6052)
class TestDNS64 < Minitest::Test

  include Dnsruby

  #  A fake upstream resolver: records the queries it receives and
  #  replies with canned responses registered per (name, type).
  class FakeUpstream
    attr_reader :queries

    def initialize
      @queries = []
      @handlers = {}
    end

    def on(name, type, &block)
      @handlers[[Dnsruby::Name.create(name).canonical, Dnsruby::Types.new(type)]] = block
    end

    def query(message)
      @queries << message
      question = message.question[0]
      handler = @handlers[[question.qname.canonical, question.qtype]]
      raise "unexpected upstream query: #{question.qname} #{question.qtype}" unless handler
      handler.call(message)
    end
  end

  def response_for(query, rcode: RCode::NOERROR, answers: [], security_level: nil, ad: false)
    msg = Message.new
    msg.header.id = query.header.id
    msg.header.qr = true
    msg.header.ra = true
    msg.header.ad = ad
    msg.header.rcode = rcode
    query.each_question { |q| msg.add_question(Question.new(q.qname, q.qtype, q.qclass)) }
    answers.each { |rr| msg.add_answer(rr) }
    msg.security_level = security_level unless security_level.nil?
    msg
  end

  def a_rr(name, address, ttl)
    RR.create(:name => name, :type => 'A', :ttl => ttl, :address => address)
  end

  def aaaa_rr(name, address, ttl)
    RR.create(:name => name, :type => 'AAAA', :ttl => ttl, :address => address)
  end

  def cname_rr(name, target, ttl)
    RR.create(:name => name, :type => 'CNAME', :ttl => ttl, :domainname => target)
  end

  #  A NODATA AAAA response plus a matching A response for the same name
  def nodata_upstream(a_answers: [], a_rcode: RCode::NOERROR, a_security: nil, name: 'ipv4-only.example.com')
    upstream = FakeUpstream.new
    upstream.on(name, 'AAAA') { |q| response_for(q) }
    upstream.on(name, 'A') { |q| response_for(q, :rcode => a_rcode, :answers => a_answers, :security_level => a_security) }
    upstream
  end

  # --- RFC 6052 prefix handling -------------------------------------

  def test_well_known_prefix_example
    prefix = DNS64::Prefix.new('64:ff9b::/96')
    assert_equal('64:ff9b::c000:221', prefix.synthesize(IPv4.create('192.0.2.33')).to_s)
  end

  def test_well_known_prefix_constant
    assert_equal('64:ff9b::/96', DNS64::Prefix::WELL_KNOWN.to_s)
  end

  def test_all_rfc6052_prefix_lengths
    v4 = IPv4.create('192.0.2.33')
    assert_equal('2001:db8:c000:221::', DNS64::Prefix.new('2001:db8::/32').synthesize(v4).to_s)
    assert_equal('2001:db8:1c0:2:21::', DNS64::Prefix.new('2001:db8:100::/40').synthesize(v4).to_s)
    assert_equal('2001:db8:1234:c000:2:2100::', DNS64::Prefix.new('2001:db8:1234::/48').synthesize(v4).to_s)
    assert_equal('2001:db8:1234:abc0:0:221::', DNS64::Prefix.new('2001:db8:1234:ab00::/56').synthesize(v4).to_s)
    assert_equal('2001:db8:1234:abcd:c0:2:2100:0', DNS64::Prefix.new('2001:db8:1234:abcd::/64').synthesize(v4).to_s)
    assert_equal('64:ff9b::c000:221', DNS64::Prefix.new('64:ff9b::/96').synthesize(v4).to_s)
  end

  def test_u_octet_kept_zero
    #  Bits 64-71 must remain zero even when the IPv4 octets wrap around them
    v4 = IPv4.create('255.255.255.255')
    assert_equal('2001:db8:1234:abff:ff:ffff::', DNS64::Prefix.new('2001:db8:1234:ab00::/56').synthesize(v4).to_s)
  end

  def test_unsupported_prefix_length_rejected
    assert_raises(ArgumentError) { DNS64::Prefix.new('64:ff9b::/24') }
    assert_raises(ArgumentError) { DNS64::Prefix.new('64:ff9b::/128') }
    assert_raises(ArgumentError) { DNS64::Prefix.new('not-a-prefix') }
  end

  def test_prefix_bits_beyond_length_masked
    assert_equal('64:ff9b::/96', DNS64::Prefix.new('64:ff9b::c000:221/96').to_s)
  end

  # --- Pass-through behaviour ----------------------------------------

  def test_existing_aaaa_response_kept_untouched
    upstream = FakeUpstream.new
    original = nil
    upstream.on('dual.example.com', 'AAAA') do |q|
      original = response_for(q, :answers => [aaaa_rr('dual.example.com', '2001:db8::5', 300)])
      original
    end
    dns64 = DNS64::Resolver.new(:upstream => upstream)
    response = dns64.resolve('dual.example.com')
    assert_same(original, response)
    assert_equal(['AAAA'], upstream.queries.map { |q| q.question[0].qtype.to_s })
  end

  def test_nxdomain_passed_through
    upstream = FakeUpstream.new
    upstream.on('missing.example.com', 'AAAA') { |q| response_for(q, :rcode => RCode::NXDOMAIN) }
    dns64 = DNS64::Resolver.new(:upstream => upstream)
    response = dns64.resolve('missing.example.com')
    assert_equal(RCode::NXDOMAIN, response.rcode)
    assert_equal(1, upstream.queries.length)
  end

  def test_nodata_without_a_records_returns_original
    upstream = nodata_upstream(:a_answers => [])
    dns64 = DNS64::Resolver.new(:upstream => upstream)
    response = dns64.resolve('ipv4-only.example.com')
    assert_equal(RCode::NOERROR, response.rcode)
    assert_equal(0, response.answer.length)
  end

  # --- Synthesis ------------------------------------------------------

  def test_synthesis_from_a_records
    upstream = nodata_upstream(:a_answers => [
      a_rr('ipv4-only.example.com', '192.0.2.33', 300),
      a_rr('ipv4-only.example.com', '192.0.2.34', 120)
    ])
    dns64 = DNS64::Resolver.new(:upstream => upstream)
    response = dns64.resolve('ipv4-only.example.com')

    assert_equal(RCode::NOERROR, response.rcode)
    addresses = response.answer.map { |rr| rr.address.to_s }
    assert_equal(['64:ff9b::c000:221', '64:ff9b::c000:222'], addresses)
    #  TTL is the minimum of the constituent A record TTLs
    assert_equal([120, 120], response.answer.map(&:ttl))
    #  The question section is preserved
    question = response.question[0]
    assert_equal('ipv4-only.example.com.', question.qname.to_s(true))
    assert_equal(Types::AAAA, question.qtype)
  end

  def test_synthesis_uses_configured_prefix
    upstream = nodata_upstream(:a_answers => [a_rr('ipv4-only.example.com', '192.0.2.33', 60)])
    dns64 = DNS64::Resolver.new(:upstream => upstream, :prefix => '2001:db8:1234:abcd::/64')
    response = dns64.resolve('ipv4-only.example.com')
    assert_equal('2001:db8:1234:abcd:c0:2:2100:0', response.answer[0].address.to_s)
  end

  def test_max_ttl_caps_synthetic_records
    upstream = nodata_upstream(:a_answers => [a_rr('ipv4-only.example.com', '192.0.2.33', 3600)])
    dns64 = DNS64::Resolver.new(:upstream => upstream, :max_ttl => 300)
    response = dns64.resolve('ipv4-only.example.com')
    assert_equal(300, response.answer[0].ttl)
  end

  def test_cname_chain_followed
    upstream = FakeUpstream.new
    upstream.on('www.example.com', 'AAAA') { |q| response_for(q) }
    upstream.on('www.example.com', 'A') do |q|
      response_for(q, :answers => [
        cname_rr('www.example.com', 'cdn.example.net', 60),
        a_rr('cdn.example.net', '203.0.113.7', 45)
      ])
    end
    dns64 = DNS64::Resolver.new(:upstream => upstream)
    response = dns64.resolve('www.example.com')

    assert_equal(2, response.answer.length)
    cname, aaaa = response.answer.to_a
    assert_equal(Types::CNAME, cname.type)
    assert_equal('cdn.example.net', cname.domainname.to_s)
    assert_equal(Types::AAAA, aaaa.type)
    assert_equal('cdn.example.net', aaaa.name.to_s)
    assert_equal('64:ff9b::cb00:7107', aaaa.address.to_s)
    assert_equal(45, aaaa.ttl)
  end

  def test_callable_upstream
    upstream = nodata_upstream(:a_answers => [a_rr('ipv4-only.example.com', '192.0.2.33', 60)])
    callable = ->(message) { upstream.query(message) }
    dns64 = DNS64::Resolver.new(:upstream => callable)
    response = dns64.resolve('ipv4-only.example.com')
    assert_equal('64:ff9b::c000:221', response.answer[0].address.to_s)
  end

  # --- Policy ----------------------------------------------------------

  def test_deny_all_policy_forbids_synthesis
    upstream = nodata_upstream(:a_answers => [a_rr('ipv4-only.example.com', '192.0.2.33', 60)])
    dns64 = DNS64::Resolver.new(:upstream => upstream, :policy => DNS64::Policy::DENY_ALL)
    response = dns64.resolve('ipv4-only.example.com')
    assert_equal(RCode::NOERROR, response.rcode)
    assert_equal(0, response.answer.length)
    #  The A query is never issued when the policy forbids synthesis
    assert_equal(['AAAA'], upstream.queries.map { |q| q.question[0].qtype.to_s })
  end

  def test_exclude_ipv4_ranges_policy
    policy = DNS64::Policy::ExcludeIPv4Ranges.new('192.0.2.0/24', '10.0.0.0/8')
    upstream = nodata_upstream(:a_answers => [a_rr('ipv4-only.example.com', '192.0.2.33', 60)])
    dns64 = DNS64::Resolver.new(:upstream => upstream, :policy => policy)
    response = dns64.resolve('ipv4-only.example.com')
    assert_equal(0, response.answer.length)

    #  An address outside the excluded ranges is still synthesized
    upstream2 = nodata_upstream(:a_answers => [a_rr('ipv4-only.example.com', '203.0.113.9', 60)])
    dns64_2 = DNS64::Resolver.new(:upstream => upstream2, :policy => policy)
    response2 = dns64_2.resolve('ipv4-only.example.com')
    assert_equal('64:ff9b::cb00:7109', response2.answer[0].address.to_s)
  end

  # --- DNSSEC: DO, CD and validated data -------------------------------

  def test_do_bit_propagated_to_upstream_queries
    upstream = nodata_upstream(:a_answers => [a_rr('ipv4-only.example.com', '192.0.2.33', 60)])
    dns64 = DNS64::Resolver.new(:upstream => upstream)
    dns64.resolve('ipv4-only.example.com', :do_bit => true)
    upstream.queries.each do |q|
      opt = q.get_opt
      refute_nil(opt)
      assert(opt.dnssec_ok)
    end
  end

  def test_bogus_validated_a_yields_servfail_when_cd_clear
    upstream = nodata_upstream(
      :a_answers => [a_rr('ipv4-only.example.com', '192.0.2.33', 60)],
      :a_security => Message::SecurityLevel::BOGUS)
    dns64 = DNS64::Resolver.new(:upstream => upstream)
    response = dns64.resolve('ipv4-only.example.com', :do_bit => true, :cd => false)
    assert_equal(RCode::SERVFAIL, response.rcode)
    assert_equal(0, response.answer.length)
  end

  def test_bogus_a_synthesized_when_cd_set
    upstream = nodata_upstream(
      :a_answers => [a_rr('ipv4-only.example.com', '192.0.2.33', 60)],
      :a_security => Message::SecurityLevel::BOGUS)
    dns64 = DNS64::Resolver.new(:upstream => upstream)
    response = dns64.resolve('ipv4-only.example.com', :do_bit => true, :cd => true)
    assert_equal(RCode::NOERROR, response.rcode)
    assert_equal('64:ff9b::c000:221', response.answer[0].address.to_s)
  end

  def test_synthesized_response_never_claims_original_security
    upstream = nodata_upstream(
      :a_answers => [a_rr('ipv4-only.example.com', '192.0.2.33', 60)],
      :a_security => Message::SecurityLevel::SECURE)
    dns64 = DNS64::Resolver.new(:upstream => upstream)
    response = dns64.resolve('ipv4-only.example.com', :do_bit => true)

    #  Synthetic records carry no original signature: AD stays clear and
    #  the message is not reported as SECURE.
    assert_equal(false, response.header.ad)
    assert_equal(Message::SecurityLevel::UNCHECKED, response.security_level)
    assert(response.answer.none? { |rr| rr.type == Types::RRSIG })
  end
end
