require_relative 'spec_helper'

# Tests for the RFC 6147 DNS64 synthesis layer and the RFC 6052
# IPv4-embedded IPv6 address formats.
class TestDNS64 < Minitest::Test

  include Dnsruby

  # A fake upstream query interface: records the queries it receives and
  # replies with the canned responses it was built with.
  class FakeUpstream
    attr_reader :queries

    def initialize
      @queries = []
      @handlers = []
    end

    # Register a handler called with the query message; the first handler
    # returning a non-nil response wins.
    def on(&block)
      @handlers << block
    end

    def query(message)
      @queries << message
      @handlers.each do |handler|
        response = handler.call(message)
        return response if response
      end
      raise "FakeUpstream: no canned response for #{message.question.first}"
    end
  end

  def aaaa_query(name, do_bit = false, cd = false)
    query = Dnsruby::Message.new(name, Dnsruby::Types.AAAA)
    query.header.rd = true
    query.header.cd = cd
    if do_bit
      opt = Dnsruby::RR::OPT.new(4096)
      opt.dnssec_ok = true
      query.add_additional(opt)
    end
    query
  end

  def response_for(query, answers: [], rcode: Dnsruby::RCode.NOERROR, ad: false)
    response = Dnsruby::Message.new
    response.header.id = query.header.id
    response.header.qr = true
    response.header.ra = true
    response.header.rd = query.header.rd
    response.header.rcode = rcode
    response.header.ad = ad
    query.question.each { |question| response.add_question(question) }
    answers.each { |rr| response.add_answer(rr) }
    response
  end

  def a_record(name, address, ttl = 300)
    Dnsruby::RR.create("#{name} #{ttl} IN A #{address}")
  end

  # RFC 6052 section 2.2: all standardized prefix lengths embed the IPv4
  # address with the reserved "u" octet (bits 64-71) kept at zero.
  def test_rfc6052_embedding_all_prefix_lengths
    vectors = {
      '2001:db8::/32' => '2001:db8:c000:221::',
      '2001:db8:100::/40' => '2001:db8:1c0:2:21::',
      '2001:db8:122::/48' => '2001:db8:122:c000:2:2100::',
      '2001:db8:122:300::/56' => '2001:db8:122:3c0:0:221::',
      '2001:db8:122:344::/64' => '2001:db8:122:344:c0:2:2100:0',
      '64:ff9b::/96' => '64:ff9b::c000:221'
    }
    vectors.each do |prefix, expected|
      assert_equal(expected, Dnsruby::DNS64.synthesize_address('192.0.2.33', prefix).to_s, "prefix #{prefix}")
    end
  end

  # The worked example: 192.0.2.33 under the Well-Known Prefix.
  def test_well_known_prefix_example
    assert_equal('64:ff9b::c000:221', Dnsruby::DNS64.synthesize_address('192.0.2.33').to_s)
  end

  def test_extract_ipv4_round_trip
    %w(2001:db8::/32 2001:db8:100::/40 2001:db8:122::/48 2001:db8:122:300::/56 2001:db8:122:344::/64 64:ff9b::/96).each do |prefix|
      synthesized = Dnsruby::DNS64.synthesize_address('192.0.2.33', prefix)
      assert_equal('192.0.2.33', Dnsruby::DNS64.extract_ipv4(synthesized, prefix).to_s, "prefix #{prefix}")
    end
    assert_nil(Dnsruby::DNS64.extract_ipv4('2001:db8::1', '64:ff9b::/96'))
  end

  def test_prefix_validation
    assert_raises(ArgumentError) { Dnsruby::DNS64.parse_prefix('64:ff9b::/24') }
    assert_raises(ArgumentError) { Dnsruby::DNS64.parse_prefix('64:ff9b::/128') }
    assert_raises(ArgumentError) { Dnsruby::DNS64.parse_prefix('64:ff9b::1/96') }
    assert_raises(ArgumentError) { Dnsruby::DNS64.parse_prefix('64:ff9b::') }
    assert_raises(ArgumentError) { Dnsruby::DNS64.new }
  end

  # When the upstream already has AAAA records, the original response is
  # kept untouched and no A query is issued.
  def test_existing_aaaa_response_preserved
    upstream = FakeUpstream.new
    aaaa_rr = Dnsruby::RR.create('dual.example. 300 IN AAAA 2001:db8::1')
    upstream.on { |query| response_for(query, answers: [aaaa_rr]) }

    dns64 = Dnsruby::DNS64.new(:query_interface => upstream)
    response = dns64.resolve(aaaa_query('dual.example'))

    assert_equal(1, upstream.queries.length)
    assert_equal([aaaa_rr], response.answer.to_a)
    assert_equal('2001:db8::1', response.answer.first.address.to_s)
  end

  # NODATA for AAAA triggers an A query and synthesis.
  def test_synthesis_from_a_records
    upstream = FakeUpstream.new
    upstream.on do |query|
      if query.question.first.qtype == Dnsruby::Types.AAAA
        response_for(query)
      else
        response_for(query, answers: [a_record('ipv4-only.example.', '192.0.2.33', 600)])
      end
    end

    dns64 = Dnsruby::DNS64.new(:query_interface => upstream)
    response = dns64.resolve(aaaa_query('ipv4-only.example'))

    assert_equal(2, upstream.queries.length)
    assert_equal(Dnsruby::Types.A, upstream.queries[1].question.first.qtype)
    assert_equal(Dnsruby::RCode.NOERROR, response.rcode)
    assert_equal(1, response.answer.length)
    synthesized = response.answer.first
    assert_equal(Dnsruby::Types.AAAA, synthesized.type)
    assert_equal('64:ff9b::c000:221', synthesized.address.to_s)
    assert_equal(600, synthesized.ttl)
    assert_equal(false, response.header.ad)
  end

  # The CNAME chain from the A response is preserved ahead of the
  # synthesized records.
  def test_cname_chain_preserved
    upstream = FakeUpstream.new
    cname_rr = Dnsruby::RR.create('www.example. 300 IN CNAME hosting.example.')
    upstream.on do |query|
      if query.question.first.qtype == Dnsruby::Types.AAAA
        response_for(query)
      else
        response_for(query, answers: [cname_rr, a_record('hosting.example.', '192.0.2.33')])
      end
    end

    dns64 = Dnsruby::DNS64.new(:query_interface => upstream)
    response = dns64.resolve(aaaa_query('www.example'))

    assert_equal([Dnsruby::Types.CNAME, Dnsruby::Types.AAAA], response.answer.map { |rr| rr.type })
    assert_equal(cname_rr, response.answer.first)
    assert_equal('hosting.example', response.answer.last.name.to_s)
    assert_equal('64:ff9b::c000:221', response.answer.last.address.to_s)
  end

  # NXDOMAIN means the name does not exist at all: no synthesis is
  # attempted and the negative response is returned unchanged.
  def test_nxdomain_passed_through
    upstream = FakeUpstream.new
    upstream.on { |query| response_for(query, rcode: Dnsruby::RCode.NXDOMAIN) }

    dns64 = Dnsruby::DNS64.new(:query_interface => upstream)
    response = dns64.resolve(aaaa_query('missing.example'))

    assert_equal(1, upstream.queries.length)
    assert_equal(Dnsruby::RCode.NXDOMAIN, response.rcode)
    assert_empty(response.answer.to_a)
  end

  # When the A lookup is also negative, the original NODATA AAAA response
  # (with its authority section for negative caching) is returned.
  def test_negative_a_response_returns_original_nodata
    upstream = FakeUpstream.new
    soa_rr = Dnsruby::RR.create('example. 60 IN SOA ns.example. hostmaster.example. 1 3600 600 86400 60')
    upstream.on do |query|
      response = response_for(query)
      response.add_authority(soa_rr)
      response
    end

    dns64 = Dnsruby::DNS64.new(:query_interface => upstream)
    response = dns64.resolve(aaaa_query('nothing.example'))

    assert_equal(2, upstream.queries.length)
    assert_equal(Dnsruby::RCode.NOERROR, response.rcode)
    assert_empty(response.answer.to_a)
    assert_equal([soa_rr], response.authority.to_a)
  end

  # The TTL of a synthesized record comes from the A record, optionally
  # clamped by the configured max_ttl.
  def test_max_ttl_clamp
    upstream = FakeUpstream.new
    upstream.on do |query|
      if query.question.first.qtype == Dnsruby::Types.AAAA
        response_for(query)
      else
        response_for(query, answers: [a_record('ipv4-only.example.', '192.0.2.33', 3600)])
      end
    end

    dns64 = Dnsruby::DNS64.new(:query_interface => upstream, :max_ttl => 60)
    response = dns64.resolve(aaaa_query('ipv4-only.example'))
    assert_equal(60, response.answer.first.ttl)
  end

  # A synthesis policy may forbid synthesis; the client then receives the
  # original empty AAAA response.
  def test_policy_forbidding_synthesis
    upstream = FakeUpstream.new
    upstream.on do |query|
      if query.question.first.qtype == Dnsruby::Types.AAAA
        response_for(query)
      else
        response_for(query, answers: [a_record('blocked.example.', '192.0.2.33')])
      end
    end

    policy = lambda { |_query, _a_response| false }
    dns64 = Dnsruby::DNS64.new(:query_interface => upstream, :synthesis_policy => policy)
    response = dns64.resolve(aaaa_query('blocked.example'))

    assert_equal(Dnsruby::RCode.NOERROR, response.rcode)
    assert_empty(response.answer.to_a)
  end

  # DO on the client query is propagated to the A query; CNAME RRSIGs are
  # kept but the A record's RRSIG is not - it does not cover the
  # synthesized AAAA, and no signature is fabricated for it.
  def test_do_bit_propagated_and_signatures_not_misrepresented
    upstream = FakeUpstream.new
    cname_rr = Dnsruby::RR.create('www.example. 300 IN CNAME hosting.example.')
    cname_sig = Dnsruby::RR.create('www.example. 300 IN RRSIG CNAME 5 3 300 20270101000000 20260101000000 12345 example. AQIDBA==')
    a_sig = Dnsruby::RR.create('hosting.example. 300 IN RRSIG A 5 3 300 20270101000000 20260101000000 12345 example. AQIDBA==')
    upstream.on do |query|
      if query.question.first.qtype == Dnsruby::Types.AAAA
        response_for(query)
      else
        response_for(query, answers: [cname_rr, cname_sig, a_record('hosting.example.', '192.0.2.33'), a_sig])
      end
    end

    dns64 = Dnsruby::DNS64.new(:query_interface => upstream)
    response = dns64.resolve(aaaa_query('www.example', true))

    a_query = upstream.queries[1]
    assert(a_query.get_opt, 'A query should carry an OPT record')
    assert(a_query.get_opt.dnssec_ok, 'A query should have DO set')

    types = response.answer.map { |rr| rr.type }
    assert_equal([Dnsruby::Types.CNAME, Dnsruby::Types.RRSIG, Dnsruby::Types.AAAA], types)
    refute(response.answer.any? { |rr| rr.type == Dnsruby::Types.RRSIG && rr.type_covered == Dnsruby::Types.A },
      'the RRSIG of the A record must not be presented as covering the synthesized AAAA')
  end

  # AD on a synthesized response requires the set_ad option, DO without CD
  # on the client query, and a validated (AD) upstream A response.
  def test_ad_bit_policy
    upstream = FakeUpstream.new
    upstream.on do |query|
      if query.question.first.qtype == Dnsruby::Types.AAAA
        response_for(query)
      else
        response_for(query, answers: [a_record('signed.example.', '192.0.2.33')], ad: true)
      end
    end

    # Default: never claim the synthesized data is validated.
    dns64 = Dnsruby::DNS64.new(:query_interface => upstream)
    refute(dns64.resolve(aaaa_query('signed.example', true)).header.ad)

    # Opt-in: vouch for validation performed upstream.
    dns64 = Dnsruby::DNS64.new(:query_interface => upstream, :set_ad => true)
    assert(dns64.resolve(aaaa_query('signed.example', true)).header.ad)
    # CD set: the client validates itself, so AD stays clear.
    refute(dns64.resolve(aaaa_query('signed.example', true, true)).header.ad)
    # No DO: AD stays clear.
    refute(dns64.resolve(aaaa_query('signed.example')).header.ad)
  end

  # CD on the client query is propagated to the upstream A query.
  def test_cd_bit_propagated
    upstream = FakeUpstream.new
    upstream.on do |query|
      if query.question.first.qtype == Dnsruby::Types.AAAA
        response_for(query)
      else
        response_for(query, answers: [a_record('ipv4-only.example.', '192.0.2.33')])
      end
    end

    dns64 = Dnsruby::DNS64.new(:query_interface => upstream)
    dns64.resolve(aaaa_query('ipv4-only.example', false, true))
    assert(upstream.queries[1].header.cd)
  end

  # Non-AAAA questions are forwarded untouched.
  def test_non_aaaa_query_passed_through
    upstream = FakeUpstream.new
    upstream.on { |query| response_for(query, answers: [a_record('host.example.', '192.0.2.33')]) }

    dns64 = Dnsruby::DNS64.new(:query_interface => upstream)
    response = dns64.resolve(Dnsruby::Message.new('host.example', Dnsruby::Types.A))

    assert_equal(1, upstream.queries.length)
    assert_equal(Dnsruby::Types.A, response.answer.first.type)
  end

  # Convenience: resolving by name builds an AAAA query.
  def test_resolve_by_name
    upstream = FakeUpstream.new
    upstream.on do |query|
      if query.question.first.qtype == Dnsruby::Types.AAAA
        response_for(query)
      else
        response_for(query, answers: [a_record('ipv4-only.example.', '192.0.2.33')])
      end
    end

    dns64 = Dnsruby::DNS64.new(:query_interface => upstream)
    response = dns64.resolve('ipv4-only.example')
    assert_equal('64:ff9b::c000:221', response.answer.first.address.to_s)
  end
end
