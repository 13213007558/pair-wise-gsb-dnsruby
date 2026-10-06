require_relative 'spec_helper'

# Tests for the optional Dnsruby::DNS64 layer (RFC 6147 / RFC 6052).
#
# All tests are offline: a fake resolver hands back locally-built
# Dnsruby::Message objects and records the queries it receives, so the
# AAAA -> A resolution order can be checked without any network (or an
# actual NAT64 gateway).
class TestDNS64 < Minitest::Test

  include Dnsruby

  class FakeResolver
    attr_reader :queries

    def initialize
      @responses = {}
      @queries = []
    end

    def add(name, type, response)
      @responses[[Dnsruby::Name.create(name).to_s, Dnsruby::Types.new(type).to_s]] = response
    end

    def query(name, type=Dnsruby::Types.A, klass=Dnsruby::Classes.IN)
      qname = Dnsruby::Name.create(name).to_s
      qtype = Dnsruby::Types.new(type).to_s
      @queries << [qname, qtype]
      response = @responses[[qname, qtype]]
      raise Dnsruby::ResolvError.new("no canned response for #{qname} #{qtype}") if response.nil?
      response
    end
  end

  def build_response(qname, qtype, rcode: 'NOERROR', answers: [], ad: false)
    msg = Dnsruby::Message.new(qname, qtype)
    msg.header.qr = true
    msg.header.ra = true
    msg.header.rcode = rcode
    msg.header.ad = ad
    answers.each {|rr| msg.add_answer(rr)}
    msg
  end

  def a_rr(name, address, ttl=300)
    Dnsruby::RR.create("#{name} #{ttl} IN A #{address}")
  end

  def aaaa_rr(name, address, ttl=300)
    Dnsruby::RR.create("#{name} #{ttl} IN AAAA #{address}")
  end

  def cname_rr(name, target, ttl=300)
    Dnsruby::RR.create("#{name} #{ttl} IN CNAME #{target}")
  end

  #  -- Query flow --

  def test_non_aaaa_query_passes_through
    resolver = FakeResolver.new
    a_response = build_response('example.com', 'A', answers: [a_rr('example.com.', '192.0.2.1')])
    resolver.add('example.com', 'A', a_response)
    dns64 = Dnsruby::DNS64.new(resolver)
    assert_same(a_response, dns64.query('example.com', Types.A))
    assert_equal([['example.com', 'A']], resolver.queries)
  end

  def test_existing_aaaa_returned_without_a_query
    resolver = FakeResolver.new
    aaaa_response = build_response('example.com', 'AAAA',
                                   answers: [aaaa_rr('example.com.', '2001:db8::1')])
    resolver.add('example.com', 'AAAA', aaaa_response)
    dns64 = Dnsruby::DNS64.new(resolver)
    assert_same(aaaa_response, dns64.query('example.com', Types.AAAA))
    assert_equal([['example.com', 'AAAA']], resolver.queries)
  end

  def test_nxdomain_returned_without_a_query
    resolver = FakeResolver.new
    nxdomain = build_response('example.com', 'AAAA', rcode: 'NXDOMAIN')
    resolver.add('example.com', 'AAAA', nxdomain)
    dns64 = Dnsruby::DNS64.new(resolver)
    assert_same(nxdomain, dns64.query('example.com', Types.AAAA))
    assert_equal([['example.com', 'AAAA']], resolver.queries)
  end

  def test_nodata_triggers_a_query_then_synthesizes
    resolver = FakeResolver.new
    nodata = build_response('example.com', 'AAAA')
    resolver.add('example.com', 'AAAA', nodata)
    resolver.add('example.com', 'A',
                 build_response('example.com', 'A', answers: [a_rr('example.com.', '192.0.2.1', 123)]))
    dns64 = Dnsruby::DNS64.new(resolver)
    response = dns64.query('example.com', Types.AAAA)
    #  The AAAA query went first, and the A query followed the NODATA answer
    assert_equal([['example.com', 'AAAA'], ['example.com', 'A']], resolver.queries)
    assert_equal(RCode.NOERROR, response.rcode)
    synthesized = response.answer.select {|rr| rr.type == Types::AAAA}
    assert_equal(1, synthesized.length)
    assert_equal(IPv6.create('64:ff9b::c000:201'), synthesized[0].address)
    assert_equal('example.com.', synthesized[0].name.to_s(true))
    assert_equal(123, synthesized[0].ttl)
    assert_equal(Types::AAAA, response.question[0].qtype)
  end

  def test_a_query_error_returns_original_aaaa_response
    resolver = FakeResolver.new
    nodata = build_response('example.com', 'AAAA')
    resolver.add('example.com', 'AAAA', nodata)
    resolver.add('example.com', 'A', build_response('example.com', 'A', rcode: 'NXDOMAIN'))
    dns64 = Dnsruby::DNS64.new(resolver)
    assert_same(nodata, dns64.query('example.com', Types.AAAA))
    assert_equal([['example.com', 'AAAA'], ['example.com', 'A']], resolver.queries)
  end

  def test_a_response_without_a_records_returns_original
    resolver = FakeResolver.new
    nodata = build_response('example.com', 'AAAA')
    resolver.add('example.com', 'AAAA', nodata)
    resolver.add('example.com', 'A', build_response('example.com', 'A'))
    dns64 = Dnsruby::DNS64.new(resolver)
    assert_same(nodata, dns64.query('example.com', Types.AAAA))
  end

  def test_cname_chain_preserved_and_completed_with_synthesized_aaaa
    resolver = FakeResolver.new
    chain = cname_rr('www.example.com.', 'web.example.com.')
    aaaa_response = build_response('www.example.com', 'AAAA', answers: [chain])
    resolver.add('www.example.com', 'AAAA', aaaa_response)
    resolver.add('www.example.com', 'A',
                 build_response('www.example.com', 'A',
                                answers: [chain, a_rr('web.example.com.', '192.0.2.1')]))
    dns64 = Dnsruby::DNS64.new(resolver)
    response = dns64.query('www.example.com', Types.AAAA)
    assert_equal([Types::CNAME, Types::AAAA], response.answer.map {|rr| rr.type})
    assert_equal('web.example.com.', response.answer[1].name.to_s(true))
    assert_equal(IPv6.create('64:ff9b::c000:201'), response.answer[1].address)
  end

  def test_cname_chain_taken_from_a_response_when_aaaa_answer_empty
    resolver = FakeResolver.new
    resolver.add('www.example.com', 'AAAA', build_response('www.example.com', 'AAAA'))
    resolver.add('www.example.com', 'A',
                 build_response('www.example.com', 'A',
                                answers: [cname_rr('www.example.com.', 'web.example.com.'),
                                          a_rr('web.example.com.', '192.0.2.1')]))
    dns64 = Dnsruby::DNS64.new(resolver)
    response = dns64.query('www.example.com', Types.AAAA)
    assert_equal([Types::CNAME, Types::AAAA], response.answer.map {|rr| rr.type})
    assert_equal(IPv6.create('64:ff9b::c000:201'), response.answer[1].address)
  end

  def test_excluded_ipv4_ranges_are_not_synthesized
    resolver = FakeResolver.new
    resolver.add('example.com', 'AAAA', build_response('example.com', 'AAAA'))
    resolver.add('example.com', 'A',
                 build_response('example.com', 'A',
                                answers: [a_rr('example.com.', '10.1.2.3'),
                                          a_rr('example.com.', '192.0.2.1')]))
    dns64 = Dnsruby::DNS64.new(resolver, excluded_ipv4: ['10.0.0.0/8'])
    response = dns64.query('example.com', Types.AAAA)
    synthesized = response.answer.select {|rr| rr.type == Types::AAAA}
    assert_equal(1, synthesized.length)
    assert_equal(IPv6.create('64:ff9b::c000:201'), synthesized[0].address)
  end

  def test_all_ipv4_excluded_returns_original_response
    resolver = FakeResolver.new
    nodata = build_response('example.com', 'AAAA')
    resolver.add('example.com', 'AAAA', nodata)
    resolver.add('example.com', 'A',
                 build_response('example.com', 'A', answers: [a_rr('example.com.', '10.1.2.3')]))
    dns64 = Dnsruby::DNS64.new(resolver, excluded_ipv4: ['10.0.0.0/8'])
    assert_same(nodata, dns64.query('example.com', Types.AAAA))
  end

  def test_synthesized_response_does_not_inherit_authenticity
    resolver = FakeResolver.new
    nodata = build_response('example.com', 'AAAA', ad: true)
    nodata.security_level = Message::SecurityLevel.SECURE
    resolver.add('example.com', 'AAAA', nodata)
    resolver.add('example.com', 'A',
                 build_response('example.com', 'A', answers: [a_rr('example.com.', '192.0.2.1')], ad: true))
    dns64 = Dnsruby::DNS64.new(resolver)
    response = dns64.query('example.com', Types.AAAA)
    refute(response.header.ad, 'synthesized response must not carry the AD bit')
    assert_equal(Message::SecurityLevel.UNCHECKED, response.security_level)
    #  The original response object is left untouched
    assert(nodata.header.ad)
    assert_equal(Message::SecurityLevel.SECURE, nodata.security_level)
  end

  def test_query_bang_returns_response_and_nil_error
    resolver = FakeResolver.new
    resolver.add('example.com', 'AAAA', build_response('example.com', 'AAAA'))
    resolver.add('example.com', 'A',
                 build_response('example.com', 'A', answers: [a_rr('example.com.', '192.0.2.1')]))
    dns64 = Dnsruby::DNS64.new(resolver)
    response, error = dns64.query!('example.com', Types.AAAA)
    assert_nil(error)
    assert_equal(1, response.answer.length)
  end

  #  -- RFC 6052 embedding for every defined prefix length --

  #  Expected embeddings of 192.0.2.33 (c0.00.02.21), worked out from the
  #  RFC 6052 section 2.2 address format: the IPv4 bits follow the prefix,
  #  skipping the zero 'u' octet (bits 64-71) for prefix lengths 32-64.
  EMBEDDING_VECTORS = {
    32 => ['2001:db8::/32',        '2001:db8:c000:221::'],
    40 => ['2001:db8:1000::/40',   '2001:db8:10c0:2:21::'],
    48 => ['2001:db8:1234::/48',   '2001:db8:1234:c000:2:2100::'],
    56 => ['2001:db8:1234:ab00::/56', '2001:db8:1234:abc0:0:221::'],
    64 => ['2001:db8:1234:abcd::/64', '2001:db8:1234:abcd:c0:2:2100:0'],
    96 => ['64:ff9b::/96',         '64:ff9b::c000:221'],
  }

  def test_rfc6052_embedding_for_all_prefix_lengths
    EMBEDDING_VECTORS.each do |prefix_length, (pref64, expected)|
      dns64 = Dnsruby::DNS64.new(FakeResolver.new, pref64: pref64)
      synthesized = dns64.synthesize_address('192.0.2.33')
      assert_equal(IPv6.create(expected), synthesized,
                   "wrong embedding for /#{prefix_length}")
      bytes = synthesized.address.unpack('C16')
      #  The 'u' octet (bits 64-71) must be zero for prefix lengths 32-64
      assert_equal(0, bytes[8], "u octet not zero for /#{prefix_length}") unless prefix_length == 96
      #  The prefix itself must be preserved
      prefix_bytes = prefix_length / 8
      assert_equal(IPv6.create(pref64.split('/')[0]).address.unpack('C16')[0, prefix_bytes],
                   bytes[0, prefix_bytes], "prefix not preserved for /#{prefix_length}")
    end
  end

  def test_well_known_prefix_is_default
    dns64 = Dnsruby::DNS64.new(FakeResolver.new)
    assert_equal(96, dns64.prefix_length)
    assert_equal(IPv6.create('64:ff9b::'), dns64.prefix)
    assert_equal(IPv6.create('64:ff9b::c000:201'), dns64.synthesize_address('192.0.2.1'))
  end

  def test_prefix_and_length_given_separately
    dns64 = Dnsruby::DNS64.new(FakeResolver.new, pref64: '2001:db8::', prefix_length: 32)
    assert_equal(32, dns64.prefix_length)
    assert_equal(IPv6.create('2001:db8:c000:201::'), dns64.synthesize_address('192.0.2.1'))
  end

  def test_invalid_prefix_length_rejected
    [33, 72, 128].each do |length|
      assert_raises(ArgumentError) do
        Dnsruby::DNS64.new(FakeResolver.new, pref64: "64:ff9b::/#{length}")
      end
    end
  end

  def test_prefix_with_bits_beyond_length_rejected
    assert_raises(ArgumentError) do
      Dnsruby::DNS64.new(FakeResolver.new, pref64: '64:ff9b::1/96')
    end
  end

  def test_invalid_exclusion_range_rejected
    assert_raises(ArgumentError) do
      Dnsruby::DNS64.new(FakeResolver.new, excluded_ipv4: ['10.0.0.0/33'])
    end
  end

  def test_excluded_ipv4_predicate
    dns64 = Dnsruby::DNS64.new(FakeResolver.new,
                               excluded_ipv4: ['10.0.0.0/8', '192.0.2.99'])
    assert(dns64.excluded_ipv4?('10.1.2.3'))
    assert(dns64.excluded_ipv4?('192.0.2.99'))
    refute(dns64.excluded_ipv4?('192.0.2.1'))
    refute(dns64.excluded_ipv4?('11.0.0.1'))
  end
end
