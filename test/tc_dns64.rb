# --
# Copyright 2007 Nominet UK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require_relative 'spec_helper'

class TestDNS64 < Minitest::Test

  include Dnsruby

  #  RFC 6052 section 2.4 example translations for 192.0.2.33
  RFC6052_EXAMPLES = {
    '2001:db8::/32'         => '2001:db8:c000:221::',
    '2001:db8:100::/40'     => '2001:db8:1c0:2:21::',
    '2001:db8:122::/48'     => '2001:db8:122:c000:2:2100::',
    '2001:db8:122:300::/56' => '2001:db8:122:3c0:0:221::',
    '2001:db8:122:344::/64' => '2001:db8:122:344:c0:2:2100:0',
    '2001:db8::/96'         => '2001:db8::c000:221',
    '64:ff9b::/96'          => '64:ff9b::c000:221'
  }.freeze

  def test_rfc6052_embedding_all_prefix_lengths
    RFC6052_EXAMPLES.each do |prefix, expected|
      synthesized = DNS64.new(prefix).synthesize('192.0.2.33')
      assert_equal([IPv6.create(expected).to_s], synthesized,
        "IPv4 embedding for Pref64 #{prefix}")
    end
  end

  def test_well_known_prefix_is_default
    assert_equal(['64:ff9b::c000:221'], DNS64.new.synthesize('192.0.2.33'))
  end

  def test_bare_prefix_defaults_to_96
    assert_equal(96, DNS64.new('64:ff9b::').prefixes.first.length)
  end

  def test_invalid_prefix_lengths_rejected
    %w[64:ff9b::/24 64:ff9b::/72 64:ff9b::/88 64:ff9b::/128].each do |prefix|
      assert_raises(ArgumentError) { DNS64.new(prefix) }
    end
  end

  def test_non_canonical_prefix_rejected
    #  Bits set beyond the prefix length (including the reserved u octet)
    assert_raises(ArgumentError) { DNS64.new('2001:db8::1/32') }
    assert_raises(ArgumentError) { DNS64.new('2001:db8::ff00:0:0/64') }
  end

  def test_empty_prefix_list_rejected
    assert_raises(ArgumentError) { DNS64.new([]) }
  end

  def test_default_ipv4_exclusions
    dns64 = DNS64.new
    %w[0.0.0.0 0.1.2.3 127.0.0.1 127.255.255.254
       224.0.0.1 239.255.255.255 255.255.255.255].each do |address|
      assert(dns64.excluded_ipv4?(address), "#{address} should be excluded")
      assert_equal([], dns64.synthesize(address),
        "#{address} should not be synthesized")
    end
    %w[1.2.3.4 8.8.8.8 192.0.2.1 126.255.255.255 223.255.255.255 240.0.0.1].each do |address|
      refute(dns64.excluded_ipv4?(address), "#{address} should not be excluded")
    end
  end

  def test_custom_ipv4_exclusions
    dns64 = DNS64.new('64:ff9b::/96',
      ipv4_exclusions: ['192.0.2.0/24', '203.0.113.7/32'])
    assert(dns64.excluded_ipv4?('192.0.2.99'))
    assert(dns64.excluded_ipv4?('203.0.113.7'))
    refute(dns64.excluded_ipv4?('203.0.113.8'))
    refute(dns64.excluded_ipv4?('127.0.0.1')) #  defaults are replaced
  end

  def aaaa_query_message(name = 'example.com')
    msg = Message.new
    msg.header.rd = 1
    msg.add_question(name, Types.AAAA, Classes.IN)
    msg
  end

  def nodata_aaaa_response
    msg = Message.new
    msg.header.qr = true
    msg.add_question('example.com', Types.AAAA, Classes.IN)
    msg
  end

  def existing_aaaa_response
    msg = nodata_aaaa_response
    msg.header.ad = true
    msg.add_answer(RR.create('example.com. 300 IN AAAA 2001:db8::1'))
    msg.security_level = Message::SecurityLevel::SECURE
    msg
  end

  def a_response(records, ad: false, security_level: Message::SecurityLevel::UNCHECKED)
    msg = Message.new
    msg.header.qr = true
    msg.header.ad = ad
    msg.add_question('example.com', Types.A, Classes.IN)
    records.each { |record| msg.add_answer(record) }
    msg.security_level = security_level
    msg
  end

  #  Runs the DNS64 flow against local response objects, recording the
  #  queries made. responses maps qtype strings to a response or :nxdomain.
  def run_dns64_flow(dns64, responses)
    queries = []
    messages = []
    sender = lambda do |message|
      qtype = message.question.first.qtype.to_s
      queries << qtype
      messages << message
      response = responses[qtype]
      raise NXDomain.new('NXDOMAIN') if response == :nxdomain
      response
    end
    result = dns64.resolve(aaaa_query_message, &sender)
    [result, queries, messages]
  end

  def test_existing_aaaa_response_returned_untouched
    response = existing_aaaa_response
    result, queries = run_dns64_flow(DNS64.new, 'AAAA' => response)
    assert_equal(%w[AAAA], queries)
    assert_same(response, result)
    assert(result.header.ad, 'AD bit must be preserved on untouched responses')
    assert_equal(Message::SecurityLevel::SECURE, result.security_level)
  end

  def test_nxdomain_response_not_followed_up
    queries = []
    sender = lambda do |message|
      queries << message.question.first.qtype.to_s
      raise NXDomain.new('NXDOMAIN')
    end
    assert_raises(NXDomain) { DNS64.new.resolve(aaaa_query_message, &sender) }
    assert_equal(%w[AAAA], queries)
  end

  def test_nodata_triggers_a_query_and_synthesis
    a_resp = a_response([RR.create('example.com. 300 IN A 192.0.2.1')],
      ad: true, security_level: Message::SecurityLevel::SECURE)
    result, queries, messages = run_dns64_flow(DNS64.new,
      'AAAA' => nodata_aaaa_response, 'A' => a_resp)

    assert_equal(%w[AAAA A], queries)
    #  The follow-up query is for the same name, with type A
    a_query = messages[1]
    assert_equal(Types::A, a_query.question.first.qtype)
    assert_equal('example.com', a_query.question.first.qname.to_s)

    assert_equal(RCode::NOERROR, result.rcode)
    assert_equal(Types::AAAA, result.question.first.qtype)
    answers = result.answer.select { |rr| rr.type == Types::AAAA }
    assert_equal(1, answers.length)
    assert_equal('64:ff9b::c000:201', answers.first.address.to_s)
    assert_equal(300, answers.first.ttl)
    assert_equal('example.com', answers.first.name.to_s)
    #  Synthesized data must not claim the authenticity of the A response
    refute(result.header.ad, 'AD bit must be cleared on synthesized responses')
    assert_equal(Message::SecurityLevel::INSECURE, result.security_level)
  end

  def test_cname_chain_preserved_in_synthesized_response
    a_resp = a_response([
      RR.create('www.example.com. 300 IN CNAME www1.example.com.'),
      RR.create('www1.example.com. 300 IN A 192.0.2.1')
    ])
    result, queries = run_dns64_flow(DNS64.new,
      'AAAA' => nodata_aaaa_response, 'A' => a_resp)

    assert_equal(%w[AAAA A], queries)
    cnames = result.answer.select { |rr| rr.type == Types::CNAME }
    assert_equal(1, cnames.length)
    assert_equal('www1.example.com', cnames.first.domainname.to_s)
    assert(result.answer.none? { |rr| rr.type == Types::A },
      'A records must be replaced by synthesized AAAA records')
    aaaa = result.answer.select { |rr| rr.type == Types::AAAA }
    assert_equal(1, aaaa.length)
    assert_equal('www1.example.com', aaaa.first.name.to_s)
    assert_equal('64:ff9b::c000:201', aaaa.first.address.to_s)
  end

  def test_excluded_addresses_not_synthesized
    a_resp = a_response([
      RR.create('example.com. 300 IN A 127.0.0.1'),
      RR.create('example.com. 300 IN A 192.0.2.1')
    ])
    result, = run_dns64_flow(DNS64.new,
      'AAAA' => nodata_aaaa_response, 'A' => a_resp)
    aaaa = result.answer.select { |rr| rr.type == Types::AAAA }
    assert_equal(1, aaaa.length)
    assert_equal('64:ff9b::c000:201', aaaa.first.address.to_s)
  end

  def test_all_excluded_returns_original_response
    nodata = nodata_aaaa_response
    a_resp = a_response([RR.create('example.com. 300 IN A 127.0.0.1')])
    result, queries = run_dns64_flow(DNS64.new,
      'AAAA' => nodata, 'A' => a_resp)
    assert_equal(%w[AAAA A], queries)
    assert_same(nodata, result)
  end

  def test_a_query_nxdomain_returns_original_response
    nodata = nodata_aaaa_response
    result, queries = run_dns64_flow(DNS64.new,
      'AAAA' => nodata, 'A' => :nxdomain)
    assert_equal(%w[AAAA A], queries)
    assert_same(nodata, result)
  end

  def test_a_query_without_a_records_returns_original_response
    nodata = nodata_aaaa_response
    result, = run_dns64_flow(DNS64.new,
      'AAAA' => nodata, 'A' => a_response([]))
    assert_same(nodata, result)
  end

  def test_multiple_prefixes_synthesize_multiple_addresses
    dns64 = DNS64.new(['64:ff9b::/96', '2001:db8::/96'])
    a_resp = a_response([RR.create('example.com. 300 IN A 192.0.2.1')])
    result, = run_dns64_flow(dns64,
      'AAAA' => nodata_aaaa_response, 'A' => a_resp)
    addresses = result.answer.select { |rr| rr.type == Types::AAAA }.
      map { |rr| rr.address.to_s }.sort
    assert_equal(['2001:db8::c000:201', '64:ff9b::c000:201'], addresses)
  end

  #  A Resolver which answers from local response objects, recording the
  #  queries made - no network traffic is generated.
  class Dns64StubResolver < Resolver
    attr_reader :sent

    def initialize(*args)
      super
      @sent = []
    end

    def send_message(message)
      qtype = message.question.first.qtype.to_s
      @sent << qtype
      response = Dnsruby::Message.new
      response.header.qr = true
      message.question.each { |q| response.add_question(q) }
      if qtype == 'A'
        response.add_answer(Dnsruby::RR.create('example.com. 300 IN A 192.0.2.1'))
      end
      response
    end
  end

  def test_resolver_query_with_dns64_enabled
    resolver = Dns64StubResolver.new('127.0.0.1')
    resolver.dns64 = true
    response = resolver.query('example.com', Types.AAAA)
    assert_equal(%w[AAAA A], resolver.sent)
    aaaa = response.answer.select { |rr| rr.type == Types::AAAA }
    assert_equal(1, aaaa.length)
    assert_equal('64:ff9b::c000:201', aaaa.first.address.to_s)
  end

  def test_resolver_query_with_dns64_disabled
    resolver = Dns64StubResolver.new('127.0.0.1')
    response = resolver.query('example.com', Types.AAAA)
    assert_equal(%w[AAAA], resolver.sent)
    assert_equal(0, response.answer.length)
  end

  def test_resolver_non_aaaa_query_unaffected
    resolver = Dns64StubResolver.new('127.0.0.1')
    resolver.dns64 = true
    response = resolver.query('example.com', Types.A)
    assert_equal(%w[A], resolver.sent)
    assert_equal(1, response.answer.length)
  end

  def test_resolver_new_with_dns64_option
    resolver = Dns64StubResolver.new(nameserver: '127.0.0.1', dns64: true)
    assert(resolver.dns64.is_a?(DNS64))
  end

  def test_resolver_dns64_configuration_forms
    resolver = Resolver.new('127.0.0.1')
    assert_nil(resolver.dns64)

    resolver.dns64 = true
    assert_equal([96], resolver.dns64.prefixes.map(&:length))

    resolver.dns64 = '2001:db8::/32'
    assert_equal([32], resolver.dns64.prefixes.map(&:length))

    resolver.dns64 = ['64:ff9b::/96', '2001:db8::/96']
    assert_equal([96, 96], resolver.dns64.prefixes.map(&:length))

    resolver.dns64 = { prefixes: '2001:db8::/48', ipv4_exclusions: ['10.0.0.0/8'] }
    assert_equal([48], resolver.dns64.prefixes.map(&:length))
    assert(resolver.dns64.excluded_ipv4?('10.1.2.3'))
    refute(resolver.dns64.excluded_ipv4?('127.0.0.1'))

    resolver.dns64 = DNS64.new
    assert(resolver.dns64.is_a?(DNS64))

    resolver.dns64 = false
    assert_nil(resolver.dns64)

    assert_raises(ArgumentError) { resolver.dns64 = 42 }
  end
end
