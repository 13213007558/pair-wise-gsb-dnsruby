require_relative 'spec_helper'

class TestECS < Minitest::Test
  include Dnsruby

  FakeClock = Struct.new(:now)

  def test_client_subnet_encoding
    ipv4 = RR::OPT::ClientSubnet.create('216.253.14.2/24')
    assert_equal(['00011800d8fd0e'], ipv4.encode.unpack('H*'))
    assert_equal('216.253.14.0/24/0', ipv4.to_s)

    ipv6 = RR::OPT::ClientSubnet.create('2600:3c00:0:91fd:ab77:157e::/64')
    assert_equal(['0002400026003c00000091fd'], ipv6.encode.unpack('H*'))
    assert_equal('2600:3c00:0:91fd::/64/0', ipv6.to_s)
  end

  def test_message_encoding_preserves_client_subnet
    query = message_with_subnet('192.0.2.7/24/0')
    decoded = Message.decode(query.encode)
    subnet = decoded.get_opt.client_subnet

    assert_equal(RR::OPT::IPV4_ADDRESS_FAMILY, subnet.family)
    assert_equal('192.0.2.0', subnet.address)
    assert_equal(24, subnet.source_prefix)
    assert_equal(0, subnet.scope_prefix)
  end

  def test_scope_zero_covers_entire_family
    scope = RR::OPT::ClientSubnet.create('0.0.0.0/24/0')

    assert(scope.covers?('0.0.0.0/24/0'))
    assert(scope.covers?('198.51.100.0/24/0'))
    refute(scope.covers?('2001:db8::/56/0'))
  end

  def test_rejects_malformed_client_subnet_options
    assert_raises(DecodeError) do
      RR::OPT::ClientSubnet.decode([0, 99, 24, 0].pack('nCC'))
    end
    assert_raises(DecodeError) do
      RR::OPT::ClientSubnet.decode([1, 24, 0].pack('nCC') + "\xd8\xfd".b)
    end

    message = Message.new('example.net', Types.A)
    opt = RR::OPT.new
    valid = RR::OPT::ClientSubnet.create('192.0.2.0/24')
    opt.options = [
      RR::OPT::Option.new(RR::OPT::EDNS_SUBNET_OPTION, valid.encode),
      RR::OPT::Option.new(RR::OPT::EDNS_SUBNET_OPTION, valid.encode)
    ]
    message.add_additional(opt)
    assert_raises(DecodeError) { Message.decode(message.encode) }
  end

  def test_adjacent_subnets_share_scope_23_but_requery_for_scope_24
    assert_subnet_sharing(23, shared: true)
    assert_subnet_sharing(24, shared: false)
  end

  def test_scope_zero_answer_is_shared_without_full_client_keys
    clock = FakeClock.new(Time.at(1000))
    queries = []
    transport = lambda do |query|
      queries << query
      response_for(query, '192.0.2.0/24/0')
    end
    resolver = ClientSubnetResolver.new(
      source_prefixes: { RR::OPT::IPV4_ADDRESS_FAMILY => 24 },
      transport: transport,
      clock: clock
    )

    first = resolver.query('example.net', Types.A, client_address: '192.0.2.10')
    second = resolver.query('example.net', Types.A, client_address: '203.0.113.10')

    refute(first.cached)
    assert(second.cached)
    assert_equal(1, queries.length)
    assert_equal('192.0.2.0/24/0', queries[0].get_opt.client_subnet.to_s)
    index_keys = resolver.instance_variable_get(:@index).instance_variable_get(:@entries).keys.inspect
    refute_includes(index_keys, '192.0.2.10')
  end

  def test_ttl_expiry_with_fake_clock_forces_requery
    clock = FakeClock.new(Time.at(1000))
    queries = []
    transport = lambda do |query|
      queries << query
      response_for(query, "#{query.get_opt.client_subnet.address}/24/24")
    end
    resolver = ClientSubnetResolver.new(
      source_prefixes: { RR::OPT::IPV4_ADDRESS_FAMILY => 24 },
      transport: transport,
      clock: clock
    )

    resolver.query('example.net', Types.A, client_address: '192.0.2.1')
    clock.now = Time.at(1060)
    resolver.query('example.net', Types.A, client_address: '192.0.2.2')

    assert_equal(2, queries.length)
  end

  def test_rejects_response_family_source_prefix_and_source_mismatches
    request = message_with_subnet('192.0.2.0/24/0')
    index = ECSAnswerIndex.new

    assert_raises(ECSAssociationError) do
      index.add(request, message_with_subnet('2001:db8::/56/56'))
    end
    assert_raises(ECSAssociationError) do
      index.add(request, message_with_subnet('192.0.2.0/23/23'))
    end
    assert_raises(ECSAssociationError) do
      index.add(request, message_with_subnet('192.0.3.0/24/24'))
    end
    assert_raises(ECSAssociationError) do
      index.add(message_with_subnet('192.0.2.0/24/1'), response_for(message_with_subnet('192.0.2.0/24/1'), '192.0.2.0/24/24'))
    end
  end

  def test_rejects_malformed_response_without_caching_it
    clock = FakeClock.new(Time.at(1000))
    transport = lambda do |request|
      response = response_for(request, '192.0.2.0/24/24')
      response.get_opt.options = [RR::OPT::Option.new(RR::OPT::EDNS_SUBNET_OPTION, 'bad')]
      response
    end
    resolver = ClientSubnetResolver.new(transport: transport, clock: clock)

    assert_raises(ECSAssociationError) do
      resolver.query('example.net', Types.A, client_address: '192.0.2.1')
    end
    assert_equal(0, resolver.instance_variable_get(:@index).length)
  end

  private

  def assert_subnet_sharing(scope_prefix, shared:)
    clock = FakeClock.new(Time.at(1000))
    queries = []
    transport = lambda do |query|
      queries << query
      request_subnet = query.get_opt.client_subnet
      response_for(query, "#{request_subnet.address}/#{request_subnet.source_prefix}/#{scope_prefix}")
    end
    resolver = ClientSubnetResolver.new(
      source_prefixes: { RR::OPT::IPV4_ADDRESS_FAMILY => 24 },
      transport: transport,
      clock: clock
    )

    resolver.query('example.net', Types.A, client_address: '192.0.2.1')
    adjacent = resolver.query('example.net', Types.A, client_address: '192.0.3.2')

    if shared
      assert(adjacent.cached)
      assert_equal(1, queries.length)
    else
      refute(adjacent.cached)
      assert_equal(2, queries.length)
      assert_equal('192.0.3.0/24/0', queries[1].get_opt.client_subnet.to_s)
    end
  end

  def message_with_subnet(subnet)
    message = Message.new('example.net', Types.A, Classes.IN)
    opt = RR::OPT.new
    message.add_additional(opt)
    opt.set_client_subnet(subnet)
    message
  end

  def response_for(request, subnet)
    response = Message.new(request.question[0].qname, request.question[0].qtype, request.question[0].qclass)
    response.header.qr = true
    response.header.rd = true
    response.header.ra = true
    response.add_answer(RR.create('example.net 60 IN A 192.0.2.100'))
    opt = RR::OPT.new
    response.add_additional(opt)
    opt.set_client_subnet(subnet)
    response
  end
end
