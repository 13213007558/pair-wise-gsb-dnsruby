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

class TestECS < Minitest::Test
  include Dnsruby

  class FakeClock
    attr_accessor :now

    def initialize(now = 1000)
      @now = now
    end

    def call
      @now
    end
  end

  def setup
    PacketSender.clear_caches
  end

  def teardown
    PacketSender.clear_caches
  end

  def test_ecs_roundtrip_truncates_address_and_preserves_scope
    request = RR::OPT::ClientSubnet.create('192.0.2.99', 22)
    assert_equal '192.0.0.0/22/0', request.to_s
    assert_equal "\x00\x01\x16\x00\xc0\x00\x00".b, request.data

    opt = RR::OPT.new(1232)
    opt.client_subnet = request
    message = Message.new('example.com', Types.A)
    message.add_additional(opt)

    decoded = Message.decode(message.encode).get_opt.client_subnet
    assert_equal request, decoded

    response = RR::OPT::ClientSubnet.new('192.0.0.0', 22, 22)
    assert_equal '192.0.0.0/22/22', response.to_s
    assert response.valid_response_to?(request)
  end

  def test_ipv6_ecs_roundtrip
    subnet = RR::OPT::ClientSubnet.create('2001:db8:1234:5678::1', 56)
    opt = RR::OPT.new(1232)
    opt.client_subnet = subnet
    message = Message.new('example.com', Types.AAAA)
    message.add_additional(opt)

    decoded = Message.decode(message.encode).get_opt.client_subnet
    assert_equal '2001:db8:1234:5600::/56/0', decoded.to_s
    assert_equal 11, decoded.data.length
  end

  def test_configuration_truncates_full_client_address
    sender = PacketSender.new(server: '192.0.2.1')
    sender.client_subnet = ['192.0.2.99', 24]
    query = Message.new('example.com', Types.A)
    encoded = sender.make_query_packet(query, false)
    subnet = Message.decode(encoded).get_opt.client_subnet

    assert_equal '192.0.2.0/24/0', subnet.to_s
    assert_equal 7, subnet.data.length
  end

  def test_rejects_inconsistent_response_family_source_and_network
    request = RR::OPT::ClientSubnet.create('192.0.2.1', 24)

    refute RR::OPT::ClientSubnet.new('192.0.2.0', 24, 24, false)
      .valid_response_to?(RR::OPT::ClientSubnet.create('203.0.113.1', 24))
    refute RR::OPT::ClientSubnet.new('192.0.2.0', 23, 23, false)
      .valid_response_to?(request)
    refute RR::OPT::ClientSubnet.new('192.0.3.0', 24, 24, false)
      .valid_response_to?(request)

    assert_raises(DecodeError) do
      RR::OPT::ClientSubnet.decode("\x00\x01\x18\x19\xc0\x00\x02".b)
    end
    assert_raises(DecodeError) do
      RR::OPT::ClientSubnet.decode("\x00\x03\x00\x00".b)
    end
  end

  def test_scope_zero_covers_every_client_in_that_family
    cache = Cache.new
    request = query_with_ecs('192.0.2.1', 24)
    response = response_with_ecs(request, '192.0.2.0', 24, 0)

    assert cache.add(response, request)
    assert cache.find_for_message(query_with_ecs('198.51.100.2', 24))
    refute cache.find_for_message(query_with_ecs('2001:db8::1', 24))
  end

  def test_adjacent_subnets_share_only_inside_returned_scope
    sender, sent = fake_sender do |query|
      response_with_ecs(query, '192.0.2.0', 24, 23)
    end

    first_query = query_with_ecs('192.0.2.10', 24)
    response = send_with_fake_transport(sender, sent, first_query)
    assert_equal 1, sent.length
    assert_equal '192.0.2.0/24/0', first_query.get_opt.client_subnet.to_s

    same_scope = query_with_ecs('192.0.3.20', 24)
    response = send_with_fake_transport(sender, sent, same_scope)
    assert(response.cached, '192.0.2.0/24 and 192.0.3.0/24 share the /23 scope')
    assert_equal 1, sent.length

    outside_scope = query_with_ecs('192.0.4.30', 24)
    response = send_with_fake_transport(sender, sent, outside_scope)
    refute(response.cached, '192.0.4.0/24 is outside the /23 scope and must be requeried')
    assert_equal 2, sent.length
  end

  def test_configured_client_subnet_uses_returned_scope_index
    sender, sent = fake_sender('192.0.2.99/24') do |query|
      response_with_ecs(query, '192.0.2.0', 24, 23)
    end

    first = Message.new('example.com', Types.A)
    first.header.rd = true
    first = send_with_fake_transport(sender, sent, first)
    assert_equal '192.0.2.0/24/0', sent.first.get_opt.client_subnet.to_s

    sender.client_subnet = '192.0.3.50/24'
    second = Message.new('example.com', Types.A)
    second.header.rd = true
    second = send_with_fake_transport(sender, sent, second)
    assert second.cached
    assert_equal 1, sent.length

    sender.client_subnet = '192.0.4.50/24'
    third = Message.new('example.com', Types.A)
    third.header.rd = true
    third = send_with_fake_transport(sender, sent, third)
    refute third.cached
    assert_equal 2, sent.length
  end

  def test_scope_prefixes_do_not_treat_different_source_lengths_as_full_addresses
    cache = Cache.new
    request = query_with_ecs('192.0.2.99', 24)
    response = response_with_ecs(request, '192.0.2.0', 24, 24)
    cache.add(response, request)

    assert_equal 1, cache.length
    stored_key = cache.cache.keys.first
    assert_equal [1, 24, "\xc0\x00\x02".b], stored_key.last
    refute_includes cache.cache.keys.first.inspect, '99'
  end

  def test_time_double_expires_scoped_answer
    clock = FakeClock.new
    cache = Cache.new(clock)
    request = query_with_ecs('192.0.2.1', 24)
    response = response_with_ecs(request, '192.0.2.0', 24, 24, ttl: 5)
    cache.add(response, request)

    assert cache.find_for_message(request)
    clock.now = 1004
    assert cache.find_for_message(request)
    clock.now = 1005
    refute cache.find_for_message(request)
  end

  private

  def fake_sender(configured_subnet = nil, &block)
    sender = PacketSender.new(server: '192.0.2.1')
    sender.client_subnet = configured_subnet
    sent = []
    sender.define_singleton_method(:send_dnsruby) do |query_bytes, query, client_query_id, client_queue, _use_tcp = false|
      received = Message.decode(query_bytes)
      sent << received
      response = block.call(received)
      PacketSender.cache(received, response)
      response.header.id = received.header.id
      SelectThread.instance.push_response_to_select(
        client_query_id, client_queue, response, received, self
      )
    end
    [sender, sent]
  end

  def send_with_fake_transport(_sender, _sent, query)
    queue = Queue.new
    id = _sender.send_async(query, queue)
    item = nil
    item = queue.pop until item && item.first == id &&
      item.length == 4 && item[1] == Resolver::EventType::VALIDATED
    _id, _event, response, error = item
    raise error if error
    assert_equal id, _id
    response
  end

  def query_with_ecs(address, prefix)
    message = Message.new('example.com', Types.A)
    message.header.rd = true
    opt = RR::OPT.new(1232)
    opt.client_subnet = RR::OPT::ClientSubnet.create(address, prefix)
    message.add_additional(opt)
    message
  end

  def response_with_ecs(query, address, source_prefix, scope_prefix, ttl: 60)
    response = Message.new
    response.header.id = query.header.id
    response.header.qr = true
    response.header.rd = true
    response.add_question(query.question[0])
    response.add_answer(RR.create("example.com. #{ttl} IN A 192.0.2.100"))

    opt = RR::OPT.new(1232)
    opt.client_subnet = RR::OPT::ClientSubnet.new(address, source_prefix, scope_prefix, false)
    response.add_additional(opt)
    response
  end
end
