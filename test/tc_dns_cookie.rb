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

class TestDnsCookie < Minitest::Test
  include Dnsruby

  COOKIE_CODE = RR::OPT::EDNS_COOKIE_OPTION

  class RecordingPacketSender < PacketSender
    attr_reader :requests, :generator_keys

    def initialize(server, response_handler, client_byte = 0x11)
      @requests = []
      @generator_keys = []
      super(
        server: server,
        udp_size: 4096,
        client_cookie_generator: lambda do |server_key|
          @generator_keys << server_key
          ([client_byte] * 8).pack('C*')
        end
      )
      @response_handler = response_handler
    end

    def send_dnsruby(query_bytes, query, client_query_id, client_queue, use_tcp)
      request = Dnsruby::Message.decode(query_bytes)
      @requests << request
      response = @response_handler.call(request, @requests.length, use_tcp)
      if check_response(response, response.encode, query, client_queue, client_query_id, use_tcp)
        client_queue.push([client_query_id, response, response.get_exception])
      end
    end
  end

  def test_cookie_round_trip
    opt = RR::OPT.new(4096)
    opt.set_cookie(cookie_bytes(0x01), cookie_bytes(0x02, 16))

    message = Message.new('example.com')
    message.add_additional(opt)
    decoded = Message.decode(message.encode)
    cookie = decoded.get_opt.cookie

    assert_equal(COOKIE_CODE, cookie.code)
    assert_equal(cookie_bytes(0x01), cookie.client_cookie)
    assert_equal(cookie_bytes(0x02, 16), cookie.server_cookie)
    assert_equal(24, cookie.data.bytesize)
  end

  def test_rejects_invalid_wire_lengths
    assert_raises(DecodeError) { RR::OPT::Cookie.from_wire(cookie_bytes(0x01, 7)) }
    assert_raises(DecodeError) { decode_raw_cookie(cookie_bytes(0x01, 7)) }
    assert_raises(DecodeError) { decode_raw_cookie(cookie_bytes(0x01, 15)) }
    assert_raises(DecodeError) { decode_raw_cookie(cookie_bytes(0x01, 41)) }
  end

  def test_rejects_duplicate_cookie_options
    opt = RR::OPT.new(4096)
    opt.options = [
      RR::OPT::Cookie.new(cookie_bytes(0x01)),
      RR::OPT::Cookie.new(cookie_bytes(0x02))
    ]
    message = Message.new('example.com')
    message.add_additional(opt)

    assert_raises(EncodeError) { message.encode }
  end

  def test_rejects_duplicate_cookie_options_on_wire
    data = cookie_bytes(0x01) + cookie_bytes(0x02)
    assert_raises(DecodeError) { decode_raw_option_data(COOKIE_CODE, data, 2) }
  end

  def test_rejects_invalid_constructed_cookie
    assert_raises(ArgumentError) { RR::OPT::Cookie.new(cookie_bytes(0x01, 7)) }
    assert_raises(ArgumentError) { RR::OPT::Cookie.new('not-binary') }
  end

  def test_badcookie_retry_uses_challenge_and_remembers_server_cookie
    challenge_cookie = cookie_bytes(0x22, 16)
    sender = RecordingPacketSender.new('192.0.2.1', lambda do |request, request_number, _use_tcp|
      if request_number == 1
        badcookie_response(request, challenge_cookie)
      else
        successful_response(request)
      end
    end)

    response = send_query(sender)
    assert_equal(RCode.NOERROR, response.rcode)

    assert_equal(2, sender.requests.length)
    first_cookie = sender.requests[0].get_opt.cookie
    retried_cookie = sender.requests[1].get_opt.cookie
    assert_nil(first_cookie.server_cookie)
    assert_equal(first_cookie.client_cookie, retried_cookie.client_cookie)
    assert_equal(challenge_cookie, retried_cookie.server_cookie)
    assert_equal(['192.0.2.1', '192.0.2.1'], sender.generator_keys)

    send_query(sender)
    remembered_cookie = sender.requests[2].get_opt.cookie
    assert_equal(challenge_cookie, remembered_cookie.server_cookie)
  end

  def test_server_cookie_is_not_shared_across_servers
    handler = lambda { |_request, _number, _use_tcp| raise ArgumentError.new('no response expected') }
    first = RecordingPacketSender.new('192.0.2.1', handler)
    second = RecordingPacketSender.new('192.0.2.2', handler)
    first.instance_variable_set(:@server_cookie, cookie_bytes(0x33, 16))

    first_request = prepared_query(first)
    second_request = prepared_query(second)

    assert_equal(cookie_bytes(0x33, 16), first_request.get_opt.cookie.server_cookie)
    assert_nil(second_request.get_opt.cookie.server_cookie)
    assert_equal('192.0.2.1', first.generator_keys.last)
    assert_equal('192.0.2.2', second.generator_keys.last)
  end

  def test_client_cookie_generator_configuration_is_propagated
    generator = lambda { |server| cookie_bytes(server[-1].to_i) }
    single = SingleResolver.new(server: '192.0.2.1', client_cookie_generator: generator)
    assert_same(generator, single.single_resolvers[0].client_cookie_generator)

    multi = Resolver.new(nameserver: ['192.0.2.1', '192.0.2.2'])
    multi.client_cookie_generator = generator
    multi.single_resolvers.each do |sender|
      assert_same(generator, sender.client_cookie_generator)
    end
    multi.close
  end

  def test_client_cookie_generator_receives_server_context
    contexts = []
    generator = lambda do |server, port, context|
      contexts << [server, port, context]
      cookie_bytes(0x66)
    end
    sender = PacketSender.new(server: '192.0.2.3', client_cookie_generator: generator)
    prepared_query(sender)

    assert_equal(
      ['192.0.2.3', 53, {server: '192.0.2.3', port: 53, use_ipv6: false, src_address: '0.0.0.0'}],
      contexts.last
    )
  end

  def test_repeated_badcookie_challenge_is_limited
    sender = RecordingPacketSender.new('192.0.2.1', lambda do |request, request_number, _use_tcp|
      badcookie_response(request, cookie_bytes(request_number, 16))
    end)

    response = send_query(sender)

    assert_equal(RCode.BADCOOKIE, response.rcode)
    assert_equal(2, sender.requests.length)
    assert_equal(cookie_bytes(1, 16), sender.requests[1].get_opt.cookie.server_cookie)
  end

  def test_mismatched_client_cookie_is_rejected_without_retry
    sender = RecordingPacketSender.new('192.0.2.1', lambda do |request, _number, _use_tcp|
      badcookie_response(request, cookie_bytes(0x44, 16), cookie_bytes(0x55))
    end)
    queue = Queue.new
    sender.send_async(Message.new('example.com'), queue)

    assert_equal(1, sender.requests.length)
    assert(queue.empty?)
    assert_nil(sender.instance_variable_get(:@server_cookie))
  end

  def test_badcookie_with_short_server_cookie_is_rejected_without_retry
    sender = RecordingPacketSender.new('192.0.2.1', lambda do |request, _number, _use_tcp|
      badcookie_response(request, cookie_bytes(0x44, 15))
    end)
    queue = Queue.new
    sender.send_async(Message.new('example.com'), queue)

    assert_equal(1, sender.requests.length)
    assert(queue.empty?)
    assert_nil(sender.instance_variable_get(:@server_cookie))
  end

  def test_response_without_cookie_is_rejected
    sender = RecordingPacketSender.new('192.0.2.1', lambda do |request, _number, _use_tcp|
      response = response_from_request(request)
      response.remove_additional
      response
    end)
    queue = Queue.new
    sender.send_async(Message.new('example.com'), queue)

    assert_equal(1, sender.requests.length)
    assert(queue.empty?)
  end

  private

  def send_query(sender)
    queue = Queue.new
    sender.send_async(Message.new('example.com'), queue)
    _id, response, error = queue.pop
    raise error if error
    response
  end

  def prepared_query(sender)
    message = Message.new('example.com')
    sender.make_query_packet(message)
    message
  end

  def successful_response(request)
    response = response_from_request(request)
    response
  end

  def badcookie_response(request, server_cookie, client_cookie = nil)
    response = response_from_request(request)
    response.header.rcode = 7
    response.get_opt.xrcode = 1
    response.get_opt.set_cookie(
      client_cookie || request.get_opt.cookie.client_cookie,
      server_cookie
    )
    response
  end

  def response_from_request(request)
    response = Message.decode(request.encode)
    response.header.qr = true
    response
  end

  def decode_raw_cookie(data)
    opt = raw_option_opt(COOKIE_CODE, data, 1)
    message = Message.new('example.com')
    message.add_additional(opt)
    Message.decode(message.encode)
  end

  def decode_raw_option_data(code, data, count)
    opt = raw_option_opt(code, data, count)
    message = Message.new('example.com')
    message.add_additional(opt)
    Message.decode(message.encode)
  end

  def raw_option_opt(code, data, count)
    opt = RR::OPT.new(4096)
    opt.define_singleton_method(:encode_rdata) do |msg, _canonical = false|
      data.bytes.each_slice(data.bytesize / count) do |slice|
        option_data = slice.pack('C*')
        msg.put_pack('nna*', code, option_data.bytesize, option_data)
      end
    end
    opt
  end

  def self.cookie_bytes(byte, length = 8)
    ([byte] * length).pack('C*')
  end

  def cookie_bytes(byte, length = 8)
    self.class.cookie_bytes(byte, length)
  end
end
