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

#  Tests for RFC 7873 DNS Cookies : strict COOKIE option codec, per-server
#  server cookie caching, bounded BADCOOKIE retries and rejection of
#  malformed or mismatched cookies.
class TestCookie < Minitest::Test
  include Dnsruby

  CLIENT_COOKIE = 'c' * 8
  SERVER_COOKIE = 's' * 16
  SERVER_COOKIE_2 = 't' * 16

  #  A PacketSender which records every packet it would send, and answers
  #  each query synchronously through a caller-supplied responder block
  #  instead of using the network.
  class RecordingSender < Dnsruby::PacketSender
    attr_reader :requests

    def initialize(args, &responder)
      @requests = []
      @responder = responder
      super(args)
    end

    def send_dnsruby(query_bytes, query, client_query_id, client_queue, use_tcp)
      @requests << query_bytes
      response = @responder.call(Dnsruby::Message.decode(query_bytes), @requests.length)
      response_bytes = response.encode
      if check_response(response, response_bytes, query, client_queue, client_query_id, use_tcp)
        client_queue.push([client_query_id, response, nil])
      end
    end
  end

  def setup
    Dnsruby.log.level = Logger::FATAL
  end

  #  ----- strict codec -----

  def test_round_trip_client_cookie_only
    cookie = Dnsruby::Cookie.new(CLIENT_COOKIE)
    assert_nil cookie.server
    decoded = Dnsruby::Cookie.decode(cookie.encode)
    assert_equal cookie, decoded
    assert_equal CLIENT_COOKIE, decoded.client
    assert_nil decoded.server
  end

  def test_round_trip_client_and_server_cookie
    cookie = Dnsruby::Cookie.new(CLIENT_COOKIE, SERVER_COOKIE)
    decoded = Dnsruby::Cookie.decode(cookie.encode)
    assert_equal cookie, decoded
    assert_equal SERVER_COOKIE, decoded.server
  end

  def test_decode_rejects_invalid_lengths
    [0, 7, 9, 15, 41, 100].each do |len|
      assert_raises(Dnsruby::DecodeError) { Dnsruby::Cookie.decode('x' * len) }
    end
  end

  def test_decode_accepts_valid_lengths
    [8, 16, 24, 40].each do |len|
      cookie = Dnsruby::Cookie.decode('x' * len)
      assert_equal 'x' * 8, cookie.client
    end
  end

  def test_new_rejects_invalid_lengths
    assert_raises(ArgumentError) { Dnsruby::Cookie.new('short') }
    assert_raises(ArgumentError) { Dnsruby::Cookie.new(CLIENT_COOKIE, 'short') }
    assert_raises(ArgumentError) { Dnsruby::Cookie.new(CLIENT_COOKIE, 's' * 33) }
  end

  #  ----- resolver behaviour over the fake transport -----

  def make_query
    msg = Dnsruby::Message.new('example.com', Dnsruby::Types.A)
    msg.do_caching = false
    msg
  end

  def cookie_of(request_bytes)
    opt = Dnsruby::Message.decode(request_bytes).get_opt
    option = opt ? opt.cookie_option : nil
    option ? Dnsruby::Cookie.decode(option.data) : nil
  end

  def build_response(query)
    response = Dnsruby::Message.new
    response.header.id = query.header.id
    response.header.qr = true
    response.add_question(query.question[0])
    response
  end

  def add_cookie_option(response, cookie)
    opt = response.get_opt
    unless opt
      opt = Dnsruby::RR::OPT.new(1232)
      response.add_additional(opt)
    end
    opt.options = [Dnsruby::RR::OPT::Option.new(Dnsruby::Cookie::OPTION_CODE, cookie.encode)]
    opt
  end

  def make_badcookie(response, cookie)
    opt = add_cookie_option(response, cookie)
    opt.xrcode = 1
    response.header.rcode = 7 # 7 + (1 << 4) == 23 == BADCOOKIE
    response
  end

  def challenge_then_answer
    lambda do |query_msg, count|
      response = build_response(query_msg)
      if count == 1
        make_badcookie(response, Dnsruby::Cookie.new(CLIENT_COOKIE, SERVER_COOKIE))
      else
        add_cookie_option(response, Dnsruby::Cookie.new(CLIENT_COOKIE, SERVER_COOKIE))
      end
      response
    end
  end

  def test_badcookie_retry_carries_new_server_cookie
    generator_calls = 0
    generator = -> { generator_calls += 1; CLIENT_COOKIE }
    sender = RecordingSender.new({server: '10.1.2.3', client_cookie_generator: generator},
        &challenge_then_answer)

    queue = Queue.new
    sender.send_async(make_query, queue)
    _id, response, error = queue.pop

    assert_nil error
    assert_equal 0, response.rcode.code
    assert_equal 2, sender.requests.length

    first = cookie_of(sender.requests[0])
    assert_equal CLIENT_COOKIE, first.client
    assert_nil first.server

    #  The retry must carry the server cookie learned from the BADCOOKIE
    #  response, and keep the same client cookie
    second = cookie_of(sender.requests[1])
    assert_equal CLIENT_COOKIE, second.client
    assert_equal SERVER_COOKIE, second.server

    #  The client cookie is generated once per query, not once per packet
    assert_equal 1, generator_calls
    assert_equal SERVER_COOKIE, sender.server_cookie
  end

  def test_repeated_badcookie_is_bounded
    responder = lambda do |query_msg, count|
      response = build_response(query_msg)
      make_badcookie(response, Dnsruby::Cookie.new(CLIENT_COOKIE, "srv#{count}".ljust(8, 'x')))
      response
    end
    sender = RecordingSender.new({server: '10.1.2.3', client_cookie_generator: -> { CLIENT_COOKIE }},
        &responder)

    queue = Queue.new
    sender.send_async(make_query, queue)
    _id, response, error = queue.pop

    assert_nil error
    assert_equal 23, response.rcode.code # BADCOOKIE
    #  The server challenged every time, but the retry count is bounded
    assert_equal 1 + Dnsruby::PacketSender::DEFAULT_COOKIE_MAX_RETRIES, sender.requests.length

    #  Each retry carried the server cookie learned from the previous
    #  BADCOOKIE response
    sender.requests.each_with_index do |request, i|
      next if i == 0
      assert_equal "srv#{i}".ljust(8, 'x'), cookie_of(request).server
    end
  end

  def test_mismatched_client_cookie_response_is_dropped
    responder = lambda do |query_msg, _count|
      response = build_response(query_msg)
      add_cookie_option(response, Dnsruby::Cookie.new('q' * 8, SERVER_COOKIE))
      response
    end
    sender = RecordingSender.new({server: '10.1.2.3', client_cookie_generator: -> { CLIENT_COOKIE }},
        &responder)

    queue = Queue.new
    sender.send_async(make_query, queue)

    assert_equal 1, sender.requests.length
    assert queue.empty?, 'Response with mismatched client cookie must be dropped'
    assert_nil sender.server_cookie
  end

  def test_malformed_cookie_response_is_dropped
    responder = lambda do |query_msg, _count|
      response = build_response(query_msg)
      opt = add_cookie_option(response, Dnsruby::Cookie.new(CLIENT_COOKIE))
      opt.options = [Dnsruby::RR::OPT::Option.new(Dnsruby::Cookie::OPTION_CODE, 'abc')]
      response
    end
    sender = RecordingSender.new({server: '10.1.2.3', client_cookie_generator: -> { CLIENT_COOKIE }},
        &responder)

    queue = Queue.new
    sender.send_async(make_query, queue)

    assert_equal 1, sender.requests.length
    assert queue.empty?, 'Response with malformed COOKIE option must be dropped'
    assert_nil sender.server_cookie
  end

  def test_server_cookies_are_not_shared_across_servers
    sender_a = RecordingSender.new({server: '10.1.2.3', client_cookie_generator: -> { CLIENT_COOKIE }},
        &challenge_then_answer)
    queue_a = Queue.new
    sender_a.send_async(make_query, queue_a)
    queue_a.pop
    assert_equal SERVER_COOKIE, sender_a.server_cookie

    #  A session with a different server must not use the cookie learned
    #  from the first server
    ok_responder = lambda do |query_msg, _count|
      response = build_response(query_msg)
      add_cookie_option(response, Dnsruby::Cookie.new(CLIENT_COOKIE, SERVER_COOKIE_2))
      response
    end
    sender_b = RecordingSender.new({server: '10.2.3.4', client_cookie_generator: -> { CLIENT_COOKIE }},
        &ok_responder)
    queue_b = Queue.new
    sender_b.send_async(make_query, queue_b)
    queue_b.pop

    assert_equal 1, sender_b.requests.length
    cookie_b = cookie_of(sender_b.requests[0])
    assert_equal CLIENT_COOKIE, cookie_b.client
    assert_nil cookie_b.server
    assert_equal SERVER_COOKIE_2, sender_b.server_cookie
    assert_equal SERVER_COOKIE, sender_a.server_cookie
  end

  def test_server_cookie_reused_within_session
    sender = RecordingSender.new({server: '10.1.2.3', client_cookie_generator: -> { CLIENT_COOKIE }},
        &challenge_then_answer)
    queue = Queue.new
    sender.send_async(make_query, queue)
    queue.pop

    #  A new query to the same server carries the learned server cookie
    #  straight away - no fresh BADCOOKIE challenge is needed
    sender.send_async(make_query, queue)
    queue.pop

    assert_equal 3, sender.requests.length
    third = cookie_of(sender.requests[2])
    assert_equal CLIENT_COOKIE, third.client
    assert_equal SERVER_COOKIE, third.server
  end

  def test_no_cookie_option_without_generator
    responder = ->(query_msg, _count) { build_response(query_msg) }
    sender = RecordingSender.new({server: '10.1.2.3'}, &responder)

    queue = Queue.new
    sender.send_async(make_query, queue)
    queue.pop

    assert_equal 1, sender.requests.length
    assert_nil cookie_of(sender.requests[0])
  end

  def test_generator_must_return_8_bytes
    responder = ->(query_msg, _count) { build_response(query_msg) }
    sender = RecordingSender.new({server: '10.1.2.3', client_cookie_generator: -> { 'short' }}, &responder)
    assert_raises(ArgumentError) { sender.send_async(make_query, Queue.new) }
  end
end
