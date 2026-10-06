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

module Dnsruby
  #  == Description
  #  Dnsruby::DNS64 is an optional DNS64 layer (RFC 6147) which sits in
  #  front of a resolver. AAAA queries are passed to the underlying resolver
  #  first; only when the response comes back without AAAA records (a NODATA
  #  answer, possibly carrying a CNAME chain) is a follow-up A query made.
  #  Any A records returned are then mapped into the configured Pref64
  #  prefix, using the IPv4-embedded IPv6 address format of RFC 6052, and
  #  the synthesized AAAA records are returned to the caller.
  #
  #  Responses which already contain AAAA records, NXDOMAIN (and other
  #  error) responses, and queries for other types are returned untouched.
  #
  #  Synthesized records are not authentic data: the AD bit is cleared and
  #  the DNSSEC security level of the synthesized response is reset to
  #  UNCHECKED, regardless of the validation state of the original answers
  #  (see RFC 6147 section 5.5).
  #
  #  == Example
  #
  #    require 'dnsruby'
  #    res = Dnsruby::Resolver.new
  #    dns64 = Dnsruby::DNS64.new(res, pref64: '64:ff9b::/96',
  #                               excluded_ipv4: %w(10.0.0.0/8 192.168.0.0/16))
  #    response = dns64.query('example.com', Dnsruby::Types.AAAA)
  class DNS64
    #  The Well-Known Prefix (RFC 6052 section 2.1)
    DEFAULT_PREF64 = '64:ff9b::/96'

    #  The prefix lengths defined by RFC 6052 section 2.2
    PREFIX_LENGTHS = [32, 40, 48, 56, 64, 96].freeze

    #  The resolver (or any object responding to #query) used to perform
    #  the actual lookups.
    attr_reader :resolver

    #  The Pref64 prefix length (one of PREFIX_LENGTHS)
    attr_reader :prefix_length

    #  The Pref64 prefix as a Dnsruby::IPv6 address
    attr_reader :prefix

    #  Create a DNS64 layer over +resolver+.
    #
    #  *  pref64: the Pref64 prefix, either as 'address/length' (e.g.
    #     '64:ff9b::/96') or as a bare IPv6 address (in which case
    #     prefix_length applies, defaulting to 96). Only the RFC 6052
    #     prefix lengths (32, 40, 48, 56, 64 and 96) are accepted, and the
    #     prefix must have no bits set beyond its length.
    #  *  excluded_ipv4: an array of IPv4 ranges (CIDR strings such as
    #     '10.0.0.0/8', or bare addresses meaning a /32). A records falling
    #     inside these ranges are not synthesized (RFC 6147 section 5.1.4).
    def initialize(resolver, pref64: DEFAULT_PREF64, prefix_length: nil, excluded_ipv4: [])
      @resolver = resolver
      if pref64.is_a?(String) && pref64.include?('/')
        address, length = pref64.split('/', 2)
        prefix_length = length.to_i
      else
        address = pref64
      end
      prefix_length = 96 if prefix_length.nil?
      unless PREFIX_LENGTHS.include?(prefix_length)
        raise ArgumentError.new("Pref64 prefix length must be one of #{PREFIX_LENGTHS.join(', ')}")
      end
      @prefix = IPv6.create(address)
      @prefix_length = prefix_length
      @prefix_int = @prefix.address.unpack('C16').inject(0) {|int, byte| (int << 8) | byte}
      if (@prefix_int & ((1 << (128 - prefix_length)) - 1)) != 0
        raise ArgumentError.new("Pref64 prefix #{@prefix} has bits set beyond /#{prefix_length}")
      end
      @excluded_ipv4 = excluded_ipv4.map {|range| DNS64.parse_ipv4_range(range)}
    end

    #  Query through the DNS64 layer. AAAA queries which come back without
    #  AAAA records trigger a follow-up A query and synthesis; everything
    #  else is passed straight through.
    def query(name, type=Types.A, klass=Classes.IN)
      response = @resolver.query(name, type, klass)
      return response unless synthesizable?(type, response)
      a_response = @resolver.query(name, Types.A, klass)
      synthesize_response(response, a_response) || response
    end

    #  Like query, but returns [response, error] instead of raising.
    def query!(name, type=Types.A, klass=Classes.IN)
      response = nil; error = nil
      begin
        response = query(name, type, klass)
      rescue => e
        error = e
      end
      [response, error]
    end

    #  Embed an IPv4 address into the configured Pref64 prefix, following
    #  the RFC 6052 section 2.2 address format: the 32 IPv4 bits immediately
    #  follow the prefix, skipping the 'u' octet (bits 64-71) for the
    #  32-64 bit prefix lengths. Returns a Dnsruby::IPv6.
    def synthesize_address(ipv4)
      v4_int = IPv4.create(ipv4).address.unpack('C4').inject(0) {|int, byte| (int << 8) | byte}
      v6_int = @prefix_int
      32.times do |i|
        bit = (v4_int >> (31 - i)) & 1
        next if bit == 0
        position = @prefix_length + i
        position += 8 if position >= 64 && @prefix_length != 96
        v6_int |= bit << (127 - position)
      end
      IPv6.new([v6_int.to_s(16).rjust(32, '0')].pack('H32'))
    end

    #  Is this IPv4 address inside one of the configured exclusion ranges?
    def excluded_ipv4?(ipv4)
      v4_int = IPv4.create(ipv4).address.unpack('C4').inject(0) {|int, byte| (int << 8) | byte}
      @excluded_ipv4.any? {|base, mask| (v4_int & mask) == base}
    end

    #  Parse an IPv4 CIDR range ('10.0.0.0/8' or '10.0.0.0') into
    #  [base, mask] integers. :nodoc:
    def self.parse_ipv4_range(range)
      address, length = range.to_s.split('/', 2)
      length = length.nil? ? 32 : length.to_i
      unless (0..32).cover?(length)
        raise ArgumentError.new("Invalid IPv4 range prefix length: #{range}")
      end
      mask = length == 0 ? 0 : (0xffffffff << (32 - length)) & 0xffffffff
      base = IPv4.create(address).address.unpack('C4').inject(0) {|int, byte| (int << 8) | byte}
      [base & mask, mask]
    end

    private

    #  Only NOERROR AAAA responses without any AAAA record in the answer
    #  section (NODATA, with or without a CNAME chain) are eligible for
    #  synthesis. Existing AAAA records, NXDOMAIN and other errors are
    #  returned to the caller untouched.
    def synthesizable?(type, response)
      Types.new(type) == Types::AAAA &&
        response.rcode == RCode.NOERROR &&
        !response.answer.any? {|rr| rr.type == Types::AAAA}
    end

    #  Build the synthesized response from the original AAAA response and
    #  the follow-up A response. Returns nil when there is nothing to
    #  synthesize (no usable A records), in which case the original AAAA
    #  response should be returned instead.
    def synthesize_response(aaaa_response, a_response)
      return nil unless a_response.rcode == RCode.NOERROR
      a_records = a_response.answer.select {|rr| rr.type == Types::A && !excluded_ipv4?(rr.address)}
      return nil if a_records.empty?

      synthesized = Message.decode(aaaa_response.encode)
      #  Keep the original CNAME chain (if any); fall back to the chain
      #  from the A response when the AAAA answer section was empty.
      chain = synthesized.answer.to_a
      chain = a_response.answer.select {|rr| rr.type != Types::A} if chain.empty?
      answer = chain + a_records.map do |a_rr|
        RR.create(name: a_rr.name, type: Types::AAAA, klass: a_rr.klass,
                  ttl: a_rr.ttl, address: synthesize_address(a_rr.address).to_s)
      end
      synthesized.answer.clear
      answer.each {|rr| synthesized.add_answer(rr)}
      #  Synthesized records are not authentic data: do not propagate the
      #  original AD bit or DNSSEC validation state (RFC 6147 section 5.5).
      synthesized.header.ad = false
      synthesized.security_level = Message::SecurityLevel.UNCHECKED
      synthesized.security_error = nil
      synthesized
    end
  end
end
