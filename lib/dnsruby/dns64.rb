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
  #  Dnsruby::DNS64 implements the DNS64 synthesis of AAAA records from
  #  A records (RFC 6147), embedding IPv4 addresses in IPv6 addresses
  #  according to the configured Pref64 (RFC 6052).
  #
  #  A DNS64 instance is configured with one or more Pref64 prefixes
  #  (defaulting to the well-known prefix 64:ff9b::/96) and a set of
  #  IPv4 exclusion ranges for which synthesis must not be performed
  #  (defaulting to the ranges listed in RFC 6052 section 3.1).
  #
  #  The resolution flow (DNS64#resolve) takes an AAAA query message and
  #  a block which sends a message and returns the response. The AAAA
  #  query is sent first. Only if the response is NOERROR with no AAAA
  #  records in the answer section (NODATA) is a follow-up A query made,
  #  and AAAA records synthesized from any A records returned. Responses
  #  which already contain AAAA records, and NXDOMAIN responses, are
  #  returned untouched.
  #
  #  Synthesized records are not authentic DNSSEC data, so the AD bit is
  #  cleared and a SECURE security level is downgraded to INSECURE on the
  #  synthesized response (RFC 6147 section 5.5).
  #
  #  == Example
  #    dns64 = Dnsruby::DNS64.new('64:ff9b::/96')
  #    res = Dnsruby::Resolver.new
  #    res.dns64 = dns64
  #    response = res.query('ipv4-only.example.com', Dnsruby::Types.AAAA)
  class DNS64
    #  The Pref64 prefix lengths defined by RFC 6052 section 2.2
    PREFIX_LENGTHS = [32, 40, 48, 56, 64, 96].freeze

    #  The well-known Pref64 (RFC 6052 section 2.1)
    WELL_KNOWN_PREFIX = '64:ff9b::/96'

    #  The IPv4 ranges which must not be used in IPv4-embedded IPv6
    #  addresses (RFC 6052 section 3.1)
    DEFAULT_IPV4_EXCLUSIONS = [
      '0.0.0.0/8', '127.0.0.0/8', '224.0.0.0/4', '255.255.255.255/32'
    ].freeze

    #  A Pref64 prefix and its length, used to embed IPv4 addresses in
    #  IPv6 addresses (RFC 6052 section 2.2)
    class Pref64
      #  The prefix length (one of DNS64::PREFIX_LENGTHS)
      attr_reader :length

      #  Takes a String of the form "prefix/length". If no length
      #  is given, /96 is assumed.
      def initialize(prefix)
        address, length = prefix.to_s.split('/', 2)
        @length = length.nil? ? 96 : Integer(length)
        unless DNS64::PREFIX_LENGTHS.include?(@length)
          raise ArgumentError.new(
            "Pref64 length must be one of #{DNS64::PREFIX_LENGTHS.join(', ')}")
        end
        @bits = IPv6.create(address).address.unpack('B128').first
        #  The prefix must be canonical : no bits may be set beyond the
        #  prefix length. For lengths of 64 and below, this also enforces
        #  the reserved "u" octet (bits 64-71) being zero (RFC 6052 2.2).
        if @bits[@length..-1].include?('1')
          raise ArgumentError.new(
            "Pref64 #{prefix} has bits set beyond its prefix length")
        end
      end

      #  Returns the IPv6 address (as a String) with the given IPv4
      #  address embedded after the prefix (RFC 6052 section 2.2)
      def synthesize(ipv4)
        v4_bits = IPv4.create(ipv4).address.unpack('B32').first
        bits = @bits.dup
        pos = @length
        v4_bits.each_char do |bit|
          #  Skip the reserved "u" octet (bits 64-71)
          pos += 8 if pos == 64
          bits[pos] = bit
          pos += 1
        end
        IPv6.new([bits].pack('B128')).to_s
      end
    end

    #  An IPv4 address range (in CIDR notation) for which synthesis
    #  must not be performed
    class IPv4Range
      def initialize(range)
        address, length = range.to_s.split('/', 2)
        length = length.nil? ? 32 : Integer(length)
        unless (0..32).include?(length)
          raise ArgumentError.new("Invalid IPv4 prefix length : #{length}")
        end
        @address = IPv4.create(address).address.unpack('N').first
        @mask = length.zero? ? 0 : (0xffffffff << (32 - length)) & 0xffffffff
      end

      def include?(ipv4)
        address = IPv4.create(ipv4).address.unpack('N').first
        (address & @mask) == (@address & @mask)
      end
    end

    #  The configured Pref64 prefixes (an Array of DNS64::Pref64)
    attr_reader :prefixes

    #  The configured IPv4 exclusion ranges (an Array of DNS64::IPv4Range)
    attr_reader :ipv4_exclusions

    #  Create a new DNS64 configuration.
    #
    #  * prefixes - a Pref64 String ("prefix/length") or an Array of such
    #    Strings. Defaults to the well-known prefix 64:ff9b::/96.
    #  * ipv4_exclusions - an Array of IPv4 ranges in CIDR notation for
    #    which synthesis is not performed. Defaults to
    #    DNS64::DEFAULT_IPV4_EXCLUSIONS.
    def initialize(prefixes = WELL_KNOWN_PREFIX, ipv4_exclusions: DEFAULT_IPV4_EXCLUSIONS)
      list = prefixes.is_a?(Array) ? prefixes : [prefixes]
      raise ArgumentError.new('At least one Pref64 must be configured') if list.empty?
      @prefixes = list.map { |prefix| Pref64.new(prefix) }
      @ipv4_exclusions = (ipv4_exclusions || []).map { |range| IPv4Range.new(range) }
    end

    #  Is the given IPv4 address in one of the configured exclusion ranges?
    def excluded_ipv4?(ipv4)
      @ipv4_exclusions.any? { |range| range.include?(ipv4) }
    end

    #  Returns the synthesized IPv6 addresses (one per configured Pref64)
    #  for the given IPv4 address, or an empty Array if the address is in
    #  an excluded range.
    def synthesize(ipv4)
      return [] if excluded_ipv4?(ipv4)
      @prefixes.map { |pref64| pref64.synthesize(ipv4) }
    end

    #  Should the given AAAA response be followed up with an A query?
    #  This is the case only for a NODATA response (NOERROR with no AAAA
    #  records in the answer section). Responses which already contain
    #  AAAA records, and negative responses such as NXDOMAIN, are
    #  returned to the client as they are (RFC 6147 section 5.1).
    def synthesis_required?(response)
      response.rcode == RCode::NOERROR &&
        response.answer.none? { |rr| rr.type == Types::AAAA }
    end

    #  Performs the DNS64 resolution flow for an AAAA query message.
    #  The block is called with a query message and must return the
    #  response message (raising Dnsruby::NXDomain for an NXDOMAIN
    #  response, as Resolver#send_message does).
    #
    #  Returns the final response message.
    def resolve(aaaa_message)
      response = yield aaaa_message
      return response unless synthesis_required?(response)

      a_message = build_a_query(aaaa_message)
      begin
        a_response = yield a_message
      rescue NXDomain
        #  The name existed for the AAAA query (NODATA) but not for the
        #  A query - return the original NODATA response.
        return response
      end
      synthesize_response(aaaa_message, a_response) || response
    end

    private

    def build_a_query(aaaa_message)
      message = Message.new
      message.do_caching = aaaa_message.do_caching
      message.do_validation = aaaa_message.do_validation
      message.header.rd = aaaa_message.header.rd
      message.header.cd = aaaa_message.header.cd
      aaaa_message.question.each do |question|
        message.add_question(question.qname, Types::A, question.qclass)
      end
      message
    end

    #  Builds a synthesized AAAA response from the A response, or returns
    #  nil if no synthesis can be performed (in which case the original
    #  AAAA response should be returned to the client).
    def synthesize_response(aaaa_message, a_response)
      return nil unless a_response.rcode == RCode::NOERROR
      a_records = a_response.answer.select { |rr| rr.type == Types::A }
      return nil if a_records.empty?

      synthesized = []
      a_records.each do |rr|
        synthesize(rr.address.to_s).each do |address|
          synthesized << RR.new_from_hash(
            name: rr.name.to_s, type: 'AAAA', klass: rr.klass,
            ttl: rr.ttl, address: address)
        end
      end
      return nil if synthesized.empty?

      message = Message.new
      message.header = a_response.header.dup
      #  Synthesized records are not authentic DNSSEC data, so the
      #  authenticity of the original response must not be claimed
      #  (RFC 6147 section 5.5).
      message.header.ad = false
      aaaa_message.question.each { |question| message.add_question(question) }
      #  Keep any non-A records (e.g. the CNAME chain) from the A response
      a_response.answer.each do |rr|
        message.add_answer(rr) unless rr.type == Types::A
      end
      synthesized.each { |rr| message.add_answer(rr) }
      a_response.authority.each { |rr| message.add_authority(rr) }
      a_response.additional.each { |rr| message.add_additional(rr) }
      message.do_validation = aaaa_message.do_validation
      message.do_caching = aaaa_message.do_caching
      message.answerfrom = a_response.answerfrom
      message.answerip = a_response.answerip
      message.security_error = a_response.security_error
      if a_response.security_level == Message::SecurityLevel::SECURE
        message.security_level = Message::SecurityLevel::INSECURE
      else
        message.security_level = a_response.security_level
      end
      message
    end
  end
end

