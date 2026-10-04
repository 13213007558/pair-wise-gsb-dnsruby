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
require 'dnsruby/ipv4'
require 'dnsruby/ipv6'

module Dnsruby
  # Dnsruby::DNS64 implements the optional DNS64 synthesis layer described
  # in RFC 6147, using the IPv4-embedded IPv6 address formats of RFC 6052.
  #
  # It lets IPv6-only clients reach services that publish only A records:
  # when an AAAA query comes back empty (NODATA), the layer asks the upstream
  # for the A records and synthesizes AAAA records by embedding each IPv4
  # address into the configured NAT64 prefix.  When the upstream already
  # returns real AAAA records, the original response is kept untouched.
  #
  # Upstream queries are performed through an injected interface, so this
  # layer can sit in front of a Dnsruby::Resolver, a cache, or a test fake.
  # The interface must accept a Dnsruby::Message query and return a
  # Dnsruby::Message response; it may be any object responding to
  # +query(message)+ or any callable (proc/lambda) taking the message.
  #
  # == DNSSEC policy (RFC 6147 section 5.5)
  #
  # Synthesized AAAA records are fabricated locally: they are NOT signed by
  # the zone owner and this layer never fabricates RRSIGs for them.  The
  # query flags steer synthesis as follows:
  #
  # * DO (DNSSEC OK, EDNS): when set by the client, the follow-up A query
  #   also carries DO so signatures are fetched.  RRSIGs covering the CNAME
  #   chain are preserved, but RRSIGs covering the A records are dropped
  #   (they do not cover the synthesized AAAA data and including them would
  #   misrepresent the signatures).
  # * CD (Checking Disabled): propagated to the upstream A query.  When the
  #   client sets CD it takes responsibility for validation, so the AD bit
  #   of a synthesized response is always cleared.
  # * Validated data: the AD bit on a synthesized response is set only when
  #   the +set_ad+ option is enabled AND the client query had DO set and CD
  #   clear AND the upstream A response carried AD (i.e. the upstream
  #   resolver validated the A records).  In every other case AD is cleared,
  #   because a DNS64 must not claim that synthesized data is authentic
  #   unless it vouches for the validation itself (RFC 6147 sections 3 and
  #   5.5).  Note that a security-aware stub resolver can never validate
  #   synthesized AAAA records against the zone's own signatures.
  #
  # == Example
  #
  #   dns64 = Dnsruby::DNS64.new(
  #     :prefix => '64:ff9b::/96',
  #     :query_interface => Dnsruby::Resolver.new
  #   )
  #   response = dns64.resolve(Dnsruby::Message.new('ipv4-only.example', 'AAAA'))
  #
  class DNS64
    # The Well-Known Prefix from RFC 6052 section 2.1.
    WELL_KNOWN_PREFIX = '64:ff9b::/96'

    # The prefix lengths permitted by RFC 6052 section 2.2.
    PREFIX_LENGTHS = [32, 40, 48, 56, 64, 96].freeze

    # The configured NAT64 prefix as a Dnsruby::IPv6
    attr_reader :prefix
    # The prefix length (one of PREFIX_LENGTHS)
    attr_reader :prefix_length

    # Create a new DNS64 synthesis layer.  Options:
    #
    # * +:prefix+ - NAT64 prefix as "address/length" (default 64:ff9b::/96).
    #   Only the RFC 6052 lengths 32, 40, 48, 56, 64 and 96 are accepted.
    # * +:query_interface+ - required; the upstream query interface (see
    #   the class documentation).
    # * +:max_ttl+ - optional cap (seconds) applied to synthesized AAAA TTLs.
    # * +:set_ad+ - allow AD=1 on synthesized responses when the upstream A
    #   response was validated (AD=1) and the client query had DO=1, CD=0.
    #   Defaults to false: synthesized answers never claim to be validated.
    # * +:synthesis_policy+ - optional callable invoked as
    #   +policy.call(client_query, a_response)+; synthesis is skipped (and
    #   the original empty AAAA response returned) unless it returns true.
    def initialize(options = {})
      @query_interface = options[:query_interface]
      unless @query_interface
        raise ArgumentError.new('DNS64 requires a :query_interface for upstream queries')
      end
      @prefix, @prefix_length = DNS64.parse_prefix(options[:prefix] || WELL_KNOWN_PREFIX)
      @max_ttl = options[:max_ttl]
      @set_ad = options[:set_ad] ? true : false
      @synthesis_policy = options[:synthesis_policy]
    end

    # Parse an "address/length" prefix, validating the length against
    # RFC 6052 and requiring all bits past the prefix length (including the
    # reserved "u" octet, bits 64-71) to be zero.  Returns [IPv6, length].
    def self.parse_prefix(prefix)
      address_part, length_part = prefix.to_s.split('/')
      unless address_part && length_part
        raise ArgumentError.new("DNS64 prefix must be of the form address/length: #{prefix.inspect}")
      end
      length = Integer(length_part)
      unless PREFIX_LENGTHS.include?(length)
        raise ArgumentError.new("DNS64 prefix length #{length} not in RFC 6052 set #{PREFIX_LENGTHS.inspect}")
      end
      address = IPv6.create(address_part)
      integer = address.address.unpack("C16").reduce(0) { |acc, byte| (acc << 8) | byte }
      if (integer & ((1 << (128 - length)) - 1)) != 0
        raise ArgumentError.new("DNS64 prefix #{prefix.inspect} has bits set beyond /#{length}")
      end
      return address, length
    end

    # Synthesize the IPv6 address for +ipv4+ (Dnsruby::IPv4 or String) under
    # +prefix+ ("address/length"), per RFC 6052 section 2.2.  For example,
    # DNS64.synthesize_address('192.0.2.33', '64:ff9b::/96') is
    # 64:ff9b::c000:221.
    def self.synthesize_address(ipv4, prefix = WELL_KNOWN_PREFIX)
      prefix_address, length = parse_prefix(prefix)
      embed(prefix_address, length, IPv4.create(ipv4))
    end

    # Embed +ipv4+ (Dnsruby::IPv4) into +prefix+ (Dnsruby::IPv6) of
    # +prefix_length+, returning a Dnsruby::IPv6.
    def self.embed(prefix, prefix_length, ipv4)
      prefix_int = prefix.address.unpack("C16").reduce(0) { |acc, byte| (acc << 8) | byte }
      ipv4_int = ipv4.address.unpack("C4").reduce(0) { |acc, byte| (acc << 8) | byte }
      synthesized =
        case prefix_length
        when 32 then prefix_int | (ipv4_int << 64)
        when 40 then prefix_int | ((ipv4_int >> 8) << 64) | ((ipv4_int & 0xff) << 48)
        when 48 then prefix_int | ((ipv4_int >> 16) << 64) | ((ipv4_int & 0xffff) << 40)
        when 56 then prefix_int | ((ipv4_int >> 24) << 64) | ((ipv4_int & 0xffffff) << 32)
        when 64 then prefix_int | (ipv4_int << 24)
        when 96 then prefix_int | ipv4_int
        else
          raise ArgumentError.new("DNS64 prefix length #{prefix_length} not in RFC 6052 set #{PREFIX_LENGTHS.inspect}")
        end
      IPv6.new([(synthesized >> 64) & 0xffffffffffffffff, synthesized & 0xffffffffffffffff].pack("Q>2"))
    end

    # Extract the embedded IPv4 address from a synthesized +ipv6+
    # (Dnsruby::IPv6 or String) under +prefix+, reversing RFC 6052 section
    # 2.2.  Returns a Dnsruby::IPv4, or nil if +ipv6+ does not start with
    # the prefix.
    def self.extract_ipv4(ipv6, prefix = WELL_KNOWN_PREFIX)
      prefix_address, length = parse_prefix(prefix)
      prefix_int = prefix_address.address.unpack("C16").reduce(0) { |acc, byte| (acc << 8) | byte }
      integer = IPv6.create(ipv6).address.unpack("C16").reduce(0) { |acc, byte| (acc << 8) | byte }
      return nil unless (integer >> (128 - length)) == (prefix_int >> (128 - length))
      ipv4_int =
        case length
        when 32 then (integer >> 64) & 0xffffffff
        when 40 then (((integer >> 64) & 0xffffff) << 8) | ((integer >> 48) & 0xff)
        when 48 then (((integer >> 64) & 0xffff) << 16) | ((integer >> 40) & 0xffff)
        when 56 then (((integer >> 64) & 0xff) << 24) | ((integer >> 32) & 0xffffff)
        when 64 then (integer >> 24) & 0xffffffff
        when 96 then integer & 0xffffffff
        end
      IPv4.new([(ipv4_int >> 24) & 0xff, (ipv4_int >> 16) & 0xff, (ipv4_int >> 8) & 0xff, ipv4_int & 0xff].pack("C4"))
    end

    # Resolve +query+ (a Dnsruby::Message, or a name to look up AAAA for)
    # with DNS64 synthesis applied.  Returns a Dnsruby::Message.
    #
    # * Non-AAAA questions are forwarded upstream untouched.
    # * Responses already containing AAAA records are returned as-is.
    # * NODATA (NOERROR, no AAAA) answers trigger an A query and synthesis.
    # * NXDOMAIN and other error responses are returned unchanged.
    def resolve(query)
      query = Message.new(query, Types.AAAA) unless query.kind_of?(Message)
      question = query.question.first
      unless question && question.qtype == Types.AAAA && question.qclass == Classes.IN
        return upstream(query)
      end

      aaaa_response = upstream(query)
      return aaaa_response unless aaaa_response.kind_of?(Message)
      return aaaa_response unless aaaa_response.rcode == RCode.NOERROR
      return aaaa_response if aaaa_response.answer.any? { |rr| rr.type == Types.AAAA }

      # NODATA for AAAA: fall back to A records per RFC 6147 section 5.1.
      a_response = upstream(build_a_query(query, question))
      return aaaa_response unless a_response.kind_of?(Message)
      return aaaa_response unless a_response.rcode == RCode.NOERROR

      a_records = a_response.answer.select { |rr| rr.type == Types.A }
      return aaaa_response if a_records.empty?
      return aaaa_response unless synthesis_allowed?(query, a_response)

      synthesize_response(query, aaaa_response, a_response, a_records)
    end

    # The IPv6 address synthesized for +ipv4+ under the configured prefix.
    def synthesize_address(ipv4)
      DNS64.embed(@prefix, @prefix_length, IPv4.create(ipv4))
    end

    private

    def upstream(query)
      if @query_interface.respond_to?(:query)
        @query_interface.query(query)
      else
        @query_interface.call(query)
      end
    end

    def synthesis_allowed?(query, a_response)
      return true unless @synthesis_policy
      @synthesis_policy.call(query, a_response) ? true : false
    end

    def dnssec_ok?(message)
      opt = message.get_opt
      opt ? opt.dnssec_ok : false
    end

    # Build the follow-up A query, propagating the client's RD and CD flags
    # and requesting DNSSEC records (DO) when the client did (RFC 6147
    # section 5.5).
    def build_a_query(client_query, question)
      a_query = Message.new(question.qname, Types.A, question.qclass)
      a_query.header.rd = client_query.header.rd
      a_query.header.cd = client_query.header.cd
      if dnssec_ok?(client_query)
        client_opt = client_query.get_opt
        opt = RR::OPT.new(client_opt ? client_opt.payloadsize : Resolver::DefaultUDPSize)
        opt.dnssec_ok = true
        a_query.add_additional(opt)
      end
      a_query
    end

    # Assemble the synthesized response: the CNAME chain (and, when DO was
    # set, its RRSIGs) is taken from the A response, and each A record
    # becomes a synthesized AAAA record.  RRSIGs covering the A records are
    # deliberately not carried over - they do not cover the synthesized
    # data, and no signatures are fabricated for it.
    def synthesize_response(query, aaaa_response, a_response, a_records)
      response = Message.new
      response.header = aaaa_response.header.dup
      query.question.each { |question| response.add_question(question) }

      a_response.answer.each do |rr|
        if rr.type == Types.CNAME
          response.add_answer(rr)
        elsif dnssec_ok?(query) && rr.type == Types.RRSIG && rr.type_covered == Types.CNAME
          response.add_answer(rr)
        end
      end

      a_records.each do |a_rr|
        ttl = @max_ttl ? [a_rr.ttl, @max_ttl].min : a_rr.ttl
        response.add_answer(RR.create(
          :name => a_rr.name,
          :type => Types.AAAA,
          :klass => a_rr.klass,
          :ttl => ttl,
          :address => synthesize_address(a_rr.address)))
      end

      a_response.authority.each { |rr| response.add_authority(rr) }
      a_response.additional.each { |rr| response.add_additional(rr) unless rr.type == Types::OPT }
      opt = aaaa_response.get_opt
      response.add_additional(opt) if opt

      # RFC 6147 section 5.5: AD may only be asserted on synthesized data
      # when this layer vouches for the validation (the upstream validated
      # the A records) and the client asked for DNSSEC without disabling
      # checking.  Synthesized records never carry original signatures.
      response.header.ad = @set_ad && dnssec_ok?(query) && !query.header.cd && a_response.header.ad ? true : false
      response.update_counts
      response
    end
  end
end
