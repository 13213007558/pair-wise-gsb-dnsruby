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
  #  ===DNS64 synthesis layer (RFC 6147) with RFC 6052 address mapping.
  # 
  #  DNS64 lets IPv6-only clients reach IPv4-only services: when a name
  #  has no AAAA record, the A record is mapped into a configured IPv6
  #  prefix and a synthetic AAAA record is returned.
  # 
  #  This layer is entirely optional and sits in front of an injected
  #  upstream resolver. The upstream is any object responding to
  #  +query(message)+ (e.g. Dnsruby::Resolver) or any callable taking a
  #  Dnsruby::Message and returning a Dnsruby::Message.
  # 
  #    upstream = Dnsruby::Resolver.new('2001:db8::53')
  #    dns64 = Dnsruby::DNS64::Resolver.new(:upstream => upstream)
  #    response = dns64.resolve('ipv4-only.example.com')
  # 
  #  ===Behaviour summary
  # 
  #  * If the upstream AAAA response already contains AAAA records, it is
  #    returned untouched.
  #  * NXDOMAIN and other error responses are passed through unchanged.
  #  * On NODATA (NOERROR, no AAAA), an A query is issued upstream, the
  #    CNAME chain is followed, and each terminal A record is mapped to a
  #    synthetic AAAA record. The synthetic TTL is the minimum of the
  #    constituent A record TTLs, optionally capped by +max_ttl+.
  #  * A policy object may forbid synthesis for a given response; the
  #    original (empty) AAAA response is then returned instead.
  # 
  #  ===DNSSEC considerations (RFC 6147 sections 3 and 5.5)
  # 
  #  * DO bit: when the client query has DO set, the upstream queries are
  #    sent with DO set as well, so a validating upstream can report the
  #    DNSSEC status of the A records via Message#security_level.
  #  * CD bit: when the client query has CD set, the client takes
  #    responsibility for validation, so a BOGUS A response does not
  #    block synthesis. With CD clear, a BOGUS A response yields SERVFAIL
  #    and no synthetic data is returned.
  #  * Validated data: DNS64 does not (and cannot) sign the synthetic
  #    AAAA records - it does not own the zone. Synthesized responses
  #    therefore never carry RRSIGs copied from the A records, never set
  #    the AD bit, and are reported with SecurityLevel::UNCHECKED. The
  #    AD bit from upstream is never propagated onto synthesized answers.
  module DNS64
    #  An IPv6 prefix into which IPv4 addresses are mapped, as defined by
    #  RFC 6052. Only the prefix lengths listed in RFC 6052 section 2.2
    #  are supported: 32, 40, 48, 56, 64 and 96.
    # 
    #    prefix = Dnsruby::DNS64::Prefix.new('64:ff9b::/96')
    #    prefix.synthesize(Dnsruby::IPv4.create('192.0.2.33')).to_s
    #    # => "64:ff9b::c000:221"
    class Prefix
      #  The prefix lengths permitted by RFC 6052 section 2.2
      SUPPORTED_LENGTHS = [32, 40, 48, 56, 64, 96].freeze

      #  The prefix length in bits
      attr_reader :length

      #  Create a prefix from a string of the form "ipv6-prefix/length",
      #  or from a Dnsruby::IPv6 (or parseable String) plus a length.
      def initialize(prefix, length = nil)
        if length.nil?
          unless prefix.kind_of?(String) && prefix.include?('/')
            raise ArgumentError.new("prefix must be of the form 'ipv6-prefix/length': #{prefix.inspect}")
          end
          prefix, length = prefix.split('/', 2)
          length = Integer(length)
        end
        length = Integer(length)
        unless SUPPORTED_LENGTHS.include?(length)
          raise ArgumentError.new("unsupported DNS64 prefix length #{length} " \
            "(RFC 6052 allows #{SUPPORTED_LENGTHS.join(', ')})")
        end
        @length = length
        @bytes = Prefix.mask(IPv6.create(prefix).address.bytes, length)
      end

      #  Map a Dnsruby::IPv4 (or dotted-quad String) into this prefix,
      #  returning a Dnsruby::IPv6. The layout follows RFC 6052
      #  section 2.2, with bits 64-71 (the 'u' octet) kept at zero.
      def synthesize(ipv4)
        v4 = IPv4.create(ipv4).address.bytes
        out = @bytes.dup
        case @length
        when 32
          out[4, 4] = v4
        when 40
          out[5, 3] = v4[0, 3]
          out[9] = v4[3]
        when 48
          out[6, 2] = v4[0, 2]
          out[9, 2] = v4[2, 2]
        when 56
          out[7] = v4[0]
          out[9, 3] = v4[1, 3]
        when 64
          out[9, 4] = v4
        when 96
          out[12, 4] = v4
        end
        IPv6.new(out.pack('C*'))
      end

      def to_s
        "#{IPv6.new(@bytes.pack('C*'))}/#{@length}"
      end

      #  Zero out every bit past +length+ in a 16-byte array :nodoc:
      def self.mask(bytes, length)
        bytes = bytes.dup
        (0...16).each do |i|
          bits = length - (i * 8)
          if bits <= 0
            bytes[i] = 0
          elsif bits < 8
            bytes[i] &= (0xff << (8 - bits)) & 0xff
          end
        end
        bytes
      end

      #  The Well-Known Prefix from RFC 6052 section 2.1
      WELL_KNOWN = new('64:ff9b::/96')
    end

    #  Policies decide whether a given upstream response may be turned
    #  into synthetic AAAA records. A policy is any object responding to
    #  +allows?(query_message, response_message)+, or a callable taking
    #  those two arguments. When a policy denies synthesis, the original
    #  (empty) AAAA response is returned to the client unchanged.
    module Policy
      #  Permits synthesis for every response (the default).
      class AllowAll
        def allows?(_query, _response)
          true
        end
      end

      #  Forbids synthesis entirely; every AAAA NODATA response is
      #  returned to the client as-is.
      class DenyAll
        def allows?(_query, _response)
          false
        end
      end

      #  Forbids synthesis whenever any A record in the response answer
      #  falls inside one of the given IPv4 CIDR ranges (for example
      #  RFC 1918 or documentation ranges that must not be mapped into
      #  the DNS64 prefix).
      # 
      #    policy = Dnsruby::DNS64::Policy::ExcludeIPv4Ranges.new(
      #      '10.0.0.0/8', '192.168.0.0/16', '192.0.2.0/24')
      class ExcludeIPv4Ranges
        def initialize(*cidrs)
          @ranges = cidrs.map do |cidr|
            address, bits = cidr.split('/', 2)
            bits = bits.nil? ? 32 : Integer(bits)
            unless (0..32).cover?(bits)
              raise ArgumentError.new("invalid IPv4 CIDR prefix length: #{cidr.inspect}")
            end
            base = IPv4.create(address).address.unpack1('N')
            mask = bits.zero? ? 0 : (0xffffffff << (32 - bits)) & 0xffffffff
            [base & mask, mask]
          end
        end

        def allows?(_query, response)
          response.answer.none? do |rr|
            next false unless rr.type == Types::A
            value = rr.address.address.unpack1('N')
            @ranges.any? { |base, mask| (value & mask) == base }
          end
        end
      end

      ALLOW_ALL = AllowAll.new
      DENY_ALL = DenyAll.new
    end

    #  The DNS64 resolution layer itself. Wraps an injected upstream
    #  resolver and adds RFC 6147 synthesis on top of it.
    class Resolver
      #  The DNS64::Prefix used for synthesis
      attr_reader :prefix

      #  The synthesis policy
      attr_reader :policy

      #  Optional upper bound for synthetic AAAA TTLs (seconds)
      attr_reader :max_ttl

      #  * +:upstream+ - required. Anything responding to
      #    +query(message)+, or a callable taking a Dnsruby::Message and
      #    returning the upstream Dnsruby::Message response.
      #  * +:prefix+ - a DNS64::Prefix (or "prefix/length" String).
      #    Defaults to the RFC 6052 Well-Known Prefix 64:ff9b::/96.
      #  * +:policy+ - a policy object or callable. Defaults to
      #    DNS64::Policy::ALLOW_ALL.
      #  * +:max_ttl+ - optional cap (seconds) for synthetic AAAA TTLs.
      def initialize(upstream:, prefix: Prefix::WELL_KNOWN, policy: Policy::ALLOW_ALL, max_ttl: nil)
        @upstream = upstream
        @prefix = prefix.kind_of?(Prefix) ? prefix : Prefix.new(prefix)
        @policy = policy
        @max_ttl = max_ttl
      end

      #  Convenience entry point: issue an AAAA query for +name+ through
      #  the DNS64 layer. +:do_bit+ and +:cd+ mirror the DNSSEC flags a
      #  client would place on its query (see the DNS64 module docs).
      def resolve(name, do_bit: false, cd: false)
        query = Message.new(name, Types::AAAA)
        query.header.rd = true
        query.header.cd = cd
        if do_bit
          opt = RR::OPT.new(DEFAULT_UDP_SIZE)
          opt.dnssec_ok = true
          query.add_additional(opt)
        end
        query(query)
      end

      #  Process a client AAAA query Message, synthesizing from A records
      #  when the name is IPv4-only. Non-AAAA questions and responses
      #  that already carry AAAA data are passed through untouched.
      def query(client_query)
        question = client_query.question[0]
        return send_upstream(client_query) if question.nil? || question.qtype != Types::AAAA

        do_bit = client_do_bit?(client_query)
        cd = client_query.header.cd == true

        aaaa_response = send_upstream(build_upstream_query(question, Types::AAAA, do_bit, cd, client_query.header.id))
        return aaaa_response unless nodata?(aaaa_response)
        return aaaa_response unless policy_allows?(client_query, aaaa_response)

        a_response = send_upstream(build_upstream_query(question, Types::A, do_bit, cd, client_query.header.id))
        return aaaa_response unless a_response.rcode == RCode::NOERROR

        if bogus?(a_response) && !cd
          #  RFC 6147 section 5.5: with CD clear, a BOGUS A response must
          #  not be synthesized from; the client gets SERVFAIL instead.
          return error_response(client_query, RCode::SERVFAIL)
        end
        return aaaa_response unless policy_allows?(client_query, a_response)

        cnames, a_records = follow_chain(question.qname, a_response)
        return aaaa_response if a_records.empty?

        synthesize_response(client_query, aaaa_response, cnames, a_records)
      end

      private

      DEFAULT_UDP_SIZE = 4096

      def send_upstream(message)
        if @upstream.respond_to?(:query)
          @upstream.query(message)
        else
          @upstream.call(message)
        end
      end

      def build_upstream_query(question, type, do_bit, cd, id)
        query = Message.new(question.qname, type, question.qclass)
        query.header.id = id
        query.header.rd = true
        query.header.cd = cd
        if do_bit
          opt = RR::OPT.new(DEFAULT_UDP_SIZE)
          opt.dnssec_ok = true
          query.add_additional(opt)
        end
        query
      end

      def client_do_bit?(client_query)
        opt = client_query.get_opt
        !opt.nil? && opt.respond_to?(:dnssec_ok) && opt.dnssec_ok == true
      end

      #  NOERROR with no AAAA records in the answer section
      def nodata?(response)
        response.rcode == RCode::NOERROR &&
          response.answer.none? { |rr| rr.type == Types::AAAA }
      end

      def bogus?(response)
        response.security_level == Message::SecurityLevel::BOGUS
      end

      def policy_allows?(query, response)
        if @policy.respond_to?(:allows?)
          @policy.allows?(query, response)
        else
          @policy.call(query, response)
        end
      end

      #  Walk the CNAME chain from +name+ through the A response answer
      #  section, returning [cname RRs in chain order, terminal A RRs].
      def follow_chain(name, a_response)
        current = Name.create(name).canonical
        cnames = []
        a_records = []
        visited = {}
        loop do
          break if visited[current]
          visited[current] = true
          found_cname = nil
          a_response.each_answer do |rr|
            next unless Name.create(rr.name).canonical == current
            if rr.type == Types::CNAME
              found_cname = rr
            elsif rr.type == Types::A
              a_records << rr
            end
          end
          break if found_cname.nil?
          cnames << found_cname
          current = Name.create(found_cname.domainname).canonical
        end
        [cnames, a_records]
      end

      def synthesize_response(client_query, aaaa_response, cnames, a_records)
        ttl = a_records.map(&:ttl).min
        ttl = [ttl, @max_ttl].min if @max_ttl

        response = base_response(client_query, aaaa_response, RCode::NOERROR)
        cnames.each { |rr| response.add_answer(rr) }
        a_records.each do |a|
          response.add_answer(RR.create(
            :name => a.name,
            :type => Types::AAAA,
            :klass => a.klass,
            :ttl => ttl,
            :address => @prefix.synthesize(a.address).to_s))
        end
        response
      end

      def error_response(client_query, rcode)
        base_response(client_query, nil, rcode)
      end

      #  Build a response skeleton for the client query. Synthetic
      #  answers never carry the AD bit, never carry RRSIGs, and are
      #  reported UNCHECKED: DNS64 cannot sign for the zone, so the
      #  original signatures (if any) do not cover the synthetic data.
      def base_response(client_query, upstream_response, rcode)
        response = Message.new
        response.header.id = client_query.header.id
        response.header.qr = true
        response.header.opcode = client_query.header.opcode
        response.header.rd = client_query.header.rd
        response.header.cd = client_query.header.cd
        response.header.ra = upstream_response ? upstream_response.header.ra : true
        response.header.aa = false
        response.header.ad = false
        response.header.rcode = rcode
        client_query.each_question do |q|
          response.add_question(Question.new(q.qname, q.qtype, q.qclass))
        end
        response.security_level = Message::SecurityLevel::UNCHECKED
        response
      end
    end
  end
end
