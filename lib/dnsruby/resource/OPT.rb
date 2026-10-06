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
require 'ipaddr'

module Dnsruby
  class RR
    # Class for EDNS pseudo resource record OPT.
    # This class is effectively internal to Dnsruby
    # See RFC 2671, RFC 2435 Section 3
    #  @TODO@ Extended labels RFC2671 section 3
    class OPT < RR #:nodoc: all
      ClassValue = nil #:nodoc: all
      TypeValue = Types::OPT #:nodoc: all
      DO_BIT = 0x8000

      EDNS_SUBNET_OPTION = 8

      #  @TODO@ Add BADVERS to an XRCode CodeMapper object

      # Can be called with up to 3 arguments, none of which must be present
      # * OPT.new()
      # * OPT.new(size)
      # * OPT.new(size,flags)
      # * OPT.new(size,flags,options)
      def initialize(*args)
        init_defaults
        @type = Types.new('OPT')
        @ttl = nil

        @options=[]
        if (args.length > 0)
          self.payloadsize=(args[0])
          if (args.length > 1)
            self.flags=(args[1])
            if (args.length > 2)
              self.options=(args[2])
            else
              self.options=[]
            end
          else
            self.flags=0
          end
        else
          self.payloadsize = 0
          self.flags = 0
          self.options = []
        end
      end

      def init_defaults
        self.name = Name.create('')
      end

      #  From RFC 2671 :
      #  4.3. The fixed part of an OPT RR is structured as follows:
      # 
      #      Field Name   Field Type     Description
      #      ------------------------------------------------------
      #      NAME         domain name    empty (root domain)
      #      TYPE         u_int16_t      OPT
      #      CLASS        u_int16_t      sender's UDP payload size
      #      TTL          u_int32_t      extended RCODE and flags
      #      RDLEN        u_int16_t      describes RDATA
      #      RDATA        octet stream   {attribute,value} pairs

      # 4.6. The extended RCODE and flags (which OPT stores in the RR TTL field)
      # are structured as follows:
      # 
      #                  +0 (MSB)                            +1 (LSB)
      #       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      #    0: |         EXTENDED-RCODE        |            VERSION            |
      #       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      #    2: |                               Z                               |
      #       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      # 
      #    EXTENDED-RCODE  Forms upper 8 bits of extended 12-bit RCODE.  Note
      #                    that EXTENDED-RCODE value "0" indicates that an
      #                    unextended RCODE is in use (values "0" through "15").
      # 
      #    VERSION         Indicates the implementation level of whoever sets
      #                    it.  Full conformance with this specification is
      #                    indicated by version "0."

      def flags_from_ttl
        if (@ttl)
          return [@ttl].pack("N")
        else
          return [0].pack("N")
        end
      end

      def xrcode
        return ExtendedRCode.new(flags_from_ttl[0, 1].unpack("C")[0])
      end

      def xrcode=(c)
        code = ExtendedRCode.new(c)
        @ttl = (code.code << 24) + (version() << 16) + flags()
      end

      def version
        return flags_from_ttl[1, 1].unpack("C")[0]
      end

      def version=(code)
        @ttl = (xrcode().code << 24) + (code << 16) + flags()
      end

      def flags
        return flags_from_ttl[2, 2].unpack("n")[0]
      end

      def flags=(code)
        set_flags(code)
      end

      def set_flags(code) # Should always be zero
        @ttl = (xrcode().code << 24) + (version() << 16) + code
      end

      def dnssec_ok
        return ((flags() & DO_BIT) == DO_BIT)
      end

      def dnssec_ok=(on)
        if (on)
          set_flags(flags() | DO_BIT)
        else
          set_flags(flags() & (~DO_BIT))
        end
      end

      def payloadsize
        return @klass.code
      end

      def payloadsize=(size)
        self.klass=Classes.new(size)
      end

      def options(code = nil)
        return @options if code.nil?
        @options.select { |option| option.code == code }
      end

      def options=(options)
        @options = Array(options).map do |option|
          if option.is_a?(ClientSubnet)
            option
          elsif option.respond_to?(:code) && option.code == EDNS_SUBNET_OPTION
            ClientSubnet.decode(option.data)
          else
            option
          end
        end
      end

      def from_data(data)
        @options = data
      end

      def from_string(input)
        raise NotImplementedError
      end

      def client_subnet
        @options.detect { |option| option.is_a?(ClientSubnet) }
      end

      def client_subnet=(subnet)
        @options = @options.reject { |option| option.code == EDNS_SUBNET_OPTION }
        @options << ClientSubnet.create(subnet) unless subnet.nil?
      end

      def set_client_subnet(subnet)
        self.client_subnet = subnet
      end

      def edns_client_subnet
        client_subnet&.to_s
      end

      def to_s
        ret = "OPT pseudo-record : payloadsize #{payloadsize}, xrcode #{xrcode.code}, version #{version}, flags #{flags}\n"
        if @options
          @options.each do |opt|
            if opt.is_a?(ClientSubnet)
              ret = ret + "CLIENT-SUBNET: #{opt}\n"
            else
              ret = ret + "OPT=#{opt.code}: #{opt.data}\n"
            end
          end
        end
        return ret
      end

      def encode_rdata(msg, canonical=false)
        @options.each do |opt|
          msg.put_pack('nn', opt.code, opt.data.length)
          msg.put_bytes(opt.data)
        end
      end

      def self.decode_rdata(msg)#:nodoc: all
        if (msg.has_remaining?)
          options = []
          while (msg.has_remaining?) do
            code  = msg.get_unpack('n')[0]
            len = msg.get_unpack('n')[0]
            data = msg.get_bytes(len)
            options.push(Option.new(code, data))
          end
        end
        return self.new(0, 0, options)
      end

      class Option
        attr_accessor :code, :data
        def initialize(code, data)
          @code = code
          @data = data
        end
      end

      class ClientSubnet
        IPV4_ADDRESS_FAMILY = 1
        IPV6_ADDRESS_FAMILY = 2
        ADDRESS_FAMILIES = {
          IPV4_ADDRESS_FAMILY => 4,
          IPV6_ADDRESS_FAMILY => 16
        }.freeze

        attr_reader :family, :source_prefix, :scope_prefix

        def self.create(value, source_prefix = nil, scope_prefix = 0)
          return value.dup if value.is_a?(ClientSubnet) && source_prefix.nil?

          if value.is_a?(Array)
            value = value.dup
            source_prefix ||= value[1]
            scope_prefix = value[2] || scope_prefix
            value = value[0]
          elsif value.is_a?(Hash)
            source_prefix ||= value[:source_prefix] || value['source_prefix']
            scope_prefix = value[:scope_prefix] || value['scope_prefix'] || scope_prefix
            value = value[:address] || value['address']
          end

          if value.is_a?(IPAddr)
            address = value
            source_prefix ||= address.ipv4? ? 32 : 128
          else
            address_text, prefix = value.to_s.split('/', 2)
            address = IPAddr.new(address_text)
            source_prefix ||= prefix
          end

          new(address, source_prefix, scope_prefix)
        end

        def self.decode(data)
          raise DecodeError.new('ECS option is too short') if data.nil? || data.length < 4

          family, source_prefix, scope_prefix = data.unpack('nCC')
          address_length = ADDRESS_FAMILIES[family]
          raise DecodeError.new("unsupported ECS address family #{family}") unless address_length

          max_prefix = address_length * 8
          unless source_prefix <= max_prefix && scope_prefix <= max_prefix
            raise DecodeError.new('ECS prefix is longer than address family')
          end
          unless scope_prefix <= source_prefix
            raise DecodeError.new('ECS scope prefix is longer than source prefix')
          end

          address_bytes = data.byteslice(4, data.length - 4) || +''
          expected_length = (source_prefix + 7) / 8
          unless address_bytes.length == expected_length
            raise DecodeError.new('ECS address has an incorrect length')
          end

          if source_prefix % 8 > 0
            mask = (0xff << (8 - source_prefix % 8)) & 0xff
            last_byte = address_bytes.getbyte(-1)
            raise DecodeError.new('ECS address contains host bits') if (last_byte & mask) != last_byte
          end

          address = IPAddr.ntop(address_bytes.ljust(address_length, "\0"))
          new(address, source_prefix, scope_prefix, false)
        end

        def initialize(address, source_prefix, scope_prefix, validate_scope = true)
          @address_object = address.is_a?(IPAddr) ? address : IPAddr.new(address.to_s)
          @family = @address_object.ipv4? ? IPV4_ADDRESS_FAMILY : IPV6_ADDRESS_FAMILY
          @max_prefix = ADDRESS_FAMILIES[@family] * 8
          @source_prefix = Integer(source_prefix)
          @scope_prefix = Integer(scope_prefix)
          validate_prefix(@source_prefix, 'source')
          validate_prefix(@scope_prefix, 'scope')
          if validate_scope && @scope_prefix > @source_prefix
            raise DecodeError.new('ECS scope prefix is longer than source prefix')
          end
          @address_object = @address_object.mask(@source_prefix)
          freeze
        end

        def code
          EDNS_SUBNET_OPTION
        end

        def address
          @address_object.native
        end

        def data
          address_bytes = address.hton
          length = (@source_prefix + 7) / 8
          [@family, @source_prefix, @scope_prefix].pack('nCC') + address_bytes.byteslice(0, length)
        end

        def scope
          self.class.new(address, @scope_prefix, 0, false)
        end

        def scope_key
          length = (@scope_prefix + 7) / 8
          [@family, @scope_prefix, address.mask(@scope_prefix).hton.byteslice(0, length) || +'']
        end

        def covers?(other)
          other = self.class.create(other)
          family == other.family && address.mask(scope_prefix).include?(other.address)
        end

        def valid_response_to?(request)
          request = self.class.create(request)
          family == request.family &&
            source_prefix == request.source_prefix &&
            scope_prefix <= source_prefix &&
            address.to_s == request.address.to_s
        end

        def to_cidr
          "#{address}/#{source_prefix}"
        end

        def to_s
          "#{address}/#{source_prefix}/#{scope_prefix}"
        end

        def ==(other)
          other.is_a?(ClientSubnet) &&
            family == other.family &&
            source_prefix == other.source_prefix &&
            scope_prefix == other.scope_prefix &&
            address.to_s == other.address.to_s
        end
        alias eql? ==

        def hash
          [family, source_prefix, scope_prefix, address.to_s].hash
        end

        private

        def validate_prefix(prefix, name)
          unless prefix >= 0 && prefix <= @max_prefix
            raise DecodeError.new("ECS #{name} prefix is out of range")
          end
        end
      end
    end
  end
end
