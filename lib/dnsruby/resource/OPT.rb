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
require 'socket'

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

      ADDRESS_FAMILIES = [1, 2]
      IPV4_ADDRESS_FAMILY, IPV6_ADDRESS_FAMILY = ADDRESS_FAMILIES

      EDNS_SUBNET_OPTION = 8

      class ClientSubnet
        attr_reader :family, :source_prefix, :scope_prefix

        def self.create(address, source_prefix = nil, scope_prefix = nil)
          case address
          when ClientSubnet
            address
          when IPAddr
            new(address, source_prefix || address.prefix, scope_prefix)
          when String
            address, source_from_string, scope_from_string = address.split('/', 3)
            scope = scope_prefix.nil? ? (scope_from_string || 0) : scope_prefix
            new(address, source_prefix || source_from_string, scope)
          else
            raise ArgumentError.new("invalid client subnet #{address.inspect}")
          end
        end

        def self.decode(data)
          raise DecodeError.new("EDNS client subnet option is too short") if data.nil? || data.length < 4

          family, source_prefix, scope_prefix = data.unpack('nCC')
          address_bytes = data[4, data.length - 4] || +''
          max_prefix = family == RR::OPT::IPV4_ADDRESS_FAMILY ? 32 : 128

          unless RR::OPT::ADDRESS_FAMILIES.include?(family) &&
              source_prefix <= max_prefix &&
              scope_prefix <= max_prefix &&
              scope_prefix <= source_prefix
            raise DecodeError.new("invalid EDNS client subnet option")
          end

          expected_length = (source_prefix + 7) / 8
          unless address_bytes.length == expected_length
            raise DecodeError.new("EDNS client subnet address length is invalid")
          end

          address = decode_address(family, address_bytes, max_prefix)
          subnet = new(address, source_prefix, scope_prefix)
          unless address_bytes == subnet.send(:wire_address, source_prefix)
            raise DecodeError.new("EDNS client subnet address has host bits set")
          end
          subnet
        end

        def self.decode_address(family, address_bytes, max_prefix)
          address_length = max_prefix / 8
          padded = address_bytes.b + ("\0".b * (address_length - address_bytes.length))
          IPAddr.new_ntoh(padded)
        end

        def initialize(address, source_prefix = nil, scope_prefix = 0)
          address = IPAddr.new(address) if String === address
          source_prefix = source_prefix.nil? ? address.prefix : Integer(source_prefix)
          scope_prefix = Integer(scope_prefix)

          @family = address.ipv4? ? RR::OPT::IPV4_ADDRESS_FAMILY : RR::OPT::IPV6_ADDRESS_FAMILY
          @max_prefix = address.ipv4? ? 32 : 128

          unless source_prefix.between?(0, @max_prefix) && scope_prefix.between?(0, source_prefix)
            raise ArgumentError.new("invalid EDNS client subnet prefix")
          end

          @source_prefix = source_prefix
          @scope_prefix = scope_prefix
          @source_address = address.mask(source_prefix)
          @scope_address = address.mask(scope_prefix)
        end

        def address
          @source_address.to_s
        end

        def source_netmask
          source_prefix
        end

        def scope_netmask
          scope_prefix
        end

        def source_address
          @source_address.dup
        end

        def scope_address
          @scope_address.dup
        end

        def encode
          [family, source_prefix, scope_prefix].pack('nCC') + wire_address(source_prefix)
        end

        def covers?(other)
          other = self.class.create(other)
          family == other.family &&
            scope_prefix <= other.source_prefix &&
            scope_address.include?(other.source_address)
        end

        def valid_response_to?(request)
          request = self.class.create(request)
          family == request.family &&
            source_prefix == request.source_prefix &&
            source_address.to_s == request.source_address.to_s &&
            scope_prefix <= request.source_prefix
        end

        def ==(other)
          other.is_a?(self.class) &&
            family == other.family &&
            source_prefix == other.source_prefix &&
            scope_prefix == other.scope_prefix &&
            source_address.to_s == other.source_address.to_s
        end
        alias eql? ==

        def hash
          [family, source_address.to_s, source_prefix, scope_prefix].hash
        end

        def to_s
          "#{source_address}/#{source_prefix}/#{scope_prefix}"
        end

        private

        def wire_address(prefix)
          return +''.b if prefix == 0
          bytes = @source_address.hton
          bytes.byteslice(0, (prefix + 7) / 8)
        end
      end

      #  @TODO@ Add BADVERS to an XRCode CodeMapper object

      # Can be called with up to 3 arguments, none of which must be present
      # * OPT.new()
      # * OPT.new(size)
      # * OPT.new(size,flags)
      # * OPT.new(size,flags,options)
      def initialize(*args)
        @name = Name.create('.')
        @type = Types.new('OPT')
        @ttl = nil

        @options=nil
        if (args.length > 0)
          self.payloadsize=(args[0])
          if (args.length > 1)
            self.flags=(args[1])
            if (args.length > 2)
              self.options=(args[2])
            else
              self.options=nil
            end
          else
            self.flags=0
          end
        else
          self.payloadsize=0
          self.flags=0
        end
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

      def options(args = nil)
        if (args==nil)
          return @options
        elsif args.kind_of?(Integer)
          #  return list of options with that code
          ret = []
          @options.each do |option|
            if (option.code == args)
              ret.push(option)
            end
          end
          return ret
        end
      end

      def options=(options)
        @options = options
      end

      def from_data(data)
        @options = data
      end

      def from_string(input)
        raise NotImplementedError
      end

      def get_client_subnet(opt)
        ClientSubnet.decode(opt.data).to_s
      rescue DecodeError => error
        "Unsupported(#{error.message})"
      end

      def set_client_subnet(subnet)
        client_subnet = ClientSubnet.create(subnet)
        option = Option.new(EDNS_SUBNET_OPTION, client_subnet.encode)
        remaining = (@options || []).reject { |existing| existing.code == EDNS_SUBNET_OPTION }
        self.options = remaining + [option]
      end

      def client_subnet
        return nil if @options.nil?
        subnet_option = @options.detect { |option| option.code == EDNS_SUBNET_OPTION }
        subnet_option ? ClientSubnet.decode(subnet_option.data) : nil
      end

      def edns_client_subnet
        return nil if @options.nil?
        subnet_option = @options.detect { |option| option.code == EDNS_SUBNET_OPTION }
        subnet_option ? get_client_subnet(subnet_option) : nil
      end

      def to_s
        ret = "OPT pseudo-record : payloadsize #{payloadsize}, xrcode #{xrcode.code}, version #{version}, flags #{flags}\n"
        if @options
          @options.each do |opt|
            if opt.code == EDNS_SUBNET_OPTION
              ret = ret + "CLIENT-SUBNET: #{get_client_subnet(opt)}\n"
            else
              ret = ret + "OPT=#{opt.code}: #{opt.data}\n"
            end
          end
        end
        return ret
      end

      def encode_rdata(msg, canonical=false)
        if (@options)
          @options.each do |opt|
            msg.put_pack('n', opt.code)
            msg.put_pack('n', opt.data.length)
            msg.put_pack('a*', opt.data)
          end
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
          if options.count { |option| option.code == EDNS_SUBNET_OPTION } > 1
            raise DecodeError.new("multiple EDNS client subnet options")
          end
          options.each { |option| ClientSubnet.decode(option.data) if option.code == EDNS_SUBNET_OPTION }
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
    end
  end
end
