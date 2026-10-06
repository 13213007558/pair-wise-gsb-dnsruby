require 'digest/sha2'

module Dnsruby
  class RR
    # RFC 8976 ZONEMD resource record.
    class ZONEMD < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::ZONEMD #:nodoc: all

      SIMPLE = 1
      SHA384 = 1
      SHA512 = 2
      DIGEST_LENGTHS = { SHA384 => 48, SHA512 => 64 }

      DEFAULT_MEMORY_BUDGET = 1024 * 1024

      attr_reader :serial, :scheme, :hash_algorithm, :digest

      def serial=(value)
        @serial = integer_field(value, 'serial', 0xffffffff)
      end

      def scheme=(value)
        @scheme = integer_field(value, 'scheme', 0xff)
      end

      def hash_algorithm=(value)
        @hash_algorithm = integer_field(value, 'hash algorithm', 0xff)
      end

      def digest=(value)
        @digest = value.to_s.b
      end

      def digest_hex
        @digest.unpack('H*')[0]
      end

      def digest_hex=(value)
        hex = value.to_s.gsub(/\s+/, '')
        raise DecodeError, 'ZONEMD digest must contain an even number of hexadecimal digits' unless hex.length.even?
        self.digest = [hex].pack('H*')
      end

      def from_data(data) #:nodoc: all
        self.serial, self.scheme, self.hash_algorithm, self.digest = data
      end

      def from_hash(hash)
        self.serial = hash[:serial]
        self.scheme = hash.fetch(:scheme, SIMPLE)
        self.hash_algorithm = hash.fetch(:hash_algorithm, hash[:algorithm])
        if hash.key?(:digest_hex)
          self.digest_hex = hash[:digest_hex]
        else
          self.digest = hash[:digest]
        end
      end

      def from_string(input) #:nodoc: all
        fields = input.split
        raise DecodeError, 'ZONEMD RDATA requires serial, scheme, hash algorithm and digest' unless fields.length >= 4
        self.serial = fields[0].to_i
        self.scheme = fields[1].to_i
        self.hash_algorithm = fields[2].to_i
        self.digest_hex = fields[3..-1].join
      end

      def rdata_to_string #:nodoc: all
        "#{@serial} #{@scheme} #{@hash_algorithm} #{digest_hex}"
      end

      def encode_rdata(msg, _canonical = false) #:nodoc: all
        msg.put_pack('NCC', @serial, @scheme, @hash_algorithm)
        msg.put_bytes(@digest)
      end

      def self.decode_rdata(msg) #:nodoc: all
        serial, scheme, hash_algorithm = msg.get_unpack('NCC')
        digest = msg.get_bytes
        new([serial, scheme, hash_algorithm, digest])
      end

      def self.from_zone(zone, hash_algorithm:, ttl: 0,
                         memory_budget: DEFAULT_MEMORY_BUDGET, tempdir: nil)
        soa = ZoneDigest.soa(zone)
        hash_algorithm = ZoneDigest.hash_algorithm_code(hash_algorithm)
        digest = ZoneDigest.digest(zone, hash_algorithm,
                                   memory_budget: memory_budget, tempdir: tempdir)
        record_class = RR.get_class(Types::ZONEMD, soa.klass)
        record = record_class.new([soa.serial, SIMPLE, hash_algorithm, digest])
        record.name = soa.name
        record.ttl = ttl
        record.type = Types::ZONEMD
        record.klass = soa.klass
        record
      end

      def supported?
        @scheme == SIMPLE && DIGEST_LENGTHS[@hash_algorithm] == @digest.bytesize
      end

      def verify_zone(zone, memory_budget: DEFAULT_MEMORY_BUDGET, tempdir: nil)
        verify_zone!(zone, memory_budget: memory_budget, tempdir: tempdir)
        true
      rescue VerifyError
        false
      end

      def verify_zone!(zone, memory_budget: DEFAULT_MEMORY_BUDGET, tempdir: nil)
        soa = ZoneDigest.soa(zone)
        unless name.canonical == soa.name.canonical && klass == soa.klass
          raise VerifyError, 'ZONEMD owner name or class does not match zone apex'
        end
        unless @serial == soa.serial
          raise VerifyError, "ZONEMD serial #{@serial} does not match SOA serial #{soa.serial}"
        end
        unless @scheme == SIMPLE
          raise VerifyError, "unsupported ZONEMD scheme #{@scheme}"
        end
        algorithm = digest_algorithm
        unless algorithm
          raise VerifyError, "unsupported ZONEMD hash algorithm #{@hash_algorithm}"
        end
        unless @digest.bytesize == DIGEST_LENGTHS[@hash_algorithm]
          raise VerifyError, "invalid ZONEMD digest length #{@digest.bytesize}"
        end

        actual = ZoneDigest.digest(zone, @hash_algorithm,
                                   memory_budget: memory_budget, tempdir: tempdir)
        unless actual == @digest
          raise VerifyError, 'ZONEMD digest does not match zone'
        end
        true
      end

      def self.verify_zone(zone, zonemd = nil, **options)
        records = zonemd ? Array(zonemd) : zone_zonemds(zone)
        soa = ZoneDigest.soa(zone)
        records = records.select do |record|
          record.type == Types::ZONEMD && record.serial == soa.serial && record.supported?
        end
        return false if records.empty?
        records.any? { |record| record.verify_zone(zone, **options) }
      end

      def self.zone_zonemds(zone)
        apex = ZoneDigest.soa(zone).name
        zone.select do |record|
          record.type == Types::ZONEMD && record.name.canonical == apex.canonical
        end
      end

      private

      def digest_algorithm
        case @hash_algorithm
        when SHA384 then Digest::SHA384
        when SHA512 then Digest::SHA512
        end
      end

      def integer_field(value, name, maximum)
        value = value.code if value.respond_to?(:code)
        value = value.to_i
        unless value >= 0 && value <= maximum
          raise DecodeError, "ZONEMD #{name} out of range: #{value}"
        end
        value
      end
    end
  end
end
