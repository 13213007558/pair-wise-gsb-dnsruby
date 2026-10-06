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
  class RR
    # RFC8976, section 2
    # The ZONEMD Resource Record provides a cryptographic message digest
    # over DNS zone data at rest.  It allows recipients of the zone (e.g.
    # via zone transfer) to verify the zone contents for data integrity
    # and origin authenticity.
    #
    # The RDATA for a ZONEMD RR consists of a 4 octet Serial field, a 1
    # octet Scheme field, a 1 octet Hash Algorithm field, and a Digest
    # field.
    #
    #                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                             Serial                            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |    Scheme     |Hash Algorithm |                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    # |                             Digest                            |
    # /                                                               /
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    class ZONEMD < RR
      class Schemes < CodeMapper
        update()
        add_pair("RESERVED", 0)
        add_pair("SIMPLE", 1)

        def unknown_code(arg) #:nodoc: all
          #  Accept unknown (e.g. private use) scheme codes, so that
          #  records using them can still be parsed (though not
          #  verified).
          Schemes.add_pair(arg.to_s, arg)
          set_code(arg)
        end
      end

      class HashAlgorithms < CodeMapper
        update()
        add_pair("RESERVED", 0)
        add_pair("SHA384", 1)
        add_pair("SHA512", 2)

        def unknown_code(arg) #:nodoc: all
          #  Accept unknown (e.g. private use) hash algorithm codes, so
          #  that records using them can still be parsed (though not
          #  verified).
          HashAlgorithms.add_pair(arg.to_s, arg)
          set_code(arg)
        end
      end

      ClassValue = nil #:nodoc: all
      TypeValue = Types::ZONEMD #:nodoc: all

      # The Serial field of the ZONEMD RR.  It MUST match the serial of
      # the zone's SOA record for the digest to be considered valid.
      attr_accessor :serial
      # The Scheme field of the ZONEMD RR.  Only SIMPLE (1) is currently
      # defined by RFC 8976.
      attr_reader :scheme
      # The Hash Algorithm field of the ZONEMD RR.  SHA384 (1) and
      # SHA512 (2) are defined by RFC 8976.
      attr_reader :hash_algorithm
      # The digest of the zone, calculated as described in RFC 8976
      # section 4.1.
      attr_accessor :digest
      attr_accessor :digestbin

      def scheme=(s)
        @scheme = ZONEMD.get_scheme(s)
      end

      def ZONEMD.get_scheme(s)
        if (s.instance_of?String)
          if (s.length == 1)
            s = s.to_i
          end
        end
        begin
          scheme = Schemes.new(s)
          return scheme
        rescue ArgumentError => e
          raise DecodeError.new(e)
        end
      end

      def hash_algorithm=(a)
        @hash_algorithm = ZONEMD.get_hash_algorithm(a)
      end

      def ZONEMD.get_hash_algorithm(a)
        if (a.instance_of?String)
          if (a.length == 1)
            a = a.to_i
          end
        end
        begin
          alg = HashAlgorithms.new(a)
          return alg
        rescue ArgumentError => e
          raise DecodeError.new(e)
        end
      end

      def from_data(data) #:nodoc: all
        serial, scheme, hash_algorithm, digest = data
        self.serial=(serial)
        self.scheme=(scheme)
        self.hash_algorithm=(hash_algorithm)
        self.digestbin=(digest)
        self.digest=@digestbin.unpack("H*")[0]
      end

      def from_string(input)
        if (input.length > 0)
          data = input.split(" ")
          self.serial=(data[0].to_i)
          self.scheme=(data[1])
          self.hash_algorithm=(data[2])

          buf = ""
          index = 3
          end_index = data.length - 1
          if (data[index]=="(")
            end_index = data.length - 2
            index = 4
          end
          (index..end_index).each {|i|
            if (comment_index = data[i].index(";"))
              buf += data[i].slice(0, comment_index)
              break
            else
              buf += data[i]
            end
          }
          buf.gsub!(/\n/, "")
          buf.gsub!(/ /, "")
          self.digest=buf
          self.digestbin = [buf].pack("H*")
        end
      end

      def rdata_to_string #:nodoc: all
        if (@serial != nil)
          return "#{@serial.to_i} #{@scheme.code} #{@hash_algorithm.code} ( #{@digest.upcase} )"
        else
          return ""
        end
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_pack("Ncc", @serial, @scheme.code, @hash_algorithm.code)
        msg.put_bytes(@digestbin)
      end

      def self.decode_rdata(msg) #:nodoc: all
        serial, scheme, hash_algorithm = msg.get_unpack("Ncc")
        digest = msg.get_bytes
        return self.new(
          [serial, scheme, hash_algorithm, digest])
      end

      #  Calculate the zone digest (RFC 8976 section 4.1) over the given
      #  list of RRs, using the Serial, Scheme and Hash Algorithm fields
      #  of this record.  Returns the binary digest.
      #  See Dnsruby::ZoneDigest for the available options.
      def calculate_zone_digest(rrs, options = {})
        return ZoneDigest.new({:scheme => @scheme, :hash_algorithm => @hash_algorithm}.merge(options)).
          digest(rrs, @serial)
      end

      #  Verify this ZONEMD record against the given list of RRs (RFC 8976
      #  section 4.2).  Returns true if the zone data matches the digest
      #  stored in this record, false otherwise (including when the zone's
      #  SOA serial does not match the Serial field of this record).
      #  Raises ZoneDigest::UnsupportedSchemeError or
      #  ZoneDigest::UnsupportedHashAlgorithmError if the Scheme or Hash
      #  Algorithm of this record is not supported.
      def verify_zone(rrs, options = {})
        return ZoneDigest.new({:scheme => @scheme, :hash_algorithm => @hash_algorithm}.merge(options)).
          verify(rrs, self)
      end
    end
  end
end
