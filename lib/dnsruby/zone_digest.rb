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

require 'tempfile'
require 'openssl'

module Dnsruby
  # This class calculates, generates and verifies ZONEMD digests for DNS
  # zones, as described in RFC 8976 (Message Digest for DNS Zones).
  #
  # Only the SIMPLE scheme (1) is defined by RFC 8976; the SHA-384 (1)
  # and SHA-512 (2) hash algorithms are supported.
  #
  # The digest is calculated over the zone's RRs in canonical form
  # (RFC 4034 section 6.2) and canonical order (RFC 4034 sections 6.1
  # and 6.3), excluding the apex ZONEMD RRset, the RRSIGs covering it,
  # occluded data and duplicate RRs, as required by RFC 8976 section 4.1.
  #
  # Zones which do not fit comfortably in memory are sorted externally :
  # sorted runs of at most +max_records_in_memory+ records are spilled
  # to temporary files and merged back in canonical order, so the memory
  # footprint stays bounded regardless of the zone size.
  #
  # Example :
  #   rrs = Dnsruby::ZoneReader.new('example.com').process_file('zonefile')
  #   zonemd = Dnsruby::ZoneDigest.generate(rrs, :hash_algorithm => 'SHA384')
  #   Dnsruby::ZoneDigest.verify(rrs + [zonemd], zonemd) # => true
  class ZoneDigest
    class Error < StandardError; end
    # The ZONEMD Scheme is not supported by this implementation.
    class UnsupportedSchemeError < Error; end
    # The ZONEMD Hash Algorithm is not supported by this implementation.
    class UnsupportedHashAlgorithmError < Error; end
    # No SOA record could be found in the supplied zone data.
    class MissingSoaError < Error; end

    # The SIMPLE scheme (RFC 8976 section 3.1)
    SIMPLE_SCHEME = 1
    # Maps supported ZONEMD Hash Algorithm codes to OpenSSL digest names
    HASH_ALGORITHMS = { 1 => 'SHA384', 2 => 'SHA512' } #:nodoc: all
    # Default maximum number of records held in memory while sorting.
    # Larger zones are sorted via temporary files.
    DEFAULT_MAX_RECORDS_IN_MEMORY = 10000

    attr_reader :scheme, :hash_algorithm, :max_records_in_memory

    # Create a ZoneDigest calculator.
    #
    # Options :
    # * +:scheme+ - the ZONEMD Scheme to use (defaults to SIMPLE)
    # * +:hash_algorithm+ - the ZONEMD Hash Algorithm to use (defaults
    #   to SHA384)
    # * +:max_records_in_memory+ - the maximum number of records held in
    #   memory at once while sorting the zone; bigger zones are sorted
    #   externally through temporary files (defaults to
    #   DEFAULT_MAX_RECORDS_IN_MEMORY)
    def initialize(options = {})
      @scheme = RR::ZONEMD.get_scheme(options.fetch(:scheme, SIMPLE_SCHEME))
      @hash_algorithm = RR::ZONEMD.get_hash_algorithm(options.fetch(:hash_algorithm, 1))
      @max_records_in_memory = [ options.fetch(:max_records_in_memory, DEFAULT_MAX_RECORDS_IN_MEMORY), 1 ].max
      if (@scheme.code != SIMPLE_SCHEME)
        raise UnsupportedSchemeError.new("ZONEMD scheme #{@scheme.string} not supported")
      end
      if (!HASH_ALGORITHMS.has_key?(@hash_algorithm.code))
        raise UnsupportedHashAlgorithmError.new("ZONEMD hash algorithm #{@hash_algorithm.string} not supported")
      end
    end

    # Calculate the SIMPLE scheme zone digest (RFC 8976 section 4.1) over
    # the given RRs, using the given (SOA) serial.  Returns the binary
    # digest.
    #
    # +rrs+ must be re-iterable (e.g. an Array of Dnsruby::RR), as the
    # zone is scanned once to locate the apex and delegations, and once
    # to process the records.
    def digest(rrs, serial)
      digest = OpenSSL::Digest.new(HASH_ALGORITHMS[@hash_algorithm.code])
      digest.update([serial, @scheme.code, @hash_algorithm.code].pack('Ncc'))
      each_canonical_rr(rrs) do |wire|
        digest.update(wire)
      end
      return digest.digest
    end

    # Generate a ZONEMD RR for the given zone data.  The record's Serial
    # is taken from the zone's SOA record (unless the +:serial+ option is
    # given), and its TTL defaults to the SOA's TTL (unless the +:ttl+
    # option is given).
    def generate(rrs, options = {})
      soa = ZoneDigest.find_soa(rrs)
      serial = options[:serial] || soa.serial
      digestbin = digest(rrs, serial)
      return RR.create({:name => soa.name, :type => Types::ZONEMD,
        :ttl => options[:ttl] || soa.ttl, :serial => serial,
        :scheme => @scheme.code, :hash_algorithm => @hash_algorithm.code,
        :digestbin => digestbin, :digest => digestbin.unpack('H*')[0]})
    end

    # Verify a ZONEMD RR against the given zone data (RFC 8976 section
    # 4.2).  Returns true if the zone data matches the digest stored in
    # the record, false otherwise (including when the zone's SOA serial
    # does not match the record's Serial field).
    #
    # The Scheme and Hash Algorithm are taken from the ZONEMD record;
    # UnsupportedSchemeError or UnsupportedHashAlgorithmError is raised
    # if they are not supported.
    def verify(rrs, zonemd)
      if (zonemd.scheme.code != SIMPLE_SCHEME)
        raise UnsupportedSchemeError.new("ZONEMD scheme #{zonemd.scheme.string} not supported")
      end
      if (!HASH_ALGORITHMS.has_key?(zonemd.hash_algorithm.code))
        raise UnsupportedHashAlgorithmError.new("ZONEMD hash algorithm #{zonemd.hash_algorithm.string} not supported")
      end
      soa = ZoneDigest.find_soa(rrs)
      if (soa.serial != zonemd.serial)
        return false
      end
      calculator = ZoneDigest.new(:scheme => zonemd.scheme,
        :hash_algorithm => zonemd.hash_algorithm,
        :max_records_in_memory => @max_records_in_memory)
      return calculator.digest(rrs, zonemd.serial) == zonemd.digestbin
    end

    # Calculate the SIMPLE scheme zone digest over the given RRs.
    # See #digest.
    def self.digest(rrs, serial, options = {})
      return ZoneDigest.new(options).digest(rrs, serial)
    end

    # Generate a ZONEMD RR for the given zone data.  See #generate.
    def self.generate(rrs, options = {})
      generate_options = {}
      [ :serial, :ttl ].each { |k| generate_options[k] = options[k] if options.has_key?(k) }
      return ZoneDigest.new(options).generate(rrs, generate_options)
    end

    # Verify a ZONEMD RR against the given zone data.  See #verify.
    def self.verify(rrs, zonemd, options = {})
      return ZoneDigest.new(options).verify(rrs, zonemd)
    end

    # Locate the zone's SOA record.  Raises MissingSoaError if the
    # supplied RRs contain no SOA record.
    def self.find_soa(rrs)
      soa = nil
      rrs.each do |rr|
        if (rr.type == Types::SOA)
          soa = rr
          break
        end
      end
      if (!soa)
        raise MissingSoaError.new('No SOA record found in zone data')
      end
      return soa
    end

    private

    # Yield each record of the zone exactly once, in canonical order
    # (RFC 4034 sections 6.1 and 6.3), in its canonical wire format
    # (RFC 4034 section 6.2).
    def each_canonical_rr(rrs) #:nodoc: all
      apex, delegations = analyze_zone(rrs)
      run_files = []
      buffer = []
      begin
        rrs.each do |rr|
          next unless include_rr?(rr, apex, delegations)
          buffer << [ sort_key(rr), canonical_wire(rr) ]
          if (buffer.length >= @max_records_in_memory)
            run_files << write_run(buffer)
            buffer = []
          end
        end
        if (run_files.empty?)
          emit_sorted(buffer) { |wire| yield wire }
        else
          run_files << write_run(buffer) if (buffer.length > 0)
          merge_runs(run_files) { |wire| yield wire }
        end
      ensure
        run_files.each { |file| file.close(true) }
      end
    end

    # Scan the zone for its apex and its delegations (non-apex NS
    # records), so that out-of-zone and occluded data can be excluded
    # from the digest.
    def analyze_zone(rrs)
      apex = ZoneDigest.find_soa(rrs).name
      delegations = {}
      rrs.each do |rr|
        next unless (rr.type == Types::NS)
        next if (rr.name == apex)
        next unless rr.name.subdomain_of?(apex)
        key = rr.name.to_s.downcase
        delegations[key] ||= []
        delegations[key] << rr.nsdname.to_s.downcase
      end
      return apex, delegations
    end

    # Should this record be included in the zone digest?  (RFC 8976
    # section 4.1)
    def include_rr?(rr, apex, delegations)
      #  Only zone data is included
      return false unless (rr.name == apex || rr.name.subdomain_of?(apex))
      #  The apex ZONEMD RRset is excluded
      if (rr.type == Types::ZONEMD)
        return false if (rr.name == apex)
      end
      #  RRSIGs covering the apex ZONEMD RRset are excluded
      if (rr.type == Types::RRSIG && rr.type_covered == Types::ZONEMD)
        return false if (rr.name == apex)
      end
      #  Occluded data (below a zone cut, other than glue) is excluded
      name = rr.name
      while (name != apex)
        name = name.strip_label
        targets = delegations[name.to_s.downcase]
        if (targets)
          #  This record sits below a delegation; only glue address
          #  records for the delegated nameservers are included.
          return false unless (rr.type == Types::A || rr.type == Types::AAAA)
          return targets.include?(rr.name.to_s.downcase)
        end
      end
      return true
    end

    # The canonical wire format of the record (RFC 4034 section 6.2) :
    # owner | type | class | TTL | RDATA length | RDATA, with all names
    # in canonical (downcased) form.
    def canonical_wire(rr)
      return MessageEncoder.new { |msg|
        msg.put_rr(rr, true)
      }.to_s.b
    end

    # A binary sort key ordering records in canonical order : owner name
    # (RFC 4034 section 6.1), then class, then type, then canonical
    # RDATA (RFC 4034 section 6.3), then TTL (so that the order is
    # total, and duplicates compare equal).
    def sort_key(rr)
      key = canonical_name_key(rr.name)
      key << [ rr.klass.code, rr.type.code ].pack('nn')
      key << MessageEncoder.new { |msg|
        rr.encode_rdata(msg, true)
      }.to_s.b
      key << [ rr.ttl ].pack('N')
      return key
    end

    # Encode a name so that plain binary string comparison of the
    # encoded forms matches the canonical DNS name order of RFC 4034
    # section 6.1 : labels are compared from the most significant
    # (rightmost) label, as downcased left-justified octet strings,
    # where the absence of an octet sorts before a zero value octet.
    #
    # Each downcased label is emitted most-significant first, with 0x00
    # octets escaped as (0x00 0x01) and a single 0x00 octet terminating
    # each label; the end of the name sorts before any further label.
    def canonical_name_key(name)
      key = ''.b
      name.to_a.reverse_each do |label|
        label.string.downcase.each_byte do |byte|
          if (byte == 0)
            key << 0 << 1
          else
            key << byte
          end
        end
        key << 0
      end
      return key
    end

    # Sort the buffered records and yield each unique record's wire
    # format in canonical order.
    def emit_sorted(buffer)
      buffer.sort_by! { |key, _| key }
      previous_key = nil
      buffer.each do |key, wire|
        next if (key == previous_key)
        previous_key = key
        yield wire
      end
    end

    # Sort the buffered records and write them to a temporary file as
    # length-prefixed (key, wire) pairs, dropping duplicates.
    def write_run(buffer)
      buffer.sort_by! { |key, _| key }
      file = Tempfile.new('dnsruby-zonemd')
      file.binmode
      previous_key = nil
      buffer.each do |key, wire|
        next if (key == previous_key)
        previous_key = key
        file.write([ key.bytesize ].pack('N'))
        file.write(key)
        file.write([ wire.bytesize ].pack('N'))
        file.write(wire)
      end
      file.flush
      file.rewind
      return file
    end

    # Merge the sorted run files, yielding each unique record's wire
    # format in canonical order.
    def merge_runs(run_files)
      heads = run_files.map { |file| read_record(file) }
      previous_key = nil
      loop do
        min_index = nil
        heads.each_with_index do |head, i|
          next unless head
          if (min_index.nil? || head[0] < heads[min_index][0])
            min_index = i
          end
        end
        break if min_index.nil?
        key, wire = heads[min_index]
        heads[min_index] = read_record(run_files[min_index])
        next if (key == previous_key)
        previous_key = key
        yield wire
      end
    end

    def read_record(file)
      length_data = file.read(4)
      return nil unless length_data
      key = file.read(length_data.unpack1('N'))
      wire = file.read(file.read(4).unpack1('N'))
      return [ key, wire ]
    end
  end
end
