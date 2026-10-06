require 'tempfile'

module Dnsruby
  # Computes RFC 8976 ZONEMD digests using canonical RR ordering.
  class ZoneDigest
    SIMPLE = RR::ZONEMD::SIMPLE
    SHA384 = RR::ZONEMD::SHA384
    SHA512 = RR::ZONEMD::SHA512
    HASH_ALGORITHMS = {
      'SHA384' => SHA384,
      'SHA512' => SHA512
    }

    def self.digest(zone, hash_algorithm, memory_budget: RR::ZONEMD::DEFAULT_MEMORY_BUDGET, tempdir: nil)
      new(zone, hash_algorithm, memory_budget: memory_budget, tempdir: tempdir).digest
    end

    def self.soa(zone)
      soas = zone.select { |record| record.type == Types::SOA }
      raise VerifyError, 'zone must contain an SOA record' if soas.empty?
      soas.first
    end

    def self.hash_algorithm_code(value)
      return value.code if value.respond_to?(:code)
      return value if value.is_a?(Integer)
      HASH_ALGORITHMS.fetch(value.to_s.upcase)
    rescue KeyError
      raise ArgumentError, "unsupported ZONEMD hash algorithm #{value}"
    end

    def initialize(zone, hash_algorithm, memory_budget: RR::ZONEMD::DEFAULT_MEMORY_BUDGET, tempdir: nil)
      @zone = zone
      @hash_algorithm = self.class.hash_algorithm_code(hash_algorithm)
      @memory_budget = memory_budget.to_i
      @tempdir = tempdir
      @sequence = 0

      raise ArgumentError, 'memory budget cannot be negative' if @memory_budget < 0
      @digest_class = case @hash_algorithm
                      when SHA384 then Digest::SHA384
                      when SHA512 then Digest::SHA512
                      else raise ArgumentError, "unsupported ZONEMD hash algorithm #{@hash_algorithm}"
                      end
    end

    def digest
      digest = @digest_class.new
      each_canonical_rr { |wire| digest.update(wire) }
      digest.digest
    end

    private

    def each_canonical_rr
      entries = []
      files = []
      used = 0
      apex = self.class.soa(@zone).name

      @zone.each do |record|
        next if record.type == Types::RRSIG
        next if record.type == Types::ZONEMD && record.name.canonical == apex.canonical

        key = sort_key(record)
        wire = canonical_wire(record)
        entry = [key, @sequence, wire]
        @sequence += 1

        if !entries.empty? && used + key.bytesize + wire.bytesize > @memory_budget
          files << flush_chunk(entries)
          entries = []
          used = 0
        end

        entries << entry
        used += key.bytesize + wire.bytesize
      end

      if files.empty?
        entries.sort.each { |_, _, wire| yield wire }
      else
        files << flush_chunk(entries) unless entries.empty?
        merge_chunks(files) { |wire| yield wire }
      end
    ensure
      files&.each do |file|
        file.close! rescue nil
      end
    end

    def sort_key(record)
      key = +''.b
      record.name.labels.reverse.each do |label|
        label.string.bytes.each do |byte|
          key << ((byte >> 4) + 1)
          key << ((byte & 0x0f) + 1)
        end
        key << 0
      end
      key << 0
      key << [record.type.code].pack('n')
      key << canonical_rdata(record)
      key
    end

    def canonical_rdata(record)
      MessageEncoder.new { |encoder| record.encode_rdata(encoder, true) }.to_s.b
    end

    def canonical_wire(record)
      MessageEncoder.new { |encoder| encoder.put_rr(record, true) }.to_s.b
    end

    def flush_chunk(entries)
      entries.sort!
      file = Tempfile.new(['zonemd-sort', '.tmp'], @tempdir)
      file.binmode
      success = false
      begin
        entries.each do |key, index, wire|
          file.write([key.bytesize, wire.bytesize, index].pack('NNN'))
          file.write(key)
          file.write(wire)
        end
        success = true
      ensure
        unless success
          file.close!
        end
      end
      file.rewind
      file
    end

    def merge_chunks(files)
      heap = files.map do |file|
        entry = read_entry(file)
        entry ? [entry, file] : nil
      end.compact

      while !heap.empty?
        position = 0
        heap.each_with_index do |entry, index|
          current = heap[position][0]
          candidate = entry[0]
          before = candidate[0] < current[0] || (candidate[0] == current[0] && candidate[1] < current[1])
          position = index if before
        end
        (_, _, wire), file = heap[position]
        yield wire

        next_entry = read_entry(file)
        if next_entry
          heap[position] = [next_entry, file]
        else
          heap.delete_at(position)
        end
      end
    end

    def read_entry(file)
      header = file.read(12)
      return nil if header.nil? || header.empty?
      raise VerifyError, 'corrupt ZONEMD temporary sort file' unless header.bytesize == 12
      key_length, wire_length, index = header.unpack('NNN')
      key = file.read(key_length)
      wire = file.read(wire_length)
      raise VerifyError, 'corrupt ZONEMD temporary sort file' unless key && wire &&
        key.bytesize == key_length && wire.bytesize == wire_length
      [key.b, index, wire.b]
    end
  end
end
