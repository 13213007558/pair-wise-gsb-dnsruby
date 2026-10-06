require_relative 'spec_helper'

require 'digest/sha2'

class ZoneMDTest < Minitest::Test
  include Dnsruby

  def setup
    @zone = [
      RR.create('example. 3600 IN SOA ns.example. hostmaster.example. 2026010100 7200 3600 1209600 60'),
      RR.create('Example. 3600 IN NS ns.example.'),
      RR.create('z.example. 300 IN A 192.0.2.3'),
      RR.create('a.example. 300 IN A 192.0.2.1'),
      RR.create('a.example. 300 IN A 192.0.2.1'),
      RR.create('host.example. 300 IN CNAME Host.Example.'),
      RR.create('a.example. 300 IN AAAA 2001:db8::1'),
      RR::IN::RRSIG.new([1, 13, 2, 300, Time.utc(2030), Time.utc(2020), 1234,
                         Name.create('ns.example.'), 'signature'])
    ]
    @zone.last.name = 'a.example.'
    @zone.last.ttl = 300
    @zone.last.type = Types::RRSIG
    @zone.last.klass = Classes::IN
  end

  def test_parse_and_wire_round_trip
    record = RR::ZONEMD.from_zone(@zone, hash_algorithm: RR::ZONEMD::SHA384)
    parsed = RR.create(record.to_s)

    assert_equal Types::ZONEMD, parsed.type
    assert_equal 2026010100, parsed.serial
    assert_equal RR::ZONEMD::SIMPLE, parsed.scheme
    assert_equal RR::ZONEMD::SHA384, parsed.hash_algorithm
    assert_equal record.digest, parsed.digest

    message = Message.new
    message.add_additional(parsed)
    decoded = Message.decode(message.encode).additional.first

    assert_equal 48, decoded.digest.bytesize
    assert_equal record.rdata_to_string, decoded.rdata_to_string
  end

  def test_sha384_and_sha512_generation_and_verification
    sha384 = RR::ZONEMD.from_zone(@zone, hash_algorithm: :SHA384)
    sha512 = RR::ZONEMD.from_zone(@zone, hash_algorithm: 'SHA512')

    assert_equal 48, sha384.digest.bytesize
    assert_equal 64, sha512.digest.bytesize
    assert_equal Digest::SHA384.digest(canonical_zone(@zone)), sha384.digest
    assert_equal Digest::SHA512.digest(canonical_zone(@zone)), sha512.digest
    assert sha384.verify_zone(@zone)
    assert sha512.verify_zone!(@zone)
    assert RR::ZONEMD.verify_zone(@zone, [sha384, sha512])
  end

  def test_external_sort_matches_in_memory_sort
    in_memory = RR::ZONEMD.from_zone(@zone, hash_algorithm: RR::ZONEMD::SHA384)
    external = RR::ZONEMD.from_zone(@zone, hash_algorithm: RR::ZONEMD::SHA384,
                                     memory_budget: 1)

    assert_equal in_memory.digest, external.digest
    assert external.verify_zone(@zone, memory_budget: 0)
  end

  def test_duplicate_records_are_retained
    changed = @zone.dup
    changed << RR.create('dup.example. 300 IN TXT "once"')
    changed << RR.create('dup.example. 300 IN TXT "once"')

    record = RR::ZONEMD.from_zone(changed, hash_algorithm: RR::ZONEMD::SHA384)
    without_duplicate = changed[0...-1]

    refute_equal RR::ZONEMD.from_zone(without_duplicate,
                                     hash_algorithm: RR::ZONEMD::SHA384).digest,
                 record.digest
    assert record.verify_zone(changed)
  end

  def test_owner_and_rdata_case_are_canonicalized
    uppercase_only = [
      RR.create('EXAMPLE. 3600 IN SOA NS.EXAMPLE. HOSTMASTER.EXAMPLE. 2026010100 7200 3600 1209600 60'),
      RR.create('EXAMPLE. 3600 IN NS NS.EXAMPLE.'),
      RR.create('HOST.EXAMPLE. 300 IN CNAME HOST.EXAMPLE.')
    ]
    lowercase_only = [
      RR.create('example. 3600 IN SOA ns.example. hostmaster.example. 2026010100 7200 3600 1209600 60'),
      RR.create('example. 3600 IN NS ns.example.'),
      RR.create('host.example. 300 IN CNAME host.example.')
    ]

    upper = RR::ZONEMD.from_zone(uppercase_only, hash_algorithm: RR::ZONEMD::SHA384)
    lower = RR::ZONEMD.from_zone(lowercase_only, hash_algorithm: RR::ZONEMD::SHA384)

    assert_equal upper.digest, lower.digest
    assert upper.verify_zone(lowercase_only)
  end

  def test_zonemd_and_rrsig_are_excluded
    zonemd = RR::ZONEMD.from_zone(@zone, hash_algorithm: RR::ZONEMD::SHA384)
    signed_zone = @zone + [zonemd]

    assert zonemd.verify_zone(signed_zone)
    assert RR::ZONEMD.verify_zone(signed_zone)
  end

  def test_serial_mismatch_fails
    changed = @zone.dup
    changed[0] = RR.create('example. 3600 IN SOA ns.example. hostmaster.example. 2026010101 7200 3600 1209600 60')
    record = RR::ZONEMD.from_zone(@zone, hash_algorithm: RR::ZONEMD::SHA384)

    refute record.verify_zone(changed)
    assert_raises(VerifyError) { record.verify_zone!(changed) }
  end

  def test_changed_content_fails
    record = RR::ZONEMD.from_zone(@zone, hash_algorithm: RR::ZONEMD::SHA384)
    changed = @zone.dup
    changed[2] = RR.create('z.example. 300 IN A 192.0.2.4')

    refute record.verify_zone(changed)
  end

  def test_unsupported_algorithm_and_scheme_fail
    unsupported = RR.create('example. 0 IN ZONEMD 2026010100 1 3 00')
    refute unsupported.verify_zone(@zone)

    reserved_scheme = RR.create('example. 0 IN ZONEMD 2026010100 2 1 00')
    refute reserved_scheme.verify_zone(@zone)

    assert_raises(ArgumentError) do
      RR::ZONEMD.from_zone(@zone, hash_algorithm: 3)
    end
  end

  private

  def canonical_zone(zone)
    apex = zone.first.name
    zone.reject { |record| record.type == Types::RRSIG }
        .reject { |record| record.type == Types::ZONEMD && record.name.canonical == apex.canonical }
        .sort_by { |record| sort_key(record) }
        .map { |record| MessageEncoder.new { |encoder| encoder.put_rr(record, true) }.to_s }
        .join
  end

  def sort_key(record)
    key = record.name.labels.reverse.map do |label|
      label.string.downcase.bytes.map { |byte| [byte].pack('C') }.join
    end
    [key, record.type.code, canonical_rdata(record)]
  end

  def canonical_rdata(record)
    MessageEncoder.new { |encoder| record.encode_rdata(encoder, true) }.to_s
  end
end
