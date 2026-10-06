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

require_relative 'spec_helper'

require 'openssl'
require 'tempfile'

class ZonemdTest < Minitest::Test

  include Dnsruby

  ZONE_TEXT = [
    'example. 86400 IN SOA ns1.example. admin.example. 2018031500 3600 300 1814400 3600',
    'example. 86400 IN NS ns1.example.',
    'example. 86400 IN NS ns2.example.',
    'example. 86400 IN MX 10 mail.example.',
    'example. 86400 IN TXT "v=spf1 -all"',
    'example. 3600 IN A 192.0.2.1',
    'example. 3600 IN AAAA 2001:db8::1',
    'ns1.example. 86400 IN A 192.0.2.2',
    'ns1.example. 86400 IN AAAA 2001:db8::2',
    'ns2.example. 86400 IN A 192.0.2.3',
    'mail.example. 3600 IN A 192.0.2.4',
    'www.example. 300 IN A 192.0.2.5',
    'www.example. 300 IN A 192.0.2.6',
    'www.example. 300 IN AAAA 2001:db8::5',
    'WwW2.ExAmPlE. 300 IN A 192.0.2.7',
    'ftp.example. 300 IN CNAME www.example.',
    '_sip._tcp.example. 3600 IN SRV 10 60 5060 sip.example.',
    'sip.example. 3600 IN A 192.0.2.8',
    'sub.example. 86400 IN NS ns1.sub.example.',
    'sub.example. 86400 IN NS ns2.example.',
    'ns1.sub.example. 86400 IN A 192.0.2.9',
    'occluded.sub.example. 3600 IN A 192.0.2.10',
    'deep.occluded.sub.example. 3600 IN TXT "occluded too"',
    'host1.example. 60 IN A 10.0.0.1',
    'host2.example. 60 IN A 10.0.0.2',
    'host3.example. 60 IN A 10.0.0.3',
    'host4.example. 60 IN A 10.0.0.4',
    'host5.example. 60 IN A 10.0.0.5',
    'host6.example. 60 IN A 10.0.0.6',
    'host7.example. 60 IN A 10.0.0.7',
    'host8.example. 60 IN A 10.0.0.8',
    'host9.example. 60 IN A 10.0.0.9',
    'host10.example. 60 IN A 10.0.0.10',
  ]

  ZONEMD_INPUT = 'example. 86400 IN ZONEMD 2018031500 1 1 ( FEBE3D4CEA2EC4BF' +
    'C56B96D6C6F1B1C7F2C8C5D8A1C7B4E8F8D4A4B1C8D8A8F8E4D4C4B4 )'

  RRSIG_ZONEMD_INPUT = 'example. 86400 IN RRSIG ZONEMD 8 2 86400 ' +
    '20300101000000 20200101000000 12345 example. AQIDBAUGBwgJCgsMDQ4PEA=='

  def zone_rrs
    ZONE_TEXT.map { |line| Dnsruby::RR.create(line) }
  end

  def test_zonemd_from_string
    zonemd = Dnsruby::RR.create(ZONEMD_INPUT)
    assert_equal(2018031500, zonemd.serial)
    assert_equal(1, zonemd.scheme.code)
    assert_equal('SIMPLE', zonemd.scheme.string)
    assert_equal(1, zonemd.hash_algorithm.code)
    assert_equal('SHA384', zonemd.hash_algorithm.string)
    assert_equal('FEBE3D4CEA2EC4BFC56B96D6C6F1B1C7F2C8C5D8A1C7B4E8F8D4A4B1C8D8A8F8E4D4C4B4',
      zonemd.digest.upcase)

    zonemd2 = Dnsruby::RR.create(zonemd.to_s)
    assert(zonemd2.to_s == zonemd.to_s)
  end

  def test_zonemd_from_data
    zonemd = Dnsruby::RR.create(ZONEMD_INPUT)
    m = Dnsruby::Message.new
    m.add_additional(zonemd)
    data = m.encode
    m2 = Dnsruby::Message.decode(data)
    zonemd2 = m2.additional()[0]
    assert_equal(zonemd.serial, zonemd2.serial)
    assert_equal(zonemd.scheme, zonemd2.scheme)
    assert_equal(zonemd.hash_algorithm, zonemd2.hash_algorithm)
    assert_equal(zonemd.digestbin, zonemd2.digestbin)
    assert(zonemd2.to_s == zonemd.to_s)
  end

  def test_generate_and_verify_sha384
    rrs = zone_rrs
    zonemd = ZoneDigest.generate(rrs, :hash_algorithm => 'SHA384')
    assert_equal(Types::ZONEMD, zonemd.type)
    assert_equal(Name.create('example.'), zonemd.name)
    assert_equal(2018031500, zonemd.serial)
    assert_equal(48, zonemd.digestbin.length)
    assert(zonemd.verify_zone(rrs))
    assert(ZoneDigest.verify(rrs + [ zonemd ], zonemd))
  end

  def test_generate_and_verify_sha512
    rrs = zone_rrs
    zonemd = ZoneDigest.generate(rrs, :hash_algorithm => 'SHA512')
    assert_equal(2, zonemd.hash_algorithm.code)
    assert_equal(64, zonemd.digestbin.length)
    assert(zonemd.verify_zone(rrs))
  end

  def test_verify_detects_tampering
    rrs = zone_rrs
    zonemd = ZoneDigest.generate(rrs)

    added = rrs + [ Dnsruby::RR.create('evil.example. 300 IN A 192.0.2.99') ]
    assert(!zonemd.verify_zone(added))

    removed = rrs.reject { |rr| rr.type == Types::MX }
    assert(!zonemd.verify_zone(removed))

    changed_ttl = zone_rrs
    changed_ttl.each { |rr| rr.ttl = 61 if (rr.type == Types::A && rr.name.to_s == 'host1.example') }
    assert(!zonemd.verify_zone(changed_ttl))
  end

  def test_duplicate_records_counted_once
    rrs = zone_rrs
    digest = ZoneDigest.digest(rrs, 2018031500)
    duplicates = [
      Dnsruby::RR.create('www.example. 300 IN A 192.0.2.5'),
      Dnsruby::RR.create('example. 86400 IN NS ns1.example.'),
    ]
    assert_equal(digest, ZoneDigest.digest(rrs + duplicates, 2018031500))
  end

  def test_name_case_does_not_change_digest
    rrs = zone_rrs
    digest = ZoneDigest.digest(rrs, 2018031500)
    #  These records are canonical duplicates of records already in the
    #  zone; only their name (or embedded name) case differs.
    case_variants = [
      Dnsruby::RR.create('WWW.EXAMPLE. 300 IN A 192.0.2.5'),
      Dnsruby::RR.create('FTP.example. 300 IN CNAME WWW.EXAMPLE.'),
    ]
    assert_equal(digest, ZoneDigest.digest(rrs + case_variants, 2018031500))
  end

  def test_soa_serial_mismatch
    rrs = zone_rrs
    zonemd = ZoneDigest.generate(rrs)

    #  A ZONEMD whose serial does not match the zone's SOA serial
    other_serial = ZoneDigest.generate(rrs, :serial => 2018031501)
    assert(!ZoneDigest.verify(rrs, other_serial))

    #  A zone whose SOA serial does not match the ZONEMD serial
    new_zone = zone_rrs
    new_zone.each { |rr| rr.serial = 2018031501 if (rr.type == Types::SOA) }
    assert(!zonemd.verify_zone(new_zone))
  end

  def test_zonemd_and_covering_rrsig_excluded
    rrs = zone_rrs
    digest = ZoneDigest.digest(rrs, 2018031500)
    zonemd = ZoneDigest.generate(rrs)
    rrsig = Dnsruby::RR.create(RRSIG_ZONEMD_INPUT)
    assert_equal(digest, ZoneDigest.digest(rrs + [ zonemd, rrsig ], 2018031500))
    assert(zonemd.verify_zone(rrs + [ zonemd, rrsig ]))
  end

  def test_occluded_data_excluded_but_glue_included
    rrs = zone_rrs
    digest = ZoneDigest.digest(rrs, 2018031500)

    #  Occluded data (below the sub.example. delegation) is not digested
    occluded = [ Dnsruby::RR.create('more.sub.example. 3600 IN A 192.0.2.11') ]
    assert_equal(digest, ZoneDigest.digest(rrs + occluded, 2018031500))

    #  Glue address records for the delegated nameservers are digested
    glue = [ Dnsruby::RR.create('ns1.sub.example. 86400 IN AAAA 2001:db8::9') ]
    assert(digest != ZoneDigest.digest(rrs + glue, 2018031500))
  end

  def test_out_of_zone_data_ignored
    rrs = zone_rrs
    digest = ZoneDigest.digest(rrs, 2018031500)
    out_of_zone = [ Dnsruby::RR.create('other.example.net. 300 IN A 192.0.2.12') ]
    assert_equal(digest, ZoneDigest.digest(rrs + out_of_zone, 2018031500))
  end

  def test_external_sort_matches_in_memory
    rrs = zone_rrs
    digest = ZoneDigest.digest(rrs, 2018031500)
    [ 1, 3, 7 ].each do |budget|
      options = { :max_records_in_memory => budget }
      assert_equal(digest, ZoneDigest.digest(rrs, 2018031500, options),
        "external sort (budget #{budget}) produced a different digest")
      zonemd = ZoneDigest.generate(rrs, options)
      assert(zonemd.verify_zone(rrs, options))
    end
  end

  def test_external_sort_deduplicates_across_runs
    rrs = zone_rrs
    digest = ZoneDigest.digest(rrs, 2018031500)
    #  Duplicates land in different sort runs when the budget is small
    duplicates = [ Dnsruby::RR.create('www.example. 300 IN A 192.0.2.5') ]
    options = { :max_records_in_memory => 2 }
    assert_equal(digest, ZoneDigest.digest(rrs + duplicates, 2018031500, options))
  end

  def test_unsupported_scheme_and_hash_algorithm
    rrs = zone_rrs
    bad_scheme = Dnsruby::RR.create('example. 300 IN ZONEMD 2018031500 2 1 ( ABCD )')
    assert_raises(ZoneDigest::UnsupportedSchemeError) { bad_scheme.verify_zone(rrs) }
    bad_hash = Dnsruby::RR.create('example. 300 IN ZONEMD 2018031500 1 3 ( ABCD )')
    assert_raises(ZoneDigest::UnsupportedHashAlgorithmError) { bad_hash.verify_zone(rrs) }
  end

  def test_missing_soa
    rrs = zone_rrs.reject { |rr| rr.type == Types::SOA }
    assert_raises(ZoneDigest::MissingSoaError) { ZoneDigest.generate(rrs) }
    assert_raises(ZoneDigest::MissingSoaError) { ZoneDigest.digest(rrs, 2018031500) }
  end

  def test_zone_reader_integration
    Tempfile.create('zonemd-test') do |file|
      file.write(ZONE_TEXT.join("\n"))
      file.write("\n")
      file.flush
      rrs = Dnsruby::ZoneReader.new('example.').process_file(file.path)
      zonemd = ZoneDigest.generate(rrs)
      assert(zonemd.verify_zone(rrs))
      #  The same digest is calculated from the in-memory records
      assert_equal(ZoneDigest.digest(zone_rrs, 2018031500),
        ZoneDigest.digest(rrs, 2018031500))
    end
  end
end
