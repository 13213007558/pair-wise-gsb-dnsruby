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
require 'tmpdir'

class ManagedTrustAnchorsTest < Minitest::Test
  ECDSA_KEY = "oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA=="
  RSA_KEY = "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk="
  DAY = 24 * 60 * 60

  def test_rfc5011_lifecycle_with_virtual_time_and_persistence
    Dir.mktmpdir do |directory|
      state_path = File.join(directory, "managed-anchors.json")
      t0 = 1_000_000_000

      current = dnskey(ECDSA_KEY, 13, 257)
      standby = dnskey(RSA_KEY, 8, 257)
      zsk = dnskey(ECDSA_KEY, 13, 256)

      manager = Dnsruby::ManagedTrustAnchorManager.new(
        "example.", current, state_path: state_path,
        hold_down_time: 30 * DAY,
        removal_hold_down_time: 30 * DAY
      )

      assert_equal :valid, manager.key_status(current)
      assert_equal [current.key_tag], manager.trust_anchors.map(&:key_tag)

      manager.process_observation([current, standby], t0)
      assert_equal :candidate, manager.key_status(standby)
      assert_equal [standby.key_tag], manager.candidates.map(&:key_tag)

      manager.process_observation([current], t0 + 10 * DAY)
      assert_equal :candidate, manager.key_status(standby)
      assert_equal false, manager.key_state(standby)[:present]

      manager = Dnsruby::ManagedTrustAnchorManager.load(state_path)
      manager.process_observation([current, standby], t0 + 20 * DAY)
      assert_equal :candidate, manager.key_status(standby)

      manager.process_observation([current, standby], t0 + 39 * DAY)
      assert_equal :candidate, manager.key_status(standby)

      manager.process_observation([current, standby, zsk], t0 + 40 * DAY)
      assert_equal :valid, manager.key_status(standby)
      assert_equal :valid, manager.key_status(current)
      assert_equal [current.key_tag, standby.key_tag].sort,
                   manager.trust_anchors.map(&:key_tag).sort
      assert_equal [], manager.candidates

      manager.process_observation([standby, zsk], t0 + 41 * DAY)
      assert_equal :valid, manager.key_status(current)
      assert_equal false, manager.key_state(current)[:present]
      assert_equal [current.key_tag, standby.key_tag].sort,
                   manager.trust_anchors.map(&:key_tag).sort

      manager.process_observation([current, standby], t0 + 42 * DAY)
      assert_equal true, manager.key_state(current)[:present]
      assert_equal :valid, manager.key_status(current)

      revoked_current = current.clone
      revoked_current.revoked = true
      manager.process_observation([revoked_current, standby], t0 + 43 * DAY)
      assert_equal :revoked, manager.key_status(revoked_current)
      assert_equal :valid, manager.key_status(standby)
      assert_equal [standby.key_tag], manager.trust_anchors.map(&:key_tag)
      assert_equal [revoked_current.key_tag], manager.revoked_keys.map(&:key_tag)
      assert_equal current.key_tag,
                   manager.key_state(revoked_current)[:pre_revoked_key_tag]

      manager.process_observation([standby], t0 + 44 * DAY)
      assert_equal :revoked, manager.key_status(revoked_current)
      assert_equal false, manager.key_state(revoked_current)[:present]
      assert_equal [standby.key_tag], manager.trust_anchors.map(&:key_tag)

      manager.process_observation([standby], t0 + 72 * DAY)
      assert_equal :revoked, manager.key_status(revoked_current)

      manager.process_observation([standby], t0 + 73 * DAY)
      assert_nil manager.key_status(revoked_current)
      assert_equal :valid, manager.key_status(standby)
    end
  end

  def test_revoked_candidate_is_removed_immediately
    current = dnskey(ECDSA_KEY, 13, 257)
    standby = dnskey(RSA_KEY, 8, 257)
    revoked_standby = standby.clone
    revoked_standby.revoked = true
    manager = Dnsruby::ManagedTrustAnchorManager.new("example.", current)

    manager.process_observation([current, standby], 100)
    manager.process_observation([current, revoked_standby], 200)

    assert_nil manager.key_status(standby)
    assert_nil manager.key_status(revoked_standby)
    assert_equal :valid, manager.key_status(current)
  end

  def test_revoked_key_that_returns_unrevoked_starts_hold_down
    current = dnskey(ECDSA_KEY, 13, 257)
    revoked_current = current.clone
    revoked_current.revoked = true
    manager = Dnsruby::ManagedTrustAnchorManager.new("example.", current)

    manager.process_observation([revoked_current], 100)
    assert_equal :revoked, manager.key_status(current)

    manager.process_observation([current], 101)
    assert_equal :candidate, manager.key_status(current)
    assert_equal [], manager.trust_anchors
  end

  def test_observations_must_be_dnskeys_for_managed_zone
    manager = Dnsruby::ManagedTrustAnchorManager.new("example.")
    other_zone = dnskey(ECDSA_KEY, 13, 257, "other.")
    cname = Dnsruby::RR.create("example. 3600 IN CNAME target.example.")

    assert_raises(ArgumentError) { manager.process_observation(other_zone, 100) }
    assert_raises(ArgumentError) { manager.process_observation(cname, 100) }
  end

  def test_state_can_be_restored_from_a_hash
    current = dnskey(ECDSA_KEY, 13, 257)
    standby = dnskey(RSA_KEY, 8, 257)
    manager = Dnsruby::ManagedTrustAnchorManager.new("example.", current)
    manager.process_observation([current, standby], 100)

    restored = Dnsruby::ManagedTrustAnchorManager.new(
      "example.", state: manager.to_h
    )

    assert_equal :valid, restored.key_status(current)
    assert_equal :candidate, restored.key_status(standby)
    assert_equal 100, restored.key_state(standby)[:first_seen]
  end

  def test_static_dnssec_interface_remains_separate
    assert_respond_to Dnsruby::Dnssec, :add_trust_anchor
    assert_respond_to Dnsruby::Dnssec, :trust_anchors
    assert_equal false, Dnsruby::Dnssec.respond_to?(:process_observation)
  end

  private

  def dnskey(public_key, algorithm, flags, name = "example.")
    Dnsruby::RR.new_from_string(
      "#{name} 3600 IN DNSKEY #{flags} 3 #{algorithm} #{public_key}"
    )
  end
end
