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

class Rfc5011Test < Minitest::Test
  # Short hold-down so the timeline tests run instantly rather than the
  # 30 days mandated by RFC 5011.
  HOLD_DOWN = 60
  T0 = 1_000_000

  def self.make_dnskey(flags)
    rsa = OpenSSL::PKey::RSA.generate(1024)
    exponent = rsa.params["e"].to_s(2)
    modulus = rsa.params["n"].to_s(2)
    length_prefix = if exponent.length > 255
                      "\x00".b + [exponent.length].pack("n")
                    else
                      [exponent.length].pack("C")
                    end
    blob = length_prefix + exponent + modulus
    Dnsruby::RR.create(
      "example. 3600 IN DNSKEY #{flags} 3 5 #{[blob].pack('m0')}"
    )
  end

  # KSK (SEP) anchors / candidates
  K1 = make_dnskey(257)
  K2 = make_dnskey(257)
  # ZSK - never managed by RFC 5011
  ZSK = make_dnskey(256)

  def revoked(key)
    copy = key.clone
    copy.revoked = true
    copy
  end

  def new_manager(anchors = [K1])
    Dnsruby::RFC5011::TrustAnchorManager.new(anchors, hold_down: HOLD_DOWN)
  end

  def identities(*keys)
    keys.map { |key| Dnsruby::RFC5011::TrustAnchorManager.identity(key) }
  end

  def assert_anchor_tags(manager, *keys)
    expected = identities(*keys).sort
    actual = manager.trust_anchors.map do |key|
      Dnsruby::RFC5011::TrustAnchorManager.identity(key)
    end.sort
    assert_equal expected, actual
  end

  def test_configured_anchors_start_valid
    manager = new_manager
    assert_equal :valid, manager.state_of(K1)
    assert_anchor_tags manager, K1
    assert_empty manager.candidates
  end

  def test_new_key_passes_through_add_hold_down
    manager = new_manager
    manager.process([K1, K2], T0)
    assert_equal :add_pending, manager.state_of(K2)
    assert_anchor_tags manager, K1
    assert_equal 1, manager.candidates.size
    assert_equal T0, manager.hold_down_start_of(K2)

    # One second before the add hold-down expires: still a candidate.
    manager.process([K1, K2], T0 + HOLD_DOWN - 1)
    assert_equal :add_pending, manager.state_of(K2)
    assert_anchor_tags manager, K1

    # RFC 5011 section 2.3.1: key present at every authenticated
    # observation for the whole hold-down period becomes trusted.
    manager.process([K1, K2], T0 + HOLD_DOWN)
    assert_equal :valid, manager.state_of(K2)
    assert_anchor_tags manager, K1, K2
    assert_empty manager.candidates
  end

  def test_unauthenticated_observation_does_not_change_state
    manager = new_manager
    manager.process([K1, K2], T0)
    assert_equal :add_pending, manager.state_of(K2)

    # Unauthenticated observations change neither presence nor timers.
    # Even an RRset which appears to show K2 missing or K1 revoked cannot
    # move the state machine.
    manager.process([K1], T0 + 10, authenticated: false)
    manager.process([revoked(K1), K2], T0 + 20, authenticated: false)
    assert_equal :add_pending, manager.state_of(K2)
    assert_equal T0, manager.hold_down_start_of(K2)
    assert_equal :valid, manager.state_of(K1)
    assert_anchor_tags manager, K1

    # An authenticated observation just before the hold-down ends keeps
    # K2 a candidate; the next one promotes it.
    manager.process([K1, K2], T0 + HOLD_DOWN - 1)
    assert_equal :add_pending, manager.state_of(K2)
    manager.process([K1, K2], T0 + HOLD_DOWN)
    assert_equal :valid, manager.state_of(K2)
  end

  def test_disappearance_during_unauthenticated_gap_is_unseen
    manager = new_manager
    manager.process([K1, K2], T0)
    # K2 disappears for a long time, but every observation in the gap is
    # unauthenticated, so the state machine must not notice the absence.
    manager.process([K1], T0 + 10, authenticated: false)
    manager.process([K1], T0 + HOLD_DOWN + 10, authenticated: false)
    assert_equal :add_pending, manager.state_of(K2)
    # The first authenticated observation after the gap still sees K2, so
    # the add hold-down completes normally against the wall clock.
    manager.process([K1, K2], T0 + HOLD_DOWN + 20)
    assert_equal :valid, manager.state_of(K2)
  end

  def test_candidate_absent_once_drops_back_to_start
    manager = new_manager
    manager.process([K1, K2], T0)
    manager.process([K1, K2], T0 + 10)
    assert_equal :add_pending, manager.state_of(K2)

    # A single authenticated RRset without K2 resets the candidate;
    # transient disappearance is not enough to retain trust.
    manager.process([K1], T0 + 20)
    assert_nil manager.state_of(K2)

    # Seen again much later: it is a fresh candidate with a new timer.
    manager.process([K1, K2], T0 + HOLD_DOWN + 30)
    assert_equal T0 + HOLD_DOWN + 30, manager.hold_down_start_of(K2)
    assert_equal :add_pending, manager.state_of(K2)
  end

  def test_candidate_seen_revoked_is_discarded
    manager = new_manager
    manager.process([K1, K2], T0)
    # Revoked form shares the identity (owner, algorithm, key blob).
    manager.process([K1, revoked(K2)], T0 + 10)
    assert_nil manager.state_of(K2)
  end

  def test_brand_new_revoked_key_is_ignored
    manager = new_manager
    manager.process([K1, revoked(K2)], T0)
    assert_nil manager.state_of(K2)
    assert_anchor_tags manager, K1
  end

  def test_valid_key_revocation_then_removal
    manager = new_manager
    manager.process([K1, revoked(K1)], T0)
    assert_equal :revoked, manager.state_of(K1)
    # A revoked key is removed from the trust set immediately.
    assert_empty manager.trust_anchors

    # Still within the revocation hold-down: not yet reusable.
    manager.process([K1, revoked(K1)], T0 + HOLD_DOWN - 1)
    assert_equal :revoked, manager.state_of(K1)

    # RFC 5011 section 2.3.3: after the revocation hold-down the revoked
    # key is removed from state entirely and cannot be reused.
    manager.process([K1, revoked(K1)], T0 + HOLD_DOWN)
    assert_nil manager.state_of(K1)

    # Re-observed non-revoked after expiry starts a fresh add hold-down
    # rather than silently becoming trusted.
    manager.process([K1], T0 + HOLD_DOWN + 1)
    assert_equal :add_pending, manager.state_of(K1)
  end

  def test_revoked_key_seen_without_revoke_flag_stays_revoked
    manager = new_manager
    manager.process([K1, revoked(K1)], T0)
    # Revocation is irrevocable during the hold-down.
    manager.process([K1], T0 + 10)
    assert_equal :revoked, manager.state_of(K1)
    manager.process([K1], T0 + HOLD_DOWN - 1)
    assert_equal :revoked, manager.state_of(K1)
  end

  def test_valid_key_missing_reappears_within_hold_down
    manager = new_manager
    manager.process([K1], T0)
    manager.process([], T0 + 10)
    assert_equal :missing, manager.state_of(K1)
    # MISSING keys remain trusted until the removal hold-down expires.
    assert_anchor_tags manager, K1

    manager.process([K1], T0 + 20)
    assert_equal :valid, manager.state_of(K1)
    assert_anchor_tags manager, K1

    # The earlier absence must not leave a stale timer.
    manager.process([], T0 + 30)
    assert_equal :missing, manager.state_of(K1)
    assert_equal T0 + 30, manager.hold_down_start_of(K1)
  end

  def test_valid_key_removed_after_missing_for_hold_down
    manager = new_manager
    manager.process([], T0)
    assert_equal :missing, manager.state_of(K1)

    manager.process([], T0 + HOLD_DOWN - 1)
    assert_equal :missing, manager.state_of(K1)
    assert_anchor_tags manager, K1

    manager.process([], T0 + HOLD_DOWN)
    assert_nil manager.state_of(K1)
    assert_empty manager.trust_anchors

    # Reappearance after removal requires a fresh add hold-down.
    manager.process([K1], T0 + HOLD_DOWN + 1)
    assert_equal :add_pending, manager.state_of(K1)
  end

  def test_missing_key_revoked_on_reappearance
    manager = new_manager
    manager.process([], T0)
    assert_equal :missing, manager.state_of(K1)
    manager.process([revoked(K1)], T0 + 10)
    assert_equal :revoked, manager.state_of(K1)
    assert_empty manager.trust_anchors
    assert_equal T0 + 10, manager.hold_down_start_of(K1)
  end

  def test_revoked_key_disappearing_completes_revocation_hold_down
    manager = new_manager
    manager.process([revoked(K1)], T0)
    manager.process([], T0 + 10)
    assert_equal :revoked, manager.state_of(K1)
    manager.process([], T0 + HOLD_DOWN)
    assert_nil manager.state_of(K1)
  end

  def test_state_restores_after_restart_mid_hold_down
    manager = new_manager
    manager.process([K1, K2], T0)
    saved = manager.to_h

    # Simulate the process restarting 40 seconds into the add hold-down.
    restored = Dnsruby::RFC5011::TrustAnchorManager.from_h(saved)
    assert_equal :add_pending, restored.state_of(K2)
    assert_equal T0, restored.hold_down_start_of(K2)
    restored.process([K1, K2], T0 + 40)
    assert_equal :add_pending, restored.state_of(K2)
    # The timer is absolute and persisted, so only 20 more seconds needed.
    restored.process([K1, K2], T0 + HOLD_DOWN)
    assert_equal :valid, restored.state_of(K2)
  end

  def test_state_restores_mid_removal_hold_down
    manager = new_manager
    manager.process([], T0)
    assert_equal :missing, manager.state_of(K1)
    saved = manager.to_h

    restored = Dnsruby::RFC5011::TrustAnchorManager.from_h(saved)
    restored.process([], T0 + HOLD_DOWN - 1)
    assert_equal :missing, restored.state_of(K1)
    assert_anchor_tags restored, K1
    restored.process([], T0 + HOLD_DOWN)
    assert_nil restored.state_of(K1)
  end

  def test_saved_state_round_trips_through_json
    manager = new_manager
    manager.process([K1, K2], T0)
    restored = Dnsruby::RFC5011::TrustAnchorManager.from_h(JSON.generate(manager.to_h))
    assert_equal :valid, restored.state_of(K1)
    assert_equal :add_pending, restored.state_of(K2)
    assert_equal T0, restored.hold_down_start_of(K2)
    assert_equal HOLD_DOWN, restored.to_h['hold_down']
  end

  def test_zsk_is_not_managed
    manager = new_manager
    manager.process([K1, ZSK], T0)
    assert_nil manager.state_of(ZSK)
    assert_empty manager.candidates
  end

  def test_time_objects_accepted_as_clock
    manager = new_manager
    start = Time.utc(2026, 1, 1)
    manager.process([K1, K2], start)
    assert_equal :add_pending, manager.state_of(K2)
    manager.process([K1, K2], start + HOLD_DOWN)
    assert_equal :valid, manager.state_of(K2)
  end

  def test_rrset_input_and_anchor_replacement_timeline
    manager = new_manager
    rrset = Dnsruby::RRSet.new([K1, K2])
    manager.process(rrset, T0)
    manager.process(rrset, T0 + HOLD_DOWN)
    assert_anchor_tags manager, K1, K2

    # Roll: K1 revoked and later drops out, K2 carries the chain.
    manager.process(Dnsruby::RRSet.new([revoked(K1), K2]), T0 + HOLD_DOWN + 10)
    assert_anchor_tags manager, K2
    assert_equal :revoked, manager.state_of(K1)
    manager.process(Dnsruby::RRSet.new([K2]), T0 + HOLD_DOWN + 20)
    manager.process(Dnsruby::RRSet.new([K2]), T0 + 2 * HOLD_DOWN + 10)
    assert_nil manager.state_of(K1)
    assert_anchor_tags manager, K2
  end
end
