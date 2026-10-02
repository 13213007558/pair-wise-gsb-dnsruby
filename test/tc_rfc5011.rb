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
require 'json'

class TestRfc5011 < Minitest::Test
  ZONE = "example.com"
  DAY = 24 * 60 * 60
  T0 = Time.utc(2026, 1, 1).to_i
  ADD_HOLD_DOWN = Dnsruby::Rfc5011::DEFAULT_ADD_HOLD_DOWN

  def make_key(seed, revoked: false, zone: ZONE)
    flags = 257 # ZONE_KEY | SEP_KEY (KSK)
    flags |= Dnsruby::RR::DNSKEY::REVOKED_KEY if revoked
    key_material = ("rfc5011-test-key-#{seed}" * 8)
    Dnsruby::RR.create(
      "#{zone}. 3600 IN DNSKEY #{flags} 3 8 #{[key_material].pack('m0')}")
  end

  def make_tracker
    Dnsruby::Rfc5011.new(ZONE)
  end

  def test_new_key_is_candidate_not_trusted
    tracker = make_tracker
    key = make_key("a")
    tracker.observe([key], T0)

    assert_equal(1, tracker.candidates.length)
    assert_equal(Dnsruby::Rfc5011::Anchor::ADD_PEND, tracker.candidates.first.state)
    assert_empty(tracker.trusted_anchors)
    refute(tracker.trusted?(key))
    assert_equal(T0 + ADD_HOLD_DOWN, tracker.candidates.first.add_pend_expires)
  end

  def test_key_promoted_only_after_full_add_hold_down
    tracker = make_tracker
    key = make_key("a")
    tracker.observe([key], T0)

    # One day before the 30 day hold-down expires: still pending.
    tracker.observe([key], T0 + ADD_HOLD_DOWN - DAY)
    assert_empty(tracker.trusted_anchors)
    assert_equal(1, tracker.candidates.length)

    # Hold-down reached: promoted to Valid.
    tracker.observe([key], T0 + ADD_HOLD_DOWN)
    assert_equal(1, tracker.trusted_anchors.length)
    assert(tracker.trusted?(key))
    assert_empty(tracker.candidates)
    assert_equal(Dnsruby::Rfc5011::Anchor::VALID, tracker.anchors.first.state)
  end

  def test_brief_disappearance_during_add_pend_resets_timer
    tracker = make_tracker
    key = make_key("a")
    tracker.observe([key], T0)
    tracker.observe([key], T0 + 10 * DAY)

    # Key vanishes from a validated RRset: candidate dropped, timer reset.
    tracker.observe([], T0 + 15 * DAY)
    assert_empty(tracker.candidates)
    assert_empty(tracker.anchors)

    # Key reappears: the full hold-down starts again from scratch.
    tracker.observe([key], T0 + 20 * DAY)
    assert_equal(1, tracker.candidates.length)
    assert_equal(T0 + 20 * DAY + ADD_HOLD_DOWN,
                 tracker.candidates.first.add_pend_expires)

    # 29 days after reappearance (39 days of total presence): not enough.
    tracker.observe([key], T0 + 20 * DAY + ADD_HOLD_DOWN - DAY)
    assert_empty(tracker.trusted_anchors)

    tracker.observe([key], T0 + 20 * DAY + ADD_HOLD_DOWN)
    assert(tracker.trusted?(key))
  end

  def test_valid_key_missing_then_reappears
    tracker = make_tracker
    key = make_key("a")
    tracker.observe([key], T0)
    tracker.observe([key], T0 + ADD_HOLD_DOWN)
    assert(tracker.trusted?(key))

    # Missing keys remain usable as trust anchors (RFC 5011 section 4.2).
    tracker.observe([], T0 + ADD_HOLD_DOWN + DAY)
    assert_equal(Dnsruby::Rfc5011::Anchor::MISSING, tracker.anchors.first.state)
    assert(tracker.trusted?(key))
    assert_equal(1, tracker.trusted_anchors.length)

    # Reappearing valid keys return to Valid with no new hold-down.
    tracker.observe([key], T0 + ADD_HOLD_DOWN + 2 * DAY)
    assert_equal(Dnsruby::Rfc5011::Anchor::VALID, tracker.anchors.first.state)
    assert(tracker.trusted?(key))
  end

  def test_missing_key_removed_after_remove_hold_down
    tracker = make_tracker
    key = make_key("a")
    tracker.observe([key], T0)
    tracker.observe([key], T0 + ADD_HOLD_DOWN)

    gone_at = T0 + ADD_HOLD_DOWN + DAY
    tracker.observe([], gone_at)
    assert(tracker.trusted?(key))

    # Still missing just before the remove hold-down expires.
    tracker.observe([], gone_at + Dnsruby::Rfc5011::DEFAULT_REMOVE_HOLD_DOWN - DAY)
    assert_equal(Dnsruby::Rfc5011::Anchor::MISSING, tracker.anchors.first.state)
    assert(tracker.trusted?(key))

    # Remove hold-down reached: key removed and no longer trusted.
    tracker.observe([], gone_at + Dnsruby::Rfc5011::DEFAULT_REMOVE_HOLD_DOWN)
    assert_equal(Dnsruby::Rfc5011::Anchor::REMOVED, tracker.anchors.first.state)
    assert_empty(tracker.trusted_anchors)
    refute(tracker.trusted?(key))
  end

  def test_revoked_key
    tracker = make_tracker
    key = make_key("a")
    tracker.observe([key], T0)
    tracker.observe([key], T0 + ADD_HOLD_DOWN)
    assert(tracker.trusted?(key))

    # Key appears with the REVOKE bit: immediately unusable.
    revoked_key = make_key("a", revoked: true)
    revoked_at = T0 + ADD_HOLD_DOWN + DAY
    tracker.observe([revoked_key], revoked_at)
    assert_equal(Dnsruby::Rfc5011::Anchor::REVOKED, tracker.anchors.first.state)
    assert_empty(tracker.trusted_anchors)
    refute(tracker.trusted?(key))

    # An un-revoked copy reappearing must not resurrect the key.
    tracker.observe([key], revoked_at + DAY)
    assert_equal(Dnsruby::Rfc5011::Anchor::REVOKED, tracker.anchors.first.state)
    refute(tracker.trusted?(key))

    # After the remove hold-down the revoked key is removed entirely.
    tracker.observe([], revoked_at + Dnsruby::Rfc5011::DEFAULT_REMOVE_HOLD_DOWN)
    assert_equal(Dnsruby::Rfc5011::Anchor::REMOVED, tracker.anchors.first.state)
  end

  def test_revoked_key_never_seen_before_is_never_trusted
    tracker = make_tracker
    tracker.observe([make_key("a", revoked: true)], T0)
    assert_equal(Dnsruby::Rfc5011::Anchor::REVOKED, tracker.anchors.first.state)
    assert_empty(tracker.trusted_anchors)

    # The un-revoked form turning up later must not be added either.
    tracker.observe([make_key("a")], T0 + DAY)
    assert_equal(Dnsruby::Rfc5011::Anchor::REVOKED, tracker.anchors.first.state)
    assert_empty(tracker.trusted_anchors)
  end

  def test_unvalidated_observations_are_ignored
    tracker = make_tracker
    key = make_key("a")

    # An unauthenticated sighting creates no candidate.
    tracker.observe([key], T0, validated: false)
    assert_empty(tracker.candidates)
    assert_empty(tracker.anchors)

    # The hold-down clock only starts at the first validated sighting.
    tracker.observe([key], T0 + 5 * DAY)
    assert_equal(T0 + 5 * DAY + ADD_HOLD_DOWN,
                 tracker.candidates.first.add_pend_expires)

    # An unauthenticated RRset without the key must not reset the timer.
    tracker.observe([], T0 + 10 * DAY, validated: false)
    assert_equal(1, tracker.candidates.length)

    # And an unauthenticated sighting cannot complete the hold-down.
    tracker.observe([key], T0 + 5 * DAY + ADD_HOLD_DOWN, validated: false)
    assert_empty(tracker.trusted_anchors)
    tracker.observe([key], T0 + 5 * DAY + ADD_HOLD_DOWN)
    assert(tracker.trusted?(key))
  end

  def test_restart_in_the_middle_of_add_pend
    tracker = make_tracker
    key = make_key("a")
    tracker.observe([key], T0)
    tracker.observe([key], T0 + 10 * DAY)

    # Process restarts half way through the hold-down period: state is
    # persisted (through JSON, proving it is serialisable) and restored.
    persisted = JSON.parse(JSON.generate(tracker.to_h))
    restored = Dnsruby::Rfc5011.from_h(persisted)

    assert_equal(1, restored.candidates.length)
    assert_equal(T0 + ADD_HOLD_DOWN, restored.candidates.first.add_pend_expires)
    assert_empty(restored.trusted_anchors)

    # The hold-down continues from where it left off, not from the restart.
    restored.observe([key], T0 + 20 * DAY)
    assert_empty(restored.trusted_anchors)
    restored.observe([key], T0 + ADD_HOLD_DOWN)
    assert(restored.trusted?(key))
  end

  def test_restart_preserves_valid_and_missing_states
    tracker = make_tracker
    key = make_key("a")
    tracker.observe([key], T0)
    tracker.observe([key], T0 + ADD_HOLD_DOWN)
    tracker.observe([], T0 + ADD_HOLD_DOWN + DAY) # now Missing

    restored = Dnsruby::Rfc5011.from_h(JSON.parse(JSON.generate(tracker.to_h)))
    assert_equal(Dnsruby::Rfc5011::Anchor::MISSING, restored.anchors.first.state)
    assert(restored.trusted?(key))

    # Missing timer keeps running across the restart.
    gone_at = T0 + ADD_HOLD_DOWN + DAY
    restored.observe([], gone_at + Dnsruby::Rfc5011::DEFAULT_REMOVE_HOLD_DOWN)
    assert_equal(Dnsruby::Rfc5011::Anchor::REMOVED, restored.anchors.first.state)
    assert_empty(restored.trusted_anchors)
  end

  def test_accepts_rrset_and_ignores_other_zones_and_types
    tracker = make_tracker
    key = make_key("a")
    rrset = Dnsruby::RRSet.new
    rrset.add(key)
    rrset.add(Dnsruby::RR.create("#{ZONE}. 3600 IN A 192.0.2.1"))
    rrset.add(make_key("b", zone: "other.example"))
    tracker.observe(rrset, T0)

    assert_equal(1, tracker.candidates.length)
    assert_equal(key.key_tag, tracker.candidates.first.key.key_tag)
  end

  def test_old_anchor_still_trusted_while_new_key_held_down
    tracker = make_tracker
    old_key = make_key("old")
    new_key = make_key("new")

    tracker.observe([old_key], T0)
    tracker.observe([old_key], T0 + ADD_HOLD_DOWN)
    assert(tracker.trusted?(old_key))

    # The new KSK must not replace the old one on first sight.
    tracker.observe([old_key, new_key], T0 + ADD_HOLD_DOWN + DAY)
    assert(tracker.trusted?(old_key))
    refute(tracker.trusted?(new_key))
    assert_equal(1, tracker.candidates.length)

    # Only after its own hold-down does the new key become trusted too.
    tracker.observe([old_key, new_key], T0 + ADD_HOLD_DOWN + DAY + ADD_HOLD_DOWN)
    assert(tracker.trusted?(old_key))
    assert(tracker.trusted?(new_key))
  end
end
