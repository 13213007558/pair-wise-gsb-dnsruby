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
require 'tempfile'

class Rfc5011Test < Minitest::Test
  ZONE = 'example.com.'
  DAY = 24 * 60 * 60
  HOLD_DOWN = Dnsruby::Rfc5011::TrustAnchorManager::DEFAULT_ADD_HOLD_DOWN

  #  A virtual clock so tests can travel through the RFC 5011 hold-down
  #  periods without sleeping.
  class FakeClock
    def initialize(start = Time.utc(2026, 1, 1))
      @now = start
    end

    def call
      @now
    end

    def advance(seconds)
      @now += seconds
      self
    end
  end

  def setup
    @clock = FakeClock.new
    @manager = Dnsruby::Rfc5011::TrustAnchorManager.new(ZONE, :clock => @clock)
  end

  #  Build a deterministic DNSKEY for the zone. +seed+ picks the key
  #  material; +revoked+ sets the RFC 5011 REVOKE bit.
  def make_key(seed, revoked: false)
    blob = "\x03\x01\x00\x01" + seed.chr * 128
    rr = Dnsruby::RR.create({
      :name => ZONE, :type => 'DNSKEY', :ttl => 3600,
      :flags => 257, :protocol => 3, :algorithm => 8,
      :key => [blob].pack('m0')
    })
    rr.revoked = true if revoked
    rr
  end

  def test_new_key_starts_as_candidate
    key = make_key(1)
    @manager.update([key])
    assert_equal(:candidate, @manager.state_of(key))
    refute(@manager.trusted?(key))
    assert_empty(@manager.trust_anchors)
  end

  def test_candidate_promoted_after_add_hold_down
    key = make_key(1)
    @manager.update([key])
    @clock.advance(HOLD_DOWN)
    @manager.update([key])
    assert_equal(:valid, @manager.state_of(key))
    assert_equal([key].map {|k| k.key_tag}, @manager.trust_anchors.map {|k| k.key_tag})
  end

  def test_candidate_not_promoted_before_hold_down_expires
    key = make_key(1)
    @manager.update([key])
    @clock.advance(HOLD_DOWN - DAY)
    @manager.update([key])
    assert_equal(:candidate, @manager.state_of(key))
    assert_empty(@manager.trust_anchors)
    assert_equal(DAY, @manager.add_hold_down_remaining(key))
  end

  def test_candidate_disappear_and_reappear_restarts_timer
    key = make_key(1)
    @manager.update([key])
    @clock.advance(10 * DAY)
    #  The key vanishes from the validated RRSet : the candidate is dropped
    @manager.update([])
    assert_nil(@manager.state_of(key))
    #  It reappears later : the add hold-down starts over from scratch
    @clock.advance(5 * DAY)
    @manager.update([key])
    assert_equal(:candidate, @manager.state_of(key))
    @clock.advance(HOLD_DOWN - DAY)
    @manager.update([key])
    assert_equal(:candidate, @manager.state_of(key))
    @clock.advance(DAY)
    @manager.update([key])
    assert_equal(:valid, @manager.state_of(key))
  end

  def test_valid_key_survives_brief_absence
    key = make_key(1)
    @manager.update([key])
    @clock.advance(HOLD_DOWN)
    @manager.update([key])
    assert_equal(:valid, @manager.state_of(key))
    #  A validated RRSet which (briefly) omits the key must not untrust it
    @clock.advance(DAY)
    @manager.update([])
    assert_equal(:valid, @manager.state_of(key))
    assert_equal(1, @manager.trust_anchors.length)
    @clock.advance(DAY)
    @manager.update([key])
    assert_equal(:valid, @manager.state_of(key))
  end

  def test_revoke_valid_key
    key = make_key(1)
    @manager.update([key])
    @clock.advance(HOLD_DOWN)
    @manager.update([key])
    assert_equal(:valid, @manager.state_of(key))
    #  The key republishes itself with the REVOKE bit set
    @clock.advance(DAY)
    @manager.update([make_key(1, :revoked => true)])
    assert_equal(:revoked, @manager.state_of(key))
    assert_empty(@manager.trust_anchors)
    #  A revoked key is never resurrected by its unrevoked form
    @clock.advance(DAY)
    @manager.update([key])
    assert_equal(:revoked, @manager.state_of(key))
    assert_empty(@manager.trust_anchors)
    #  Purged once the remove hold-down expires
    @clock.advance(Dnsruby::Rfc5011::TrustAnchorManager::DEFAULT_REMOVE_HOLD_DOWN)
    @manager.update([])
    assert_nil(@manager.state_of(key))
  end

  def test_revoked_candidate_is_dropped
    key = make_key(1)
    @manager.update([key])
    assert_equal(:candidate, @manager.state_of(key))
    @clock.advance(DAY)
    @manager.update([make_key(1, :revoked => true)])
    assert_nil(@manager.state_of(key))
  end

  def test_rollover_overlap
    old_key = make_key(1)
    new_key = make_key(2)
    @manager.update([old_key])
    @clock.advance(HOLD_DOWN)
    @manager.update([old_key])
    assert_equal(:valid, @manager.state_of(old_key))
    #  Introduce the successor : overlap period begins
    @manager.update([old_key, new_key])
    assert_equal(:candidate, @manager.state_of(new_key))
    @clock.advance(HOLD_DOWN)
    @manager.update([old_key, new_key])
    assert_equal(:valid, @manager.state_of(old_key))
    assert_equal(:valid, @manager.state_of(new_key))
    assert_equal(2, @manager.trust_anchors.length)
    #  The old key is revoked, leaving only the successor
    @clock.advance(DAY)
    @manager.update([make_key(1, :revoked => true), new_key])
    assert_equal(:revoked, @manager.state_of(old_key))
    assert_equal(:valid, @manager.state_of(new_key))
    assert_equal([new_key.key_tag], @manager.trust_anchors.map {|k| k.key_tag})
  end

  def test_state_persistence_preserves_hold_down
    key = make_key(1)
    @manager.update([key])
    @clock.advance(10 * DAY)
    snapshot = @manager.to_h
    #  Simulate a restart : restore from the snapshot with the same clock
    restored = Dnsruby::Rfc5011::TrustAnchorManager.from_h(snapshot, :clock => @clock)
    assert_equal(:candidate, restored.state_of(key))
    assert_equal(HOLD_DOWN - 10 * DAY, restored.add_hold_down_remaining(key))
    #  The waiting period was not reset by the restart
    @clock.advance(HOLD_DOWN - 10 * DAY)
    restored.update([key])
    assert_equal(:valid, restored.state_of(key))
  end

  def test_save_and_load_file
    key = make_key(1)
    @manager.update([key])
    @clock.advance(10 * DAY)
    Tempfile.create('rfc5011') {|f|
      @manager.save(f.path)
      loaded = Dnsruby::Rfc5011::TrustAnchorManager.load(f.path, :clock => @clock)
      assert_equal(:candidate, loaded.state_of(key))
      @clock.advance(HOLD_DOWN - 10 * DAY)
      loaded.update([key])
      assert_equal(:valid, loaded.state_of(key))
    }
  end

  def test_initial_trust_anchors_are_valid
    key = make_key(1)
    manager = Dnsruby::Rfc5011::TrustAnchorManager.new(ZONE,
      :trust_anchors => [key], :clock => @clock)
    assert_equal(:valid, manager.state_of(key))
    assert_equal(1, manager.trust_anchors.length)
  end

  def test_update_accepts_rrset_and_message
    key = make_key(1)
    rrset = Dnsruby::RRSet.new
    rrset.add(key)
    @manager.update(rrset)
    assert_equal(:candidate, @manager.state_of(key))
    other = make_key(2)
    msg = Dnsruby::Message.new
    msg.add_answer(other)
    @manager.update(msg)
    assert_equal(:candidate, @manager.state_of(other))
  end

  def test_keys_from_other_zones_are_ignored
    foreign = Dnsruby::RR.create({
      :name => 'other.example.', :type => 'DNSKEY', :ttl => 3600,
      :flags => 257, :protocol => 3, :algorithm => 8,
      :key => ["\x03\x01\x00\x01" + "\x09" * 128].pack('m0')
    })
    @manager.update([foreign])
    assert_nil(@manager.state_of(foreign))
    assert_empty(@manager.tracked_keys)
  end

  def test_static_trust_anchor_api_untouched
    anchor = make_key(7)
    Dnsruby::Dnssec.add_trust_anchor(anchor)
    assert(Dnsruby::Dnssec.trust_anchors.length > 0)
  ensure
    Dnsruby::Dnssec.clear_trust_anchors
  end
end
