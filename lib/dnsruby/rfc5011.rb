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
require 'json'
module Dnsruby

  #  RFC 5011 - Automated Updates of DNS Security (DNSSEC) Trust Anchors
  #
  #  This module manages the long-term evolution of trust anchors for a
  #  trust point (zone). It consumes DNSKEY RRSets which have *already been
  #  validated* against the current trust anchors (validation is performed
  #  by the caller, e.g. via Dnssec.verify) and tracks each observed key
  #  through the RFC 5011 state machine :
  #
  #  * candidate - a new key inside the AddPend (add hold-down) period.
  #    It is NOT yet trusted. If it disappears from a validated DNSKEY
  #    RRSet before the hold-down expires, it is dropped and the timer
  #    restarts when (if) it reappears.
  #  * valid - a key which survived the add hold-down period (or was
  #    configured explicitly). It is part of the trust anchor set, and
  #    stays valid even if it is (temporarily) absent from the RRSet.
  #  * revoked - a valid key which published itself with the REVOKE bit
  #    set (RFC 5011 section 2.1). It leaves the trust anchor set
  #    immediately, is never resurrected, and is purged after the remove
  #    hold-down period.
  #
  #  The manager performs no network access itself : observations and the
  #  current time are injected by the caller, which also makes the state
  #  machine fully testable with a virtual clock.
  #
  #  State can be persisted with to_h/save and restored with from_h/load.
  #  Restoring preserves the add hold-down timers, so a restart does not
  #  reset the waiting period of a candidate key.
  #
  #  Example :
  #
  #    manager = Dnsruby::Rfc5011::TrustAnchorManager.new('example.com.',
  #                :trust_anchors => [current_ksk])
  #    # later, for each validated DNSKEY RRSet observed :
  #    manager.update(validated_dnskey_rrset)
  #    anchors = manager.trust_anchors
  #    File.write('anchors.json', JSON.generate(manager.to_h))
  module Rfc5011

    class TrustAnchorManager
      #  RFC 5011, section 4.1 : add hold-down time (30 days)
      DEFAULT_ADD_HOLD_DOWN = 30 * 24 * 60 * 60
      #  RFC 5011, section 4.1 : remove hold-down time (30 days)
      DEFAULT_REMOVE_HOLD_DOWN = 30 * 24 * 60 * 60

      STATE_CANDIDATE = :candidate
      STATE_VALID = :valid
      STATE_REVOKED = :revoked

      #  The zone (trust point) this manager tracks
      attr_reader :zone
      attr_reader :add_hold_down, :remove_hold_down

      #  A key tracked by the manager, with its RFC 5011 state.
      class TrackedKey
        #  The DNSKEY RR (carries the REVOKE bit when state == :revoked)
        attr_reader :key
        #  One of :candidate, :valid, :revoked
        attr_reader :state
        #  Time this key was first observed (start of the add hold-down)
        attr_reader :first_seen
        #  Time this key was last present in a validated RRSet
        attr_reader :last_seen
        #  Time the current state was entered
        attr_reader :state_since

        def initialize(key, state, now) #:nodoc:
          @key = key
          @state = state
          @first_seen = now
          @last_seen = now
          @state_since = now
        end

        def seen(now) #:nodoc:
          @last_seen = now
        end

        def promote!(now) #:nodoc:
          @state = TrustAnchorManager::STATE_VALID
          @state_since = now
        end

        def revoke!(now, revoked_key) #:nodoc:
          @state = TrustAnchorManager::STATE_REVOKED
          @state_since = now
          @key = revoked_key
        end

        #  Seconds of add hold-down remaining for a candidate key at +now+
        #  (0 for keys which are no longer candidates).
        def add_hold_down_remaining(now, hold_down)
          return 0 unless @state == TrustAnchorManager::STATE_CANDIDATE
          remaining = hold_down - (now - @first_seen)
          remaining > 0 ? remaining : 0
        end

        def to_h #:nodoc:
          {
            'dnskey' => @key.to_s,
            'state' => @state.to_s,
            'first_seen' => @first_seen.to_f,
            'last_seen' => @last_seen.to_f,
            'state_since' => @state_since.to_f
          }
        end

        def self.from_h(hash) #:nodoc:
          key = RR.create(hash['dnskey'])
          tracked = new(key, hash['state'].to_sym, Time.at(hash['first_seen']))
          tracked.instance_variable_set(:@last_seen, Time.at(hash['last_seen']))
          tracked.instance_variable_set(:@state_since, Time.at(hash['state_since']))
          tracked
        end
      end

      #  Create a manager for +zone+ (a Name or String).
      #
      #  * :trust_anchors - keys which are already trusted (valid state)
      #  * :clock - a callable returning the current time (Time or epoch
      #    seconds). Defaults to the system clock. Inject a virtual clock
      #    for testing.
      #  * :add_hold_down / :remove_hold_down - RFC 5011 timers, in seconds
      def initialize(zone, trust_anchors: [], clock: nil,
                     add_hold_down: DEFAULT_ADD_HOLD_DOWN,
                     remove_hold_down: DEFAULT_REMOVE_HOLD_DOWN)
        @zone = Name.create(zone)
        @clock = clock || lambda { Time.now }
        @add_hold_down = add_hold_down
        @remove_hold_down = remove_hold_down
        @keys = {} # identity => TrackedKey
        trust_anchors.each {|anchor|
          rr = anchor.clone
          @keys[identity(rr)] = TrackedKey.new(rr, STATE_VALID, now)
        }
      end

      #  Feed the manager a DNSKEY RRSet which has already been validated
      #  against the current trust anchors. Accepts an Array of DNSKEY RRs,
      #  an RRSet, or a whole Message (DNSKEYs are taken from the answer
      #  section). Records for other zones are ignored.
      #
      #  +at+ optionally overrides the observation time (defaults to the
      #  manager clock).
      #
      #  Returns true if the tracked key set changed.
      def update(dnskey_observation, at: nil)
        t = as_time(at || @clock.call)
        present = {}
        revoked = []
        each_dnskey(dnskey_observation) {|rr|
          next unless in_zone?(rr)
          if rr.revoked?
            revoked << rr
          else
            present[identity(rr)] = rr
          end
        }

        changed = false

        #  RFC 5011, section 2.1 : a valid key which republishes itself
        #  with the REVOKE bit set leaves the trust anchor set. A revoked
        #  candidate simply never becomes trusted.
        revoked.each {|rr|
          tracked = @keys[identity(rr)]
          next unless tracked
          if tracked.state == STATE_VALID
            tracked.revoke!(t, rr)
            changed = true
          elsif tracked.state == STATE_CANDIDATE
            @keys.delete(identity(rr))
            changed = true
          end
        }

        #  New keys enter the AddPend (candidate) state; known keys are
        #  refreshed. A revoked key is never resurrected.
        present.each_pair {|id, rr|
          tracked = @keys[id]
          if tracked.nil?
            @keys[id] = TrackedKey.new(rr, STATE_CANDIDATE, t)
            changed = true
          elsif tracked.state != STATE_REVOKED
            tracked.seen(t)
          end
        }

        #  RFC 5011, section 4.2 : a candidate missing from a validated
        #  RRSet is dropped; if it reappears later its timer restarts.
        @keys.values.each {|tracked|
          if tracked.state == STATE_CANDIDATE && !present.key?(identity(tracked.key))
            @keys.delete(identity(tracked.key))
            changed = true
          end
        }

        #  Candidates still present once the add hold-down has expired
        #  become valid trust anchors.
        @keys.values.each {|tracked|
          if tracked.state == STATE_CANDIDATE &&
              (t - tracked.first_seen) >= @add_hold_down
            tracked.promote!(t)
            changed = true
          end
        }

        #  Purge revoked keys once the remove hold-down has expired.
        @keys.values.each {|tracked|
          if tracked.state == STATE_REVOKED &&
              (t - tracked.state_since) >= @remove_hold_down
            @keys.delete(identity(tracked.key))
            changed = true
          end
        }

        changed
      end

      #  The current trust anchor set : DNSKEY RRs in the valid state.
      def trust_anchors
        @keys.values.select {|k| k.state == STATE_VALID}.map {|k| k.key}
      end

      #  All tracked keys (candidate, valid and revoked), most recently
      #  seen first.
      def tracked_keys
        @keys.values.sort_by {|k| k.last_seen}.reverse
      end

      #  The RFC 5011 state (:candidate, :valid, :revoked or nil) of the
      #  given DNSKEY RR.
      def state_of(dnskey_rr)
        tracked = @keys[identity(dnskey_rr)]
        tracked ? tracked.state : nil
      end

      #  True if the given DNSKEY RR is currently a valid trust anchor.
      def trusted?(dnskey_rr)
        state_of(dnskey_rr) == STATE_VALID
      end

      #  Seconds until the given candidate key would be promoted (0 if it
      #  is not a candidate).
      def add_hold_down_remaining(dnskey_rr, at: nil)
        tracked = @keys[identity(dnskey_rr)]
        return 0 unless tracked
        tracked.add_hold_down_remaining(as_time(at || @clock.call), @add_hold_down)
      end

      #  Serializable snapshot of the manager state. Persisting and
      #  restoring this hash preserves the add hold-down timers, so a
      #  restart does not reset the waiting period of candidate keys.
      def to_h
        {
          'version' => 1,
          'zone' => @zone.to_s,
          'add_hold_down' => @add_hold_down,
          'remove_hold_down' => @remove_hold_down,
          'keys' => @keys.values.map {|k| k.to_h}
        }
      end

      #  Restore a manager from a hash produced by to_h. A :clock may be
      #  supplied to override the time source.
      def self.from_h(hash, clock: nil)
        manager = new(hash['zone'],
                      :clock => clock,
                      :add_hold_down => hash['add_hold_down'],
                      :remove_hold_down => hash['remove_hold_down'])
        hash['keys'].each {|key_hash|
          tracked = TrackedKey.from_h(key_hash)
          manager.instance_variable_get(:@keys)[manager.send(:identity, tracked.key)] = tracked
        }
        manager
      end

      #  Persist the manager state to a JSON file.
      def save(path)
        File.write(path, JSON.pretty_generate(to_h))
      end

      #  Restore a manager from a JSON file written by save.
      def self.load(path, clock: nil)
        from_h(JSON.parse(File.read(path)), :clock => clock)
      end

      private

      def now
        as_time(@clock.call)
      end

      def as_time(t)
        t.is_a?(Time) ? t : Time.at(t)
      end

      #  Keys are identified by owner, algorithm and public key material.
      #  The flags field is deliberately excluded so that the revoked form
      #  of a key matches its unrevoked form.
      def identity(rr)
        [rr.name.to_s.downcase, rr.algorithm.code, rr.key]
      end

      def in_zone?(rr)
        rr.name.downcase == @zone.downcase
      end

      def each_dnskey(observation)
        if observation.is_a?(Message)
          observation.answer.each {|rr|
            yield rr if rr.type == Types::DNSKEY
          }
        else
          observation.each {|rr|
            yield rr if rr.type == Types::DNSKEY
          }
        end
      end
    end
  end
end
