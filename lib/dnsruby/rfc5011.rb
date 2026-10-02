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

  # RFC 5011 - Automated Updates of DNS Security (DNSSEC) Trust Anchors.
  #
  # This class implements the trust anchor state machine described in
  # RFC 5011 section 4.2.  It consumes DNSKEY RRsets that the caller has
  # already authenticated (i.e. validated against the current set of trust
  # anchors) together with the time each RRset was observed, and tracks
  # which keys may currently be used as trust anchors.
  #
  # A newly-seen key is not trusted immediately: it must remain present in
  # every validated RRset for the full add hold-down time (30 days per
  # RFC 5011 section 2.4.1) before it is promoted to a valid trust anchor.
  # If the key disappears before the hold-down expires, its timer is reset.
  # A valid key which disappears moves to the Missing state but continues
  # to be used; it returns to Valid if it reappears.  A key seen with the
  # REVOKE bit set is revoked and must never be used again.
  #
  # The clock is supplied by the caller on every observation, so the state
  # machine can be driven by a test timeline, and the whole state can be
  # serialised with to_h and restored with from_h (e.g. across a process
  # restart in the middle of an add hold-down period).
  #
  # Observations which could not be authenticated MUST be passed with
  # validated: false (or simply not passed at all); they are ignored and
  # never advance any hold-down timer.
  #
  # Example:
  #   tracker = Dnsruby::Rfc5011.new("example.com")
  #   tracker.observe(validated_dnskey_rrset, Time.now)
  #   tracker.trusted_anchors  # => [Dnsruby::RR::DNSKEY, ...]
  #   File.write("anchors.state", tracker.to_h.to_json)
  #   tracker = Dnsruby::Rfc5011.from_h(JSON.parse(File.read("anchors.state")))
  class Rfc5011
    # RFC 5011 section 2.4.1: the add hold-down time is 30 days.
    DEFAULT_ADD_HOLD_DOWN = 30 * 24 * 60 * 60
    # RFC 5011 section 2.4.2 suggests 30 days for the remove hold-down time.
    DEFAULT_REMOVE_HOLD_DOWN = 30 * 24 * 60 * 60

    # A single tracked key and its position in the RFC 5011 state machine.
    class Anchor
      # Key seen, waiting for the add hold-down time to expire.
      ADD_PEND = :add_pend
      # Key held down for the full add hold-down time - usable trust anchor.
      VALID = :valid
      # Was Valid, but absent from the most recent validated RRset.  Still
      # used as a trust anchor (RFC 5011 section 4.2).
      MISSING = :missing
      # Seen with the REVOKE bit set - must never be used again.
      REVOKED = :revoked
      # No longer tracked; a reappearing key is treated as brand new.
      REMOVED = :removed

      STATES = [ADD_PEND, VALID, MISSING, REVOKED, REMOVED]

      # The DNSKEY RR (in its un-revoked form, unless state is REVOKED)
      attr_reader :key
      # One of STATES
      attr_reader :state
      # Time (epoch seconds) the key was first seen in a validated RRset
      attr_reader :first_seen
      # Time (epoch seconds) the current state was entered
      attr_reader :state_since
      # Time (epoch seconds) at which an ADD_PEND key becomes VALID
      attr_reader :add_pend_expires
      # Time (epoch seconds) the key was last present in a validated RRset
      attr_reader :last_seen

      attr_writer :key

      def initialize(key, state, first_seen, state_since, add_pend_expires, last_seen)
        @key = key
        @state = state
        @first_seen = first_seen
        @state_since = state_since
        @add_pend_expires = add_pend_expires
        @last_seen = last_seen
      end

      def transition(new_state, now)
        @state = new_state
        @state_since = now
      end

      def touch(now)
        @last_seen = now
      end

      def to_h
        {
          "key" => Rfc5011.key_to_string(@key),
          "state" => @state.to_s,
          "first_seen" => @first_seen,
          "state_since" => @state_since,
          "add_pend_expires" => @add_pend_expires,
          "last_seen" => @last_seen
        }
      end

      def self.from_h(hash)
        state = hash["state"].to_sym
        unless STATES.include?(state)
          raise ArgumentError.new("Unknown RFC 5011 anchor state: #{hash['state']}")
        end
        Anchor.new(
          Dnsruby::RR.create(hash["key"]),
          state,
          hash["first_seen"],
          hash["state_since"],
          hash["add_pend_expires"],
          hash["last_seen"]
        )
      end
    end

    # The zone (trust point) this tracker manages, as a Dnsruby::Name
    attr_reader :zone
    # Add hold-down time in seconds (default 30 days, RFC 5011 section 2.4.1)
    attr_reader :add_hold_down
    # Remove hold-down time in seconds (RFC 5011 section 2.4.2)
    attr_reader :remove_hold_down

    def initialize(zone, add_hold_down: DEFAULT_ADD_HOLD_DOWN,
                   remove_hold_down: DEFAULT_REMOVE_HOLD_DOWN)
      @zone = Name.create(zone)
      @add_hold_down = add_hold_down
      @remove_hold_down = remove_hold_down
      @anchors = {} # key id => Anchor
    end

    # Record an observation of the zone's DNSKEY RRset at time +now+
    # (a Time or epoch seconds).
    #
    # Only pass validated: true when the RRset has been authenticated
    # against the current trust anchors.  Unauthenticated observations
    # (validated: false) are ignored entirely - they never create
    # candidates and never advance any hold-down timer.
    #
    # Returns self so calls can be chained.
    def observe(rrset, now, validated: true)
      return self unless validated
      now = to_epoch(now)

      seen = {}
      each_dnskey(rrset) do |rr|
        seen[key_id(rr)] = rr
      end

      # Process revocations first so they win if an RRset were to contain
      # both forms of a key.
      seen.values.sort_by { |rr| rr.revoked? ? 0 : 1 }.each do |rr|
        id = key_id(rr)
        anchor = @anchors[id]
        if rr.revoked?
          revoke(id, rr, now)
        elsif anchor.nil? || anchor.state == Anchor::REMOVED
          # A brand new key (or one which had been completely removed)
          # enters AddPend with a fresh hold-down timer.
          anchor = Anchor.new(rr, Anchor::ADD_PEND, now, now,
                              now + @add_hold_down, now)
          @anchors[id] = anchor
          maybe_promote(anchor, now)
        else
          case anchor.state
          when Anchor::REVOKED
            # RFC 5011 section 4.2: a revoked key MUST NOT be re-added.
          when Anchor::MISSING
            anchor.key = rr
            anchor.transition(Anchor::VALID, now)
            anchor.touch(now)
          when Anchor::ADD_PEND
            anchor.touch(now)
            maybe_promote(anchor, now)
          when Anchor::VALID
            anchor.touch(now)
          end
        end
      end

      # Keys absent from this validated RRset.
      @anchors.each do |id, anchor|
        next if seen.key?(id)
        case anchor.state
        when Anchor::ADD_PEND
          # RFC 5011 section 4.2: AddPend + not seen -> Start.  The key is
          # dropped and its hold-down timer discarded; if it reappears it
          # must start the full hold-down period again.
          @anchors.delete(id)
        when Anchor::VALID
          anchor.transition(Anchor::MISSING, now)
        when Anchor::MISSING, Anchor::REVOKED
          if now - anchor.state_since >= @remove_hold_down
            anchor.transition(Anchor::REMOVED, now)
          end
        end
      end
      self
    end

    # All currently tracked anchors (Dnsruby::Rfc5011::Anchor objects).
    def anchors
      @anchors.values
    end

    # The DNSKEY RRs which may currently be used as trust anchors:
    # keys in the Valid or Missing states (RFC 5011 section 4.2).
    def trusted_anchors
      @anchors.values.select { |a|
        a.state == Anchor::VALID || a.state == Anchor::MISSING
      }.map(&:key)
    end

    # Keys currently in the AddPend state - seen, but not yet held down
    # long enough to be trusted.
    def candidates
      @anchors.values.select { |a| a.state == Anchor::ADD_PEND }
    end

    # Is this DNSKEY RR currently usable as a trust anchor?
    def trusted?(rr)
      anchor = @anchors[key_id(rr)]
      !anchor.nil? &&
        (anchor.state == Anchor::VALID || anchor.state == Anchor::MISSING)
    end

    # Serialise the complete state to a plain hash (safe for JSON/Marshal),
    # so it can be persisted and restored across a process restart.
    def to_h
      {
        "zone" => @zone.to_s,
        "add_hold_down" => @add_hold_down,
        "remove_hold_down" => @remove_hold_down,
        "anchors" => @anchors.values.map(&:to_h)
      }
    end

    # Restore a tracker previously serialised with to_h.  Hold-down timers
    # are absolute times, so a restart in the middle of an add hold-down
    # period simply continues where it left off.
    def self.from_h(hash)
      tracker = new(hash["zone"],
                    add_hold_down: hash["add_hold_down"],
                    remove_hold_down: hash["remove_hold_down"])
      hash["anchors"].each do |anchor_hash|
        anchor = Anchor.from_h(anchor_hash)
        tracker.instance_variable_get(:@anchors)[tracker.send(:key_id, anchor.key)] = anchor
      end
      tracker
    end

    # Presentation-format string for a DNSKEY RR, used for serialisation.
    def self.key_to_string(rr)
      "#{rr.name.to_s} #{rr.ttl} IN DNSKEY #{rr.flags} #{rr.protocol} " +
        "#{rr.algorithm.code} #{[rr.key].pack('m0')}"
    end

    private

    def to_epoch(time)
      time.respond_to?(:to_i) ? time.to_i : time
    end

    def each_dnskey(rrset)
      rrs = if rrset.is_a?(Array)
              rrset
            elsif rrset.respond_to?(:rrs)
              rrset.rrs
            else
              [rrset]
            end
      rrs.each do |rr|
        next unless rr.type == Types::DNSKEY
        next unless Name.create(rr.name).to_s.downcase == @zone.to_s.downcase
        yield rr
      end
    end

    # Identity of a key, per RFC 5011 section 3: owner name plus RDATA.
    # The REVOKE bit is masked out so that a revoked key matches its
    # un-revoked form.
    def key_id(rr)
      [Name.create(rr.name).to_s.downcase,
       rr.flags & ~RR::DNSKEY::REVOKED_KEY,
       rr.protocol,
       rr.algorithm.code,
       rr.key]
    end

    def revoke(id, rr, now)
      anchor = @anchors[id]
      if anchor.nil?
        # A revoked key we have never seen is recorded so that it can
        # never be added as a trust anchor, but is of course not trusted.
        @anchors[id] = Anchor.new(rr, Anchor::REVOKED, now, now, nil, now)
      elsif anchor.state != Anchor::REVOKED && anchor.state != Anchor::REMOVED
        anchor.key = rr
        anchor.transition(Anchor::REVOKED, now)
        anchor.touch(now)
      end
    end

    def maybe_promote(anchor, now)
      if anchor.state == Anchor::ADD_PEND &&
         !anchor.add_pend_expires.nil? && now >= anchor.add_pend_expires
        anchor.transition(Anchor::VALID, now)
      end
    end
  end
end

