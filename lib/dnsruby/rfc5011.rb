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
require 'base64'
require 'json'

module Dnsruby
  # Implementation of the automated trust anchor update mechanism described
  # in RFC 5011.
  #
  # The caller is responsible for validating DNSKEY RRsets (for example with
  # Dnsruby::Dnssec) and for supplying the observation clock.  Only
  # observations of authenticated, validated RRsets advance the hold-down
  # timers; unauthenticated observations are ignored entirely.
  #
  # A key is identified by its owner name, algorithm and public key blob;
  # the REVOKE flag does not form part of the identity, so a revoked key is
  # recognised as the same key as its non-revoked form.
  #
  # State may be exported with #to_h (JSON-safe), saved to disk, and restored
  # later with TrustAnchorManager.from_h.  Hold-down timestamps are stored as
  # absolute times, so a restart in the middle of a waiting period does not
  # restart the timer.
  module RFC5011
    # Minimum length of all hold-down timers (RFC 5011 section 2.3): the
    # add hold-down, removal hold-down and revocation hold-down are each
    # 30 days.
    HOLD_DOWN = 30 * 24 * 60 * 60

    # Key has been seen but has not yet completed the add hold-down period.
    ADD_PENDING = :add_pending
    # Key is a current trust anchor.
    VALID = :valid
    # A valid key which is temporarily absent from authenticated RRsets.
    MISSING = :missing
    # A valid key which has been seen with the REVOKE flag set.
    REVOKED = :revoked

    # Per-key state record.
    class KeyState
      # One of the RFC5011 state symbols.
      attr_accessor :state
      # The most recently observed DNSKEY RR for this key.
      attr_accessor :key
      # Absolute time (seconds since the epoch) at which the current
      # hold-down timer started.  Meaning depends on the state:
      # ADD_PENDING: add hold-down, MISSING: removal hold-down,
      # REVOKED: revocation hold-down.
      attr_accessor :hold_down_start

      def initialize(state, key, hold_down_start = nil)
        @state = state
        @key = key
        @hold_down_start = hold_down_start
      end
    end

    # Drives the RFC 5011 trust anchor state machine for one zone.
    class TrustAnchorManager
      # Current DNSKEY RR for every tracked key, keyed by key identity.
      attr_reader :keys

      # Build a new manager.
      #
      # +anchors+ may be a single Dnsruby::RR::DNSKEY, an RRSet or an Array
      # of DNSKEY RRs.  Configured anchors start life in the VALID state, as
      # they have been distributed through a secure channel.
      #
      # +hold_down+ is the length in seconds of the hold-down timers and
      # defaults to the RFC-mandated 30 days.  It may be shortened for
      # testing.
      def initialize(anchors = nil, hold_down: HOLD_DOWN)
        @keys = {}
        @hold_down = hold_down
        add_anchors(anchors)
      end

      # Add one or more pre-configured trust anchors directly in the VALID
      # state.  Does not start any hold-down timer.
      def add_anchors(anchors)
        each_dnskey(anchors) do |key|
          record = KeyState.new(VALID, key.clone)
          @keys[identity(key)] = record
        end
        self
      end

      # Process an observation of the zone's DNSKEY RRset at +time+.
      #
      # +rrset+ may be an RRSet, an Array of DNSKEY RRs or a single RR.
      # +time+ may be a Time or an Integer number of seconds since the
      # epoch, and is supplied by the caller.
      #
      # Pass +authenticated: false+ for an observation which could not be
      # cryptographically validated; such an observation does not change any
      # state and, crucially, does not advance any hold-down timer.
      def process(rrset, time, authenticated: true)
        return self unless authenticated

        now = to_epoch(time)
        observed = {}
        each_dnskey(rrset) do |key|
          # RFC 5011 only manages Secure Entry Point keys.
          next unless key.sep_key?
          observed[identity(key)] = key
        end

        @keys.to_a.each do |id, record|
          observed_key = observed[id]
          process_known_key(id, record, observed_key, now)
        end

        observed.each do |id, key|
          next if @keys.key?(id)
          # A brand-new revoked key is ignored (RFC 5011 section 3.2,
          # START state).
          next if key.revoked?
          @keys[id] = KeyState.new(ADD_PENDING, key.clone, now)
        end

        self
      end
      alias observe process

      # The DNSKEY RRs which may currently be used as trust anchors:
      # VALID keys and MISSING keys, which remain trusted throughout the
      # removal hold-down period.
      def trust_anchors
        records_in(VALID, MISSING).map { |record| record.key.clone }
      end

      # DNSKEY RRs which are candidates awaiting the add hold-down period.
      def candidates
        records_in(ADD_PENDING).map { |record| record.key.clone }
      end

      # Current state symbol for a DNSKEY RR (or a pre-computed identity
      # Array).  Returns nil if the key is not being tracked.
      def state_of(key)
        id = key.is_a?(Array) ? key : identity(key)
        record = @keys[id]
        record ? record.state : nil
      end

      # Hold-down start time for a key, or nil.
      def hold_down_start_of(key)
        id = key.is_a?(Array) ? key : identity(key)
        record = @keys[id]
        record ? record.hold_down_start : nil
      end

      # JSON-safe representation of the state, suitable for saving to disk.
      def to_h
        {
          'version' => 1,
          'hold_down' => @hold_down,
          'keys' => @keys.map do |id, record|
            key = record.key
            {
              'name' => key.name.to_s,
              'ttl' => key.ttl,
              'flags' => key.flags,
              'algorithm' => key.algorithm.code,
              'key' => [key.key].pack('m0'),
              'state' => record.state.to_s,
              'hold_down_start' => record.hold_down_start
            }
          end
        }
      end

      # Restore state previously produced by #to_h.
      def self.from_h(hash)
        data = hash.is_a?(String) ? JSON.parse(hash) : hash
        manager = new(nil, hold_down: data.fetch('hold_down', HOLD_DOWN))
        manager.instance_variable_get(:@keys).clear
        data.fetch('keys', []).each do |entry|
          key = RR.create(
            "#{entry['name']} #{entry['ttl']} IN DNSKEY " \
            "#{entry['flags']} 3 #{entry['algorithm']} #{entry['key']}"
          )
          record = KeyState.new(entry['state'].to_sym, key, entry['hold_down_start'])
          manager.instance_variable_get(:@keys)[identity(key)] = record
        end
        manager
      end

      # Identity of a DNSKEY: owner name, algorithm and public key blob.
      # The flags (including REVOKE) are deliberately excluded.
      def self.identity(key)
        [key.name.to_s.downcase, key.algorithm.code, key.key]
      end

      def identity(key) # :nodoc:
        self.class.identity(key)
      end

      private

      # Apply the RFC 5011 section 3.2 transition table to one tracked key.
      def process_known_key(id, record, observed_key, now)
        case record.state
        when ADD_PENDING
          if observed_key.nil? || observed_key.revoked?
            # Absent from an authenticated RRset, or seen revoked, before
            # the hold-down completed: back to START.
            @keys.delete(id)
          elsif now - record.hold_down_start >= @hold_down
            record.state = VALID
            record.hold_down_start = nil
            record.key = observed_key.clone
          else
            record.key = observed_key.clone
          end
        when VALID
          if observed_key.nil?
            record.state = MISSING
            record.hold_down_start = now
          elsif observed_key.revoked?
            record.state = REVOKED
            record.hold_down_start = now
            record.key = observed_key.clone
          else
            record.key = observed_key.clone
          end
        when MISSING
          if observed_key.nil?
            if now - record.hold_down_start >= @hold_down
              # Removal hold-down expired while absent: to START.
              @keys.delete(id)
            end
          elsif observed_key.revoked?
            record.state = REVOKED
            record.hold_down_start = now
            record.key = observed_key.clone
          else
            # Reappeared before the removal hold-down expired: still trusted.
            record.state = VALID
            record.hold_down_start = nil
            record.key = observed_key.clone
          end
        when REVOKED
          if observed_key && observed_key.revoked?
            record.key = observed_key.clone
          end
          # A revoked key - whether present, absent or seen again without
          # the REVOKE flag - stays REVOKED until the revocation hold-down
          # started when the REVOKE flag was first observed has expired.
          if now - record.hold_down_start >= @hold_down
            @keys.delete(id)
          end
        end
      end

      def records_in(*states)
        @keys.values.select { |record| states.include?(record.state) }
      end

      def each_dnskey(thing)
        return if thing.nil?
        if thing.is_a?(RRSet)
          thing.rrs.each { |rr| yield rr if rr.type == Types::DNSKEY }
        elsif thing.is_a?(Array)
          thing.each { |rr| yield rr if rr.type == Types::DNSKEY }
        elsif thing.type == Types::DNSKEY
          yield thing
        end
      end

      def to_epoch(time)
        time.respond_to?(:to_i) ? time.to_i : time
      end
    end
  end
end
