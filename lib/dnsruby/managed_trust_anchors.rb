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
require 'digest/sha2'
require 'tempfile'
require 'fileutils'

module Dnsruby
  class ManagedTrustAnchorError < StandardError
  end

  # Maintains RFC 5011 state for one trust point. The manager is a pure state
  # machine: callers supply already validated DNSKEY observations and the time
  # at which they were made. It does not query the DNS.
  class ManagedTrustAnchorManager
    DEFAULT_HOLD_DOWN_TIME = 30 * 24 * 60 * 60
    DEFAULT_REMOVAL_HOLD_DOWN_TIME = 30 * 24 * 60 * 60
    FORMAT_VERSION = 1

    attr_reader :zone_name, :hold_down_time, :removal_hold_down_time

    # Initial trust anchors are immediately valid. State can optionally be
    # restored from a path or from a serialized Hash/String.
    def initialize(zone_name, trust_anchors = nil, state_path: nil, state: nil,
                   hold_down_time: DEFAULT_HOLD_DOWN_TIME,
                   removal_hold_down_time: DEFAULT_REMOVAL_HOLD_DOWN_TIME)
      @zone_name = zone_name.nil? ? nil : normalize_name(zone_name)
      @hold_down_time = Integer(hold_down_time)
      @removal_hold_down_time = Integer(removal_hold_down_time)
      @state_path = state_path
      @keys = {}

      if state
        load_state(state)
      elsif state_path && File.file?(state_path)
        load_state(state_path)
      else
        anchors = initial_trust_anchors(trust_anchors)
        anchors.each { |key| add_initial_trust_anchor(key) }
      end

      raise ManagedTrustAnchorError, "A zone name is required" if @zone_name.nil?

      raise ArgumentError, "hold_down_time must be non-negative" if @hold_down_time < 0
      raise ArgumentError, "removal_hold_down_time must be non-negative" if @removal_hold_down_time < 0
    end

    # Update the state from one validated DNSKEY RRSet, Array, or single DNSKEY.
    def process_observation(dnskeys, now = Time.now)
      now = timestamp(now)
      observations = normalize_observation(dnskeys)
      observed_ids = {}
      @keys.each_value { |entry| entry["present"] = false }
      expire_revoked_keys(now)

      observations.each do |key|
        id = key_identifier(key)
        observed_ids[id] = key

        if key.revoked?
          process_revoked_observation(id, key, now)
        else
          process_active_observation(id, key, now)
        end
      end

      expire_missing_keys(now, observed_ids)

      @keys.each_value do |entry|
        entry["present"] = observed_ids.key?(entry["id"])
        entry["last_seen"] = now if entry["present"]
      end

      save if @state_path
      trust_anchors
    end
    alias_method :observe, :process_observation
    alias_method :process, :process_observation

    # DNSKEY RRs that can currently validate the trust point. Valid keys are
    # retained across short or long unrevoked disappearances, as required by
    # RFC 5011's rollback protection.
    def trust_anchors
      entries_with_status(:valid).map { |entry| materialize(entry) }
    end

    def candidates
      entries_with_status(:candidate).map { |entry| materialize(entry) }
    end

    def revoked_keys
      entries_with_status(:revoked).map { |entry| materialize(entry) }
    end

    def key_status(key)
      entry = find_entry(key)
      entry ? entry["status"].to_sym : nil
    end
    alias_method :status, :key_status

    def key_state(key)
      entry = key.is_a?(Hash) ? entry_from_state_hash(key) : find_entry(key)
      return nil unless entry

      {
        status: entry["status"].to_sym,
        present: entry["present"],
        key_tag: entry["key_tag"],
        pre_revoked_key_tag: entry["pre_revoked_key_tag"],
        first_seen: entry["first_seen"],
        last_seen: entry["last_seen"],
        became_valid_at: entry["became_valid_at"],
        revoked_at: entry["revoked_at"],
        missing_since: entry["missing_since"]
      }
    end

    def states
      @keys.values.map { |entry| key_state(entry) }
    end

    def to_h
      {
        "format_version" => FORMAT_VERSION,
        "zone_name" => @zone_name.to_s,
        "hold_down_time" => @hold_down_time,
        "removal_hold_down_time" => @removal_hold_down_time,
        "keys" => @keys.values
      }
    end

    def save(path = @state_path)
      raise ManagedTrustAnchorError, "No state path configured" unless path
      @state_path = path
      FileUtils.mkdir_p(File.dirname(File.expand_path(path)))
      Tempfile.create(File.basename(path), File.dirname(File.expand_path(path))) do |file|
        file.write(JSON.pretty_generate(to_h))
        file.flush
        file.chmod(0600)
        File.rename(file.path, File.expand_path(path))
      end
    end

    def self.load(path)
      new(nil, nil, state_path: path)
    end

    def self.load_state(path)
      load(path)
    end

    private

    def add_initial_trust_anchor(key)
      normalized = normalize_key(key)
      id = key_identifier(normalized)
      now = Time.now.to_i
      @keys[id] ||= {
        "id" => id,
        "rr" => rr_text(normalized),
        "status" => "valid",
        "present" => false,
        "key_tag" => normalized.key_tag,
        "pre_revoked_key_tag" => normalized.key_tag_pre_revoked,
        "first_seen" => now,
        "last_seen" => nil,
        "became_valid_at" => now,
        "revoked_at" => nil,
        "missing_since" => nil
      }
    end

    def process_active_observation(id, key, now)
      entry = @keys[id]

      if entry.nil?
        @keys[id] = {
          "id" => id,
          "rr" => rr_text(key),
          "status" => "candidate",
          "present" => true,
          "key_tag" => key.key_tag,
          "pre_revoked_key_tag" => key.key_tag_pre_revoked,
          "first_seen" => now,
          "last_seen" => now,
          "became_valid_at" => nil,
          "revoked_at" => nil,
          "missing_since" => nil
        }
        return
      end

      if entry["status"] == "candidate" && now - entry["first_seen"] >= @hold_down_time
        entry["status"] = "valid"
        entry["became_valid_at"] = now
      end

      if entry["status"] == "revoked"
        entry["status"] = "candidate"
        entry["revoked_at"] = nil
        entry["missing_since"] = nil
        entry["first_seen"] = now
        entry["became_valid_at"] = nil
      end

      return unless entry["status"] == "valid"

      entry["rr"] = rr_text(key)
      entry["key_tag"] = key.key_tag
      entry["pre_revoked_key_tag"] = key.key_tag_pre_revoked
      entry["missing_since"] = nil
    end

    def process_revoked_observation(id, key, now)
      entry = @keys[id]
      if entry.nil? || entry["status"] == "candidate"
        @keys.delete(id)
        return
      end

      entry["status"] = "revoked"
      entry["rr"] = rr_text(key)
      entry["key_tag"] = key.key_tag
      entry["pre_revoked_key_tag"] = key.key_tag_pre_revoked
      entry["revoked_at"] ||= now
      entry["missing_since"] = nil
    end

    def expire_missing_keys(now, observed_ids)
      @keys.delete_if do |_id, entry|
        if observed_ids.key?(entry["id"])
          entry["missing_since"] = nil
          next false
        end

        entry["missing_since"] ||= now

        if entry["status"] == "revoked"
          now - entry["revoked_at"].to_i >= @removal_hold_down_time
        else
          if entry["status"] == "candidate"
            entry["first_seen"] = now
            entry["became_valid_at"] = nil
          end
          false
        end
      end
    end

    def expire_revoked_keys(now)
      @keys.delete_if do |_id, entry|
        entry["status"] == "revoked" &&
          now - entry["revoked_at"].to_i >= @removal_hold_down_time
      end
    end

    def entries_with_status(status)
      @keys.values.select { |entry| entry["status"] == status.to_s }
    end

    def find_entry(key)
      @keys[key_identifier(normalize_key(key))]
    end

    def entry_from_state_hash(hash)
      id = hash[:id] || hash["id"]
      @keys[id]
    end

    def materialize(entry)
      RR.create(entry["rr"])
    end

    def load_state(source)
      data =
        if source.is_a?(String) && File.file?(source)
          JSON.parse(File.read(source))
        elsif source.is_a?(String)
          JSON.parse(source)
        else
          source
        end

      data = symbolize_loaded_hash(data)
      format_version = Integer(data.fetch(:format_version, FORMAT_VERSION))
      unless format_version == FORMAT_VERSION
        raise ManagedTrustAnchorError,
              "Unsupported managed trust anchor state version #{format_version}"
      end
      @zone_name ||= normalize_name(data[:zone_name])
      @hold_down_time = Integer(data.fetch(:hold_down_time, @hold_down_time))
      @removal_hold_down_time = Integer(data.fetch(:removal_hold_down_time, @removal_hold_down_time))
      @keys = {}

      Array(data[:keys]).each do |entry|
        normalized = normalize_loaded_entry(entry)
        @keys[normalized["id"]] = normalized
      end
    end

    def normalize_loaded_entry(entry)
      source = symbolize_loaded_hash(entry)
      key =
        if source[:rr].is_a?(RR::DNSKEY)
          source[:rr]
        else
          RR.create(source[:rr])
        end
      key = normalize_key(key)
      id = source[:id] || key_identifier(key)
      status = source[:status].to_s
      unless %w(candidate valid revoked).include?(status)
        raise ManagedTrustAnchorError, "Invalid managed key status: #{status}"
      end

      {
        "id" => id,
        "rr" => rr_text(key),
        "status" => status,
        "present" => false,
        "key_tag" => Integer(source[:key_tag] || key.key_tag),
        "pre_revoked_key_tag" => Integer(source[:pre_revoked_key_tag] || key.key_tag_pre_revoked),
        "first_seen" => timestamp(source[:first_seen]),
        "last_seen" => timestamp(source[:last_seen], false),
        "became_valid_at" => timestamp(source[:became_valid_at], false),
        "revoked_at" => timestamp(source[:revoked_at], false),
        "missing_since" => timestamp(source[:missing_since], false)
      }
    end

    def symbolize_loaded_hash(value)
      return value unless value.is_a?(Hash)
      value.each_with_object({}) do |(key, item), result|
        result[key.to_sym] = item
      end
    end

    def initial_trust_anchors(keys)
      return [] if keys.nil?
      return keys.rrs if keys.is_a?(RRSet)
      return keys if keys.is_a?(Array)
      [keys]
    end

    def normalize_observation(keys)
      values =
        if keys.is_a?(RRSet)
          keys.rrs
        elsif keys.is_a?(Array)
          keys
        else
          [keys]
        end

      values.map { |key| normalize_key(key) }
        .select { |key| key.sep_key? }
        .uniq { |key| key_identifier(key) }
    end

    def normalize_key(key)
      unless key.is_a?(RR::IN::DNSKEY) || (key.is_a?(RR::DNSKEY) && key.type == Types::DNSKEY)
        raise ArgumentError, "Expected a DNSKEY observation, got #{key.class}"
      end
      unless key.name.canonical == @zone_name.canonical
        raise ArgumentError, "DNSKEY owner #{key.name} does not match managed zone #{@zone_name}"
      end
      key.clone
    end

    def normalize_name(name)
      raise ArgumentError, "A zone name is required" if name.nil? || name.to_s.empty?
      Name.create(name)
    end

    def rr_text(key)
      key.clone.to_s
    end

    def key_identifier(key)
      wire = key.name.canonical
      wire << [0, key.protocol, key.algorithm.code].pack('nCC')
      wire << key.key.b
      Base64.urlsafe_encode64(Digest::SHA256.digest(wire))
    end

    def timestamp(value, required = true)
      return nil if value.nil? && !required
      if value.respond_to?(:to_i) && !value.is_a?(String)
        value.to_i
      else
        Integer(value)
      end
    end
  end

  TrustAnchorManager = ManagedTrustAnchorManager
  ManagedTrustAnchors = ManagedTrustAnchorManager
end
