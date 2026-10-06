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


# # This class implements a cache.
# It stores data under qname-qclass-qtype tuples.
# Each tuple indexes a CacheData object (which
# stores a Message, and an expiration).
# If a new Message is stored to a tuple, it will
# overwrite the previous Message.
# When a Message is retrieved from the cache, the header
# and ttls will be "fixed" - i.e. AA cleared, etc.



# @TODO@ Max size for cache?
module Dnsruby
  class Cache # :nodoc: all
    def initialize(time_provider = nil)
    @cache = Hash.new
    @keys = []
    @now = time_provider || -> { Time.now }
    @@max_size = 16*1024 # Get this right...
    @mutex = Mutex.new
    end
    def cache
      @cache
    end
    def clear()
      @mutex.synchronize {
        @cache = Hash.new
        @keys = []
      }
    end
    def length
      return @cache.length
    end
    def Cache.max_size=(length)
       @@max_size = length
    end
    def add(message, query = message)
      q = message.question[0]
      request_q = query.question[0]
      response_subnet = message.get_opt&.client_subnet
      request_subnet = query.get_opt&.client_subnet

      if request_subnet
        return false unless response_subnet&.valid_response_to?(request_subnet)
        subnet_key = response_subnet.scope_key
      else
        return false if response_subnet
        subnet_key = nil
      end

      key = [CacheKey.new(request_q.qname, request_q.qtype, request_q.qclass).to_s, subnet_key]
      data = CacheData.new(message, @now)
      @mutex.synchronize {
        if (@cache[key])
          TheLog.debug("CACHE REPLACE : #{q.qname}, #{q.qtype}\n")
          @keys.delete(key)
        else
          TheLog.debug("CACHE ADD : #{q.qname}, #{q.qtype}\n")
        end
        @cache[key] = data
        @keys << key

        while @cache.size > @@max_size # keep the cache size reasonable
          deleted_key = @keys.shift
          @cache.delete(deleted_key)
        end
      }
      true
    end
    #  This method "fixes up" the response, so that the header and ttls are OK
    #  The resolver will still need to copy the flags and ID across from the query
    def find(qname, qtype, qclass = Classes.IN)
      qn = Name.create(qname)
      qn.absolute = true
      key = [CacheKey.new(qn, qtype, qclass).to_s, nil]
      @mutex.synchronize { get_cached(key) }
    end

    def find_for_message(query)
      question = query.question[0]
      qname = Name.create(question.qname)
      qname.absolute = true
      base_key = CacheKey.new(qname, question.qtype, question.qclass).to_s
      subnet = query.get_opt&.client_subnet

      @mutex.synchronize do
        return get_cached([base_key, nil]) unless subnet

        matching = @keys.select do |item|
          key, subnet_key = item
          next false unless key == base_key && subnet_key
          family, prefix, network_bytes = subnet_key
          next false unless family == subnet.family && prefix <= subnet.source_prefix
          query_bytes = subnet.address.hton
          prefix.times.all? do |bit|
            byte_index = bit / 8
            bit_mask = 0x80 >> (bit % 8)
            (query_bytes.getbyte(byte_index) & bit_mask) ==
              (network_bytes.getbyte(byte_index) & bit_mask)
          end
        end

        matching.sort_by! { |_key, subnet_key| subnet_key[1] }
        matching.reverse_each do |key|
          message = get_cached(key)
          return message if message
        end
        nil
      end
    end
    def Cache.delete(qname, qtype, qclass = Classes.IN)
      key = [CacheKey.new(qname, qtype, qclass).to_s, nil]
      @mutex.synchronize {
        @cache.delete(key)
        @keys.delete(key)
      }
    end

    private

    def get_cached(key)
      data = @cache[key]
      unless data
        return nil
      end
      if data.expiration <= @now.call.to_i
        @cache.delete(key)
        @keys.delete(key)
        TheLog.debug("CACHE lookup stale\n")
        return nil
      end
      message = data.message
      TheLog.debug("CACHE found\n")
      message
    end
    class CacheKey # :nodoc: all
      attr_accessor :qname, :qtype, :qclass
      def initialize(*args)
        self.qclass = Classes.IN
        if (args.length > 0)
          self.qname = Name.create(args[0])
          self.qname.absolute = true
          if (args.length > 1)
            self.qtype = Types.new(args[1])
            if (args.length > 2)
              self.qclass = Classes.new(args[2])
            end
          end
        end
      end
      def to_s
        return "#{qname.inspect.downcase} #{qclass} #{qtype}"
      end
    end
    class CacheData # :nodoc: all
      attr_reader :expiration
      def message=(m)
        @expiration = get_expiration(m)
        @message = Message.decode(m.encode(true))
        @message.cached = true
      end
      def message
        m = Message.decode(@message.encode)
        m.cached = true
        #  @TODO@ What do we do about answerfrom, answersize, etc.?
        m.header.aa = false # Anything else to do here?
        #  Fix up TTLs!!
        offset = (@now.call.to_i - @time_stored)
        m.each_resource {|rr|
          next if rr.type == Types::OPT
          rr.ttl = rr.ttl - offset
        }
        return m
      end
      def get_expiration(m)
        #  Find the minimum ttl of any of the rrsets
        min_ttl = 9999999
        m.each_section {|section|
          section.rrsets.each {|rrset|
            if (rrset.ttl < min_ttl)
              min_ttl = rrset.ttl
            end
          }
        }
        if (min_ttl == 9999999)
          return 0
        end
        return (@now.call.to_i + min_ttl)
      end
      def initialize(message, time_provider = nil)
        @now = time_provider || -> { Time.now }
        @expiration = 0
        @time_stored = @now.call.to_i
        self.message=(message)
      end
      def to_s
        return "#{self.message}"
      end
    end
  end
end
