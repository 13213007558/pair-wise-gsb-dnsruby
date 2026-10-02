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
  class DnameRedirect
    MAX_REDIRECTS = 16

    Result = Struct.new(:status, :name, :records, :response, keyword_init: true) do
      def redirect?
        status == :redirect
      end
    end

    def self.follow(message, query_name = question_name(message))
      new.follow(message, query_name)
    end

    def self.chain(message, seen = {}, hops = 0, &query)
      new.chain(message, seen, hops, &query)
    end

    def self.question_name(message)
      question = message.question[0]
      raise ResolvError.new('DNAME response has no question') unless question
      question.qname
    end

    def follow(message, query_name = self.class.question_name(message))
      query_name = as_name(query_name)
      question = message.question[0]
      klass = question ? question.qclass : Classes::IN
      rcode = message.rcode
      qtype = question ? question.qtype : Types::A

      return result(:terminal) unless rcode == RCode::NOERROR || rcode == RCode::NXDOMAIN
      return result(:terminal) if qtype == Types::CNAME || qtype == Types::DNAME

      dname = nearest_dname(message, query_name, klass)
      cname = exact_cname(message, query_name, klass)

      return result(:terminal) if dname.nil? && cname.nil?
      return result(:redirect, cname.domainname, [cname]) if dname.nil?

      records = [dname]
      if cname
        records << cname
        return result(:redirect, cname.domainname, records)
      end

      target_name = rewrite_name(query_name, dname.name, dname.domainname)
      if target_name.nil?
        response = message.clone
        response.header.rcode = RCode::YXDOMAIN
        return result(:yxdomain, nil, [dname], response)
      end

      records << synthetic_cname(dname, query_name, target_name)
      result(:redirect, target_name, records)
    end

    def chain(message, seen = {}, hops = 0, &query)
      query_name = self.class.question_name(message)
      seen = seen.transform_keys { |name| as_name(name).to_s.downcase }
      seen[query_name.to_s.downcase] = true
      records = []

      loop do
        result = follow(message, query_name)
        unless result.redirect?
          result.records = records + result.records
          result.response = message if result.response.nil?
          return result
        end

        records.concat(result.records)
        target_key = result.name.to_s.downcase
        return failure(message, result.name, :loop, records) if seen.key?(target_key)
        return failure(message, result.name, :too_many_redirects, records) if hops >= MAX_REDIRECTS

        seen[target_key] = true
        hops += 1
        message = query.call(result.name, hops)
        query_name = result.name
      end
    end

    private

    def result(status, name = nil, records = [], response = nil)
      Result.new(status: status, name: name, records: records, response: response)
    end

    def failure(message, name, status, records = [])
      response = message.clone
      response.header.rcode = RCode::SERVFAIL
      result(status, name, records, response)
    end

    def exact_cname(message, query_name, klass)
      message.answer.detect do |rr|
        rr.type == Types::CNAME && rr.klass == klass && same_name?(rr.name, query_name)
      end
    end

    def nearest_dname(message, query_name, klass)
      message.answer.select do |rr|
        rr.type == Types::DNAME &&
          rr.klass == klass &&
          descendant_of?(query_name, rr.name)
      end.min_by { |dname| -dname.name.length }
    end

    def descendant_of?(name, ancestor)
      name = as_name(name)
      ancestor = as_name(ancestor)
      name.absolute = true
      ancestor.absolute = true
      name.subdomain_of?(ancestor)
    end

    def rewrite_name(query_name, owner_name, target_name)
      prefix_labels = query_name.labels.first(query_name.length - owner_name.length)
      Name.new(prefix_labels + target_name.labels, true)
    rescue ResolvError
      nil
    end

    def synthetic_cname(dname, query_name, target_name)
      RR.new_from_hash(
        name: query_name,
        type: Types::CNAME,
        klass: dname.klass,
        ttl: dname.ttl,
        domainname: target_name
      )
    end

    def as_name(name)
      Name === name ? name : Name.create(name)
    end

    def same_name?(left, right)
      left = as_name(left)
      right = as_name(right)
      left.absolute = true
      right.absolute = true
      left == right
    end
  end
end
