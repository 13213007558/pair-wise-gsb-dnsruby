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

class TestDnameRedirect < Minitest::Test
  include Dnsruby

  def test_rewrites_descendants_but_not_owner
    response = response('a.old.example', dname('old.example', 'new.example'))
    result = DnameRedirect.follow(response)

    assert result.redirect?
    assert_equal 'a.new.example', result.name.to_s
    assert_equal [Types::DNAME, Types::CNAME], result.records.map(&:type)
    assert_equal 'a.old.example', result.records.last.name.to_s
    assert_equal 'a.new.example', result.records.last.domainname.to_s

    response = response('old.example', dname('old.example', 'new.example'))
    result = DnameRedirect.follow(response)
    refute result.redirect?
  end

  def test_uses_nearest_ancestor_with_label_boundaries_and_case_insensitive_comparison
    response = response(
      label_name('A.Deep.Old.example'),
      dname('example', 'elsewhere.example'),
      dname_label('OLD.Example', 'new.example'),
      dname('edge.old.example', 'unreachable.example')
    )

    result = DnameRedirect.follow(response)

    assert result.redirect?
    assert_equal 'A.Deep.new.example', result.name.to_s
  end

  def test_dname_is_retained_when_response_also_contains_synthetic_cname
    response = response(
      'a.old.example',
      dname('old.example', 'new.example'),
      cname('a.old.example', 'a.new.example')
    )

    result = DnameRedirect.follow(response)

    assert result.redirect?
    assert_equal 'a.new.example', result.name.to_s
    assert_equal [Types::DNAME, Types::CNAME], result.records.map(&:type)
  end

  def test_explicit_cname_takes_precedence_when_dname_rewrite_is_too_long
    target = (['x' * 40] * 5).join('.') + '.new.example'
    response = response(
      "#{'a' * 60}.old.example",
      dname('old.example', target),
      cname("#{'a' * 60}.old.example", 'target.example')
    )

    result = DnameRedirect.follow(response)

    assert result.redirect?
    assert_equal 'target.example', result.name.to_s
  end

  def test_interleaved_dname_and_cname_chain
    first = response(
      'a.old.example',
      dname('old.example', 'mid.example')
    )
    middle = response('a.mid.example', cname('a.mid.example', 'b.mid.example'))
    redirected = response('b.mid.example', dname('mid.example', 'next.example'))
    follow = response('b.next.example', cname('b.next.example', 'target.example'))
    terminal = response('target.example', rr('target.example', Types::A, address: '192.0.2.1'))

    queried = []
    result = DnameRedirect.chain(first) do |name, _hops|
      queried << name.to_s
      case name.to_s
      when 'a.mid.example' then middle
      when 'b.mid.example' then redirected
      when 'b.next.example' then follow
      else terminal
      end
    end

    refute result.redirect?
    assert_equal ['a.mid.example', 'b.mid.example', 'b.next.example', 'target.example'], queried
    assert_equal [Types::DNAME, Types::CNAME, Types::CNAME, Types::DNAME, Types::CNAME, Types::CNAME],
                 result.records.map(&:type)
    assert_equal 'target.example', result.response.question[0].qname.to_s
    assert_equal RCode::NOERROR, result.response.rcode
  end

  def test_name_too_long_returns_yxdomain
    target = (['x' * 40] * 5).join('.') + '.new.example'
    response = response("#{'a' * 60}.old.example", dname('old.example', target))

    result = DnameRedirect.follow(response)

    assert_equal :yxdomain, result.status
    assert_equal RCode::YXDOMAIN, result.response.rcode
  end

  def test_loop_returns_servfail
    first = response('a.example', cname('a.example', 'b.example'))
    second = response('b.example', cname('b.example', 'a.example'))

    result = DnameRedirect.chain(first) { second }

    assert_equal :loop, result.status
    assert_equal RCode::SERVFAIL, result.response.rcode
  end

  def test_alias_records_in_error_responses_are_not_followed
    response = response('a.old.example', dname('old.example', 'new.example'))
    response.header.rcode = RCode::SERVFAIL

    result = DnameRedirect.follow(response)

    refute result.redirect?
    assert_equal RCode::SERVFAIL, response.rcode
  end

  def test_hop_limit_returns_servfail
    start = response('n0.example', cname('n0.example', 'n1.example'))

    result = DnameRedirect.chain(start, {}, 0) do |name, hops|
      target = "n#{hops + 1}.example"
      response(name, cname(name, target))
    end

    assert_equal :too_many_redirects, result.status
    assert_equal RCode::SERVFAIL, result.response.rcode
  end

  def test_recursor_accumulates_interleaved_aliases_and_keeps_original_question
    messages = {
      'a.old.example' => response(
        'a.old.example',
        dname('old.example', 'mid.example')
      ),
      'a.mid.example' => response(
        'a.mid.example',
        cname('a.mid.example', 'b.mid.example')
      ),
      'b.mid.example' => response(
        'b.mid.example',
        dname('mid.example', 'next.example')
      ),
      'b.next.example' => response(
        'b.next.example',
        cname('b.next.example', 'target.example')
      ),
      'target.example' => response(
        'target.example',
        rr('target.example', Types::A, address: '192.0.2.1')
      )
    }
    recursor = Dnsruby::Recursor.allocate
    fake_resolver = Object.new
    fake_resolver.define_singleton_method(:dnssec=) { |_value| }
    fake_resolver.define_singleton_method(:recurse=) { |_value| }
    fake_resolver.define_singleton_method(:retry_delay=) { |_value| }
    fake_resolver.define_singleton_method(:single_resolvers) { [] }
    fake_resolver.define_singleton_method(:send_message) do |message|
      messages[message.question[0].qname.to_s].clone
    end
    recursor.instance_variable_set(:@resolver, fake_resolver)
    authorities = { 'root' => Dnsruby::Recursor::AddressCache.new }
    authorities['root'].push(['192.0.2.1', 3600])
    Dnsruby::Recursor.class_variable_set(:@@zones_cache, { '.' => authorities })
    Dnsruby::Recursor.class_variable_set(:@@hints, authorities)

    Dnsruby::Resolver.stub(:new, fake_resolver) do
      result = recursor.send(
        :_dorecursion,
        'a.old.example', Types::A, Classes::IN, '.', authorities, 0, true
      )

      assert_equal 'a.old.example', result.question[0].qname.to_s
      assert_equal(
        [Types::DNAME, Types::CNAME, Types::CNAME, Types::DNAME,
         Types::CNAME, Types::CNAME, Types::A],
        result.answer.map(&:type)
      )
    end
  end

  private

  def response(name, *answers)
    message = Message.new(name, Types::A, Classes::IN)
    answers.each { |record| message.add_answer(record) }
    message
  end

  def dname(name, target)
    rr(name, Types::DNAME, domainname: target)
  end

  def dname_label(name, target)
    rr(label_name(name), Types::DNAME, domainname: target)
  end

  def cname(name, target)
    rr(name, Types::CNAME, domainname: target)
  end

  def rr(name, type, attributes)
    RR.new_from_hash({ name: name, type: type, klass: Classes::IN, ttl: 300 }.merge(attributes))
  end

  def label_name(name)
    Name.new(name.split('.').map { |label| Name::Label.new(label) })
  end
end
