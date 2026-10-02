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

class TestDname < Minitest::Test

  include Dnsruby

  def setup
    Dnsruby::Config.reset
    @dns = Dnsruby::DNS.new({:nameserver => ['127.0.0.1']})
  end

  def teardown
    @dns.close
  end

  def canned_message(qname, answers)
    msg = Message.new
    msg.add_question(Question.new(qname, Types.A, Classes.IN))
    answers.each {|rr| msg.add_answer(rr)}
    msg
  end

  def dname(owner, target, ttl=300)
    RR.new_from_hash({:name => owner, :type => Types.DNAME, :ttl => ttl, :domainname => target})
  end

  def cname(owner, target)
    RR.new_from_hash({:name => owner, :type => Types.CNAME, :ttl => 300, :domainname => target})
  end

  def a_record(owner, address)
    RR.new_from_hash({:name => owner, :type => Types.A, :ttl => 300, :address => address})
  end

  def extract(msg, qname, type=Types.A)
    found = []
    @dns.extract_resources(msg, qname, type, Classes.IN) {|rr| found << rr}
    found
  end

  def test_dname_redirects_subtree
    msg = canned_message('a.old.example.', [
      dname('old.example.', 'new.example.'),
      a_record('a.new.example.', '10.0.0.1')
    ])
    found = extract(msg, 'a.old.example.')
    assert_equal(1, found.length)
    assert_equal('a.new.example', found[0].name.to_s)
    assert_equal('10.0.0.1', found[0].address.to_s)
  end

  def test_dname_does_not_redirect_owner
    #  The DNAME owner itself is not redirected (RFC 6672 section 2).
    msg = canned_message('old.example.', [
      dname('old.example.', 'new.example.'),
      a_record('old.example.', '10.0.0.2')
    ])
    found = extract(msg, 'old.example.')
    assert_equal(1, found.length)
    assert_equal('old.example', found[0].name.to_s)
    assert_equal('10.0.0.2', found[0].address.to_s)
  end

  def test_dname_closest_ancestor_wins
    #  The DNAME at the closest applicable ancestor applies, even when a
    #  DNAME higher up the tree is listed first.
    msg = canned_message('a.b.old.example.', [
      dname('old.example.', 'new.example.'),
      dname('b.old.example.', 'x.other.net.'),
      a_record('a.x.other.net.', '10.0.0.3')
    ])
    found = extract(msg, 'a.b.old.example.')
    assert_equal(1, found.length)
    assert_equal('a.x.other.net', found[0].name.to_s)
    assert_equal('10.0.0.3', found[0].address.to_s)
  end

  def test_dname_case_insensitive
    msg = canned_message('A.OLD.EXAMPLE.', [
      dname('Old.Example.', 'New.Example.'),
      a_record('a.new.example.', '10.0.0.4')
    ])
    found = extract(msg, 'A.OLD.EXAMPLE.')
    assert_equal(1, found.length)
    assert_equal('10.0.0.4', found[0].address.to_s)
  end

  def test_dname_label_boundary
    #  "notold.example" shares a suffix with "old.example" but is not in
    #  its subtree, so the DNAME must not apply.
    msg = canned_message('notold.example.', [
      dname('old.example.', 'new.example.'),
      a_record('notold.example.', '10.0.0.5')
    ])
    found = extract(msg, 'notold.example.')
    assert_equal(1, found.length)
    assert_equal('notold.example', found[0].name.to_s)
    assert_equal('10.0.0.5', found[0].address.to_s)
  end

  def test_dname_cname_interleaved_chain
    #  Multi-level DNAMEs interleaved with plain CNAMEs :
    #  a.old.example -> (DNAME) a.new.example -> (CNAME) b.other.net
    #  -> (DNAME) b.else.org -> (CNAME) c.final.net -> A
    msg = canned_message('a.old.example.', [
      dname('old.example.', 'new.example.'),
      cname('a.new.example.', 'b.other.net.'),
      dname('other.net.', 'else.org.'),
      cname('b.else.org.', 'c.final.net.'),
      a_record('c.final.net.', '10.0.0.9')
    ])
    found = extract(msg, 'a.old.example.')
    assert_equal(1, found.length)
    assert_equal('c.final.net', found[0].name.to_s)
    assert_equal('10.0.0.9', found[0].address.to_s)
  end

  def test_dname_yxdomain_when_too_long
    #  The DNAME target is 254 octets on the wire; prepending the "a"
    #  prefix label pushes the substituted name past the 255-octet wire
    #  format limit, which must yield YXDOMAIN (RFC 6672 section 2).
    target = "#{'a' * 63}.#{'b' * 63}.#{'c' * 63}.#{'d' * 60}."
    msg = canned_message('a.old.example.', [
      dname('old.example.', target)
    ])
    assert_raises(Dnsruby::YXDomain) do
      extract(msg, 'a.old.example.')
    end
  end

  def test_synthesize_cname
    synth = @dns.synthesize_cname('a.b.old.example.', dname('old.example.', 'new.example.', 7200))
    assert_equal(Types.CNAME, synth.type)
    assert_equal('a.b.old.example', synth.name.to_s)
    assert_equal('a.b.new.example', synth.domainname.to_s)
    assert(synth.name.absolute?)
    assert(synth.domainname.absolute?)
    assert_equal(7200, synth.ttl)
  end

  def test_synthesize_cname_yxdomain
    target = "#{'a' * 63}.#{'b' * 63}.#{'c' * 63}.#{'d' * 60}."
    assert_raises(Dnsruby::YXDomain) do
      @dns.synthesize_cname('a.old.example.', dname('old.example.', target))
    end
  end
end
