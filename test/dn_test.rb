require File.dirname(__FILE__) + '/test_helper'
require 'ldap/server/dn'

class TestLdapDn < Test::Unit::TestCase
  def setup
    @dn = LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB")
  end

  def test_find_first
    assert_equal(nil, @dn.find_first("ou"))
    assert_equal("Steve Kille", @dn.find_first("cn"))
    assert_equal("Isode Limited", @dn.find_first("o"))
  end

  def test_find_last
    assert_equal(nil, @dn.find_last("ou"))
    assert_equal("Steve Kille", @dn.find_last("cn"))
    assert_equal("Companies", @dn.find_last("o"))
  end

  def test_find
    assert_equal([], @dn.find("ou"))
    assert_equal(["Steve Kille"], @dn.find("cn"))
    assert_equal(["Isode Limited", "Companies"], @dn.find("o"))
  end

  def test_find_nth
    assert_equal(nil, @dn.find_nth("ou", 0))
    assert_equal("Steve Kille", @dn.find_nth("cn", 0))
    assert_equal(nil, @dn.find_nth("cn", 1))
    assert_equal("Isode Limited", @dn.find_nth("o", 0))
    assert_equal("Companies", @dn.find_nth("o", 1))
    assert_equal(nil, @dn.find_nth("o", 2))
  end

  def test_start_with
    assert @dn.start_with?("cn=Steve Kille")
    assert @dn.start_with?("cn=Steve Kille, o=Isode Limited")
    refute @dn.start_with?("cn=John Doe")
  end

  def test_start_with_format
    assert @dn.start_with_format?("cn=Steve Kille")
    assert @dn.start_with_format?("cn=foo, o=bar")
    refute @dn.start_with_format?("c=GB")
    refute @dn.start_with_format?("c=BE")
  end

  def test_end_with
    assert @dn.end_with?("c=GB")
    assert @dn.end_with?("o=Companies, c=GB")
    refute @dn.end_with?("c=BE")
  end

  def test_end_with_format
    assert @dn.end_with_format?("c=GB")
    assert @dn.end_with_format?("o=foo, c=bar")
    refute @dn.end_with_format?("cn=Steve Kille")
    refute @dn.end_with_format?("cn=foo")
  end

  def test_equal
    assert @dn.equal?("CN=Steve Kille,     o=Isode Limited,O=Companies,c=GB")
    refute @dn.equal?("cn=John Doe,o=Isode Limited,o=Companies,c=GB")
  end

  def test_equal_format
    assert @dn.equal_format?("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB")
    assert @dn.equal_format?("cn=STEVE KILLE,o=ISODE LIMITED,o=COMPANIES,c=GB")
    assert @dn.equal_format?("cn=foo,o=bar,o=baz,c=bat")
    assert @dn.equal_format?("CN=foo,O=bar,O=baz,C=bat")
    refute @dn.equal_format?("cn=foo,o=Isode Limited,c=GB")
  end

  def test_include
    assert @dn.include?("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB")
    assert @dn.include?("cn=Steve Kille")
    assert @dn.include?("o=Isode Limited")
    assert @dn.include?("o=Isode Limited,o=Companies")
    assert @dn.include?("c=GB")

    refute @dn.include?("cn=John Doe,o=Isode Limited,o=Companies,c=GB")
    refute @dn.include?("cn=Steve Kille,o=Isode Limited,c=GB")
  end

  def test_include_format
    assert @dn.include_format?("cn=foo,o=bar,o=baz,c=bat")
    assert @dn.include_format?("cn=foo")
    assert @dn.include_format?("o=bar")
    assert @dn.include_format?("o=bar,o=baz")
    assert @dn.include_format?("c=bat")

    refute @dn.include_format?("cn=foo,o=bar,c=bat")
    refute @dn.include_format?("cn=bar,c=bat")
  end

  def test_parse
    assert_equal @dn.parse("cn=:cn,o=:company,o=Companies,c=:country"),
      {
        :cn => 'Steve Kille',
        :company => 'Isode Limited',
        :country => 'GB'
      }
    assert_equal @dn.parse("cn=:cn,o=:company,o=:company,c=:country"),
      {
        :cn => 'Steve Kille',
        :company => 'Companies',
        :country => 'GB'
      }
    assert_empty @dn.parse("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB")

    assert_equal @dn.parse("cn=:cn,cn=Steve Kille,o=Isode Limited,o=Companies,c=GB"),
      {
        :cn => nil
      }

    assert_empty @dn.parse("o=Foo,o=Companies,c=GB")
    assert_empty @dn.parse("cn=:cn,o=Foo,o=Companies,c=GB")

  end

  def test_each
    answer = [
      { 'cn' => 'Steve Kille' },
      { 'o' => 'Isode Limited' },
      { 'o' => 'Companies' },
      { 'c' => 'GB' }
    ]
    i = 0
    @dn.each do |pair|
      assert_equal pair, answer[i]
      i += 1
    end
  end

  def test_reverse_each
    answer = [
      { 'c' => 'GB' },
      { 'o' => 'Companies' },
      { 'o' => 'Isode Limited' },
      { 'cn' => 'Steve Kille' }
    ]
    i = 0
    @dn.reverse_each do |pair|
      assert_equal pair, answer[i]
      i += 1
    end
  end
end
