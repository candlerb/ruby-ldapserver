require File.dirname(__FILE__) + '/test_helper'
require 'ldap/server/dn'

class TestLdapDn < Test::Unit::TestCase
  def test_find_first
    assert_equal(
      nil,
      LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").find_first("ou")
    )
    assert_equal(
      "Steve Kille",
      LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").find_first("cn")
    )
    assert_equal(
      "Isode Limited",
      LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").find_first("o")
    )
  end

  def test_find_last
    assert_equal(
      nil,
      LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").find_last("ou")
    )
    assert_equal(
      "Steve Kille",
      LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").find_last("cn")
    )
    assert_equal(
      "Companies",
      LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").find_last("o")
    )
  end

  def test_find
    assert_equal(
      [],
      LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").find("ou")
    )
    assert_equal(
      ["Steve Kille"],
      LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").find("cn")
    )
    assert_equal(
      ["Isode Limited", "Companies"],
      LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").find("o")
    )
  end

  def test_find_nth
    assert_equal(
      nil,
      LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").find_nth("ou", 0)
    )
    assert_equal(
      "Steve Kille",
      LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").find_nth("cn", 0)
    )
    assert_equal(
      nil,
      LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").find_nth("cn", 1)
    )
    assert_equal(
      "Isode Limited",
      LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").find_nth("o", 0)
    )
    assert_equal(
      "Companies",
      LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").find_nth("o", 1)
    )
    assert_equal(
      nil,
      LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").find_nth("o", 2)
    )
  end

  def test_starts_with
    assert LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").starts_with?("cn=Steve Kille")
    assert LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").starts_with?("cn=Steve Kille, o=Isode Limited")
    assert (not LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").starts_with?("cn=John Doe"))
  end

  def test_ends_with
    assert LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").ends_with?("c=GB")
    assert LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").ends_with?("o=Companies, c=GB")
    assert (not LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").ends_with?("c=BE"))
  end

  def test_equals
    assert LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").equals?("CN=Steve Kille,     o=Isode Limited,O=Companies,c=GB")
    assert (not LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").equals?("cn=John Doe,o=Isode Limited,o=Companies,c=GB"))
  end

  def test_equals_format
    assert LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").equals_format?("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB")
    assert LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").equals_format?("cn=STEVE KILLE,o=ISODE LIMITED,o=COMPANIES,c=GB")
    assert LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").equals_format?("cn=foo,o=bar,o=baz,c=bat")
    assert LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").equals_format?("CN=foo,O=bar,O=baz,C=bat")
    assert (not LDAP::Server::DN.new("cn=Steve Kille,o=Isode Limited,o=Companies,c=GB").equals_format?("cn=foo,o=Isode Limited,c=GB"))
  end
end
