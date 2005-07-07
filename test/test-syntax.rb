$:.unshift '../lib'
require 'ldap/server/syntax'
require 'test/unit'

class SyntaxTest < Test::Unit::TestCase

  def test_integer
    s = LDAP::Server::Syntax.find("1.3.6.1.4.1.1466.115.121.1.27")
    assert_equal(LDAP::Server::Syntax, s.class)
    assert_equal("Integer", s.desc)
    assert_equal("( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'Integer' )", s.to_def)
    assert(s.hr)
    assert(s.match("123"))
    assert(!s.match("12A"))
    assert_equal(123, s.from_s("123"))
    assert_equal("456", s.to_s(456))
    assert_equal("789", s.to_s(789))
  end

  def test_unknown
    s = LDAP::Server::Syntax.find("1.4.7.1")
    assert_equal(LDAP::Server::Syntax, s.class)
    assert_equal("1.4.7.1", s.oid)
    assert_equal("( 1.4.7.1 )", s.to_def)
    assert_equal("false", s.to_s(false))	# generic to_s
    assert_equal("true", s.from_s("true"))	# generic from_s
    assert(s.match("123"))			# match anything
  end
end
