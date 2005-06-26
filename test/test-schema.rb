$:.unshift '../lib'
require 'ldap/server/schema'
require 'test/unit'

class SchemaTest < Test::Unit::TestCase
  def test_parse_attr
attr = <<ATTR
( 2.5.4.3 NAME ( 'cn' 'commonName' ) OBSOLETE SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION USAGE userApplications )
ATTR
    a = LDAP::Server::Schema::AttributeType.new(attr)
    assert_equal("2.5.4.3", a.oid)
    assert_equal("cn", a.name)
    assert_equal(["cn", "commonName"], a.names)
    assert(a.obsolete)
    assert(a.singlevalue)
    assert(a.collective)
    assert(a.nousermod)
    assert_equal(:userApplications, a.usage)
    assert_equal(attr.chomp, a.to_def)

attr = <<ATTR
( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC2256: common name(s) for which the entity is known by' SUP name )
ATTR
    a = LDAP::Server::Schema::AttributeType.new(attr)
    assert_equal("2.5.4.3", a.oid)
    assert_equal("cn", a.name)
    assert_equal(["cn", "commonName"], a.names)
    assert_equal("RFC2256: common name(s) for which the entity is known by", a.desc)
    assert(! a.obsolete)
    assert(! a.singlevalue)
    assert(! a.collective)
    assert(! a.nousermod)
    assert_equal("name", a.sup)
    assert_equal(attr.chomp, a.to_def)
  end
end
