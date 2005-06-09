#!/usr/local/bin/ruby -w

$:.unshift('../lib')

require 'ldapserver/util'
require 'test/unit'

class TestLdapUtil < Test::Unit::TestCase
  def test_split_dn
    # examples from RFC 2253
    assert_equal(
	[{"cn"=>"Steve Kille"},{"o"=>"Isode Limited"},{"c"=>"GB"}],
	LDAPserver::Operation.split_dn("CN=Steve Kille , O=Isode Limited,C=GB")
    )
    assert_equal(
	[{"ou"=>"Sales","cn"=>"J. Smith"},{"o"=>"Widget Inc."},{"c"=>"US"}],
	LDAPserver::Operation.split_dn("OU=Sales+CN=J. Smith,O=Widget Inc.,C=US")
    )
    assert_equal(
	[{"cn"=>"L. Eagle"},{"o"=>"Sue, Grabbit and Runn"},{"c"=>"GB"}],
	LDAPserver::Operation.split_dn("CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB")
    )
    assert_equal(
	[{"cn"=>"Before\rAfter"},{"o"=>"Test"},{"c"=>"GB"}],
	LDAPserver::Operation.split_dn("CN=Before\\0DAfter,O=Test,C=GB")
    )
    assert_equal(
	[{"sn"=>"Lu\xc4\x8di\xc4\x87"}],
	LDAPserver::Operation.split_dn("SN=Lu\\C4\\8Di\\C4\\87")
    )
  end

  def test_join_dn
    # examples from RFC 2253
    assert_equal(
        "cn=Steve Kille,o=Isode Limited,c=GB",
	LDAPserver::Operation.join_dn([{"cn"=>"Steve Kille"},{"o"=>"Isode Limited"},{"c"=>"GB"}])
    )
    # These are equivalent
    d1 = "ou=Sales+cn=J. Smith,o=Widget Inc.,c=US"
    d2 = "cn=J. Smith+ou=Sales,o=Widget Inc.,c=US"
    assert_equal(d1,
	LDAPserver::Operation.join_dn([[["ou","Sales"],["cn","J. Smith"]],[["o","Widget Inc."]],["c","US"]])
    )
    r = LDAPserver::Operation.join_dn([{"ou"=>"Sales","cn"=>"J. Smith"},{"o"=>"Widget Inc."},{"c"=>"US"}])
    assert(r == d1 || r == d2, "got #{r.inspect}, expected #{d1.inspect} or #{d2.inspect}")
    assert_equal(
	"cn=L. Eagle,o=Sue\\, Grabbit and Runn,c=GB",
	LDAPserver::Operation.join_dn([{"cn"=>"L. Eagle"},{"o"=>"Sue, Grabbit and Runn"},{"c"=>"GB"}])
    )
  end
end

