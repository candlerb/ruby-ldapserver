#!/usr/local/bin/ruby -w

$:.unshift('../lib')
require 'test/unit'
require 'ldap/server/filter'

class FilterTest < Test::Unit::TestCase

  AV1 = {
    "foo" => ["abc","def"],
    "bar" => ["wibblespong"],
  }
  DM = LDAP::Server::MatchingRule::DefaultMatch

  def test_bad
    assert_raises(LDAP::ResultError::OperationsError) {
      LDAP::Server::Filter.run([:wibbly], AV1)
    }
  end

  def test_const
    assert_equal(true, LDAP::Server::Filter.run([:true], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:false], AV1))
    assert_equal(nil, LDAP::Server::Filter.run([:undef], AV1))
  end

  def test_present
    assert_equal(true, LDAP::Server::Filter.run([:present,"foo"], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:present,"zog"], AV1))
  end

  def test_eq
    assert_equal(true, LDAP::Server::Filter.run([:eq,"foo",DM,"abc"], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:eq,"foo",DM,"def"], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:eq,"foo",DM,"ghi"], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:eq,"xyz",DM,"abc"], AV1))
  end

  def test_eq_case
    c = LDAP::Server::MatchingRule.find('2.5.13.2')
    assert_equal(true, LDAP::Server::Filter.run([:eq,"foo",c,"ABC"], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:eq,"foo",c,"DeF"], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:eq,"foo",c,"ghi"], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:eq,"xyz",c,"abc"], AV1))
  end

  def test_not
    assert_equal(false, LDAP::Server::Filter.run([:not,[:eq,"foo",DM,"abc"]], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:not,[:eq,"foo",DM,"def"]], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:not,[:eq,"foo",DM,"ghi"]], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:not,[:eq,"xyz",DM,"abc"]], AV1))
  end

  def test_ge
    assert_equal(true, LDAP::Server::Filter.run([:ge,"foo",DM,"ccc"], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:ge,"foo",DM,"def"], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:ge,"foo",DM,"deg"], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:ge,"xyz",DM,"abc"], AV1))
  end

  def test_le
    assert_equal(true, LDAP::Server::Filter.run([:le,"foo",DM,"ccc"], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:le,"foo",DM,"abc"], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:le,"foo",DM,"abb"], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:le,"xyz",DM,"abc"], AV1))
  end

  def test_substrings
    assert_equal(true, LDAP::Server::Filter.run([:substrings,"foo",DM,"a",nil], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:substrings,"foo",DM,"def",nil], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:substrings,"foo",DM,"bc",nil], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:substrings,"foo",DM,"az",nil], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:substrings,"foo",DM,"",nil], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:substrings,"zzz",DM,"",nil], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:substrings,"foo",DM,nil,"a",nil], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:substrings,"foo",DM,nil,"e",nil], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:substrings,"foo",DM,nil,"ba",nil], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:substrings,"foo",DM,nil,"az",nil], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:substrings,"foo",DM,nil,"c"], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:substrings,"foo",DM,nil,"ef"], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:substrings,"foo",DM,nil,"ab"], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:substrings,"foo",DM,nil,"e"], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:substrings,"bar",DM,"wib","ong"], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:substrings,"bar",DM,"",""], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:substrings,"bar",DM,"wib","ble"], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:substrings,"bar",DM,"sp","ong"], AV1))
  end

  def test_substr_case
    c = LDAP::Server::MatchingRule.find('1.3.6.1.4.1.1466.109.114.3')
    assert_equal(true, LDAP::Server::Filter.run([:substrings,"bar",c,"WIB",nil], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:substrings,"bar",c,"WIB","lES","ong"], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:substrings,"bar",c,"SPONG",nil], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:substrings,"xyz",c,"wib",nil], AV1))
  end

  def test_and
    assert_equal(true, LDAP::Server::Filter.run([:and,[:true],[:true]], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:and,[:false],[:true]], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:and,[:true],[:false]], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:and,[:false],[:false]], AV1))
  end

  def test_or
    assert_equal(true, LDAP::Server::Filter.run([:or,[:true],[:true]], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:or,[:false],[:true]], AV1))
    assert_equal(true, LDAP::Server::Filter.run([:or,[:true],[:false]], AV1))
    assert_equal(false, LDAP::Server::Filter.run([:or,[:false],[:false]], AV1))
  end

end
