#!/usr/local/bin/ruby -w

$:.unshift('../lib')
require 'test/unit'
require 'ldapserver/filter'

class FilterTest < Test::Unit::TestCase

  AV1 = {
    "foo" => ["abc","def"],
    "bar" => ["wibblespong"],
  }

  def test_bad
    assert_raises(LDAPserver::OperationsError) {
      LDAPserver::Filter.run([:wibbly], AV1)
    }
  end

  def test_const
    assert_equal(true, LDAPserver::Filter.run([:true], AV1))
    assert_equal(false, LDAPserver::Filter.run([:false], AV1))
    assert_equal(nil, LDAPserver::Filter.run([:undef], AV1))
  end

  def test_present
    assert_equal(true, LDAPserver::Filter.run([:present,"foo"], AV1))
    assert_equal(false, LDAPserver::Filter.run([:present,"zog"], AV1))
  end

  def test_eq
    assert_equal(true, LDAPserver::Filter.run([:eq,"foo","abc"], AV1))
    assert_equal(true, LDAPserver::Filter.run([:eq,"foo","def"], AV1))
    assert_equal(false, LDAPserver::Filter.run([:eq,"foo","ghi"], AV1))
    assert_equal(false, LDAPserver::Filter.run([:eq,"xyz","abc"], AV1))
  end

  def test_not
    assert_equal(false, LDAPserver::Filter.run([:not,[:eq,"foo","abc"]], AV1))
    assert_equal(false, LDAPserver::Filter.run([:not,[:eq,"foo","def"]], AV1))
    assert_equal(true, LDAPserver::Filter.run([:not,[:eq,"foo","ghi"]], AV1))
    assert_equal(true, LDAPserver::Filter.run([:not,[:eq,"xyz","abc"]], AV1))
  end

  def test_ge
    assert_equal(true, LDAPserver::Filter.run([:ge,"foo","ccc"], AV1))
    assert_equal(true, LDAPserver::Filter.run([:ge,"foo","def"], AV1))
    assert_equal(false, LDAPserver::Filter.run([:ge,"foo","deg"], AV1))
    assert_equal(false, LDAPserver::Filter.run([:ge,"xyz","abc"], AV1))
  end

  def test_le
    assert_equal(true, LDAPserver::Filter.run([:le,"foo","ccc"], AV1))
    assert_equal(true, LDAPserver::Filter.run([:le,"foo","abc"], AV1))
    assert_equal(false, LDAPserver::Filter.run([:le,"foo","abb"], AV1))
    assert_equal(false, LDAPserver::Filter.run([:le,"xyz","abc"], AV1))
  end

  def test_substrings
    assert_equal(true, LDAPserver::Filter.run([:substrings,"foo",[:initial,"a"]], AV1))
    assert_equal(true, LDAPserver::Filter.run([:substrings,"foo",[:initial,"def"]], AV1))
    assert_equal(false, LDAPserver::Filter.run([:substrings,"foo",[:initial,"bc"]], AV1))
    assert_equal(false, LDAPserver::Filter.run([:substrings,"foo",[:initial,"az"]], AV1))
    assert_equal(true, LDAPserver::Filter.run([:substrings,"foo",[:initial,""]], AV1))
    assert_equal(false, LDAPserver::Filter.run([:substrings,"zzz",[:initial,""]], AV1))
    assert_equal(true, LDAPserver::Filter.run([:substrings,"foo",[:any,"a"]], AV1))
    assert_equal(true, LDAPserver::Filter.run([:substrings,"foo",[:any,"e"]], AV1))
    assert_equal(false, LDAPserver::Filter.run([:substrings,"foo",[:any,"ba"]], AV1))
    assert_equal(false, LDAPserver::Filter.run([:substrings,"foo",[:any,"az"]], AV1))
    assert_equal(true, LDAPserver::Filter.run([:substrings,"foo",[:final,"c"]], AV1))
    assert_equal(true, LDAPserver::Filter.run([:substrings,"foo",[:final,"ef"]], AV1))
    assert_equal(false, LDAPserver::Filter.run([:substrings,"foo",[:final,"ab"]], AV1))
    assert_equal(false, LDAPserver::Filter.run([:substrings,"foo",[:final,"e"]], AV1))
    assert_equal(true, LDAPserver::Filter.run([:substrings,"bar",[:initial,"wib"],[:final,"ong"]], AV1))
    assert_equal(true, LDAPserver::Filter.run([:substrings,"bar",[:initial,""],[:final,""]], AV1))
    assert_equal(false, LDAPserver::Filter.run([:substrings,"bar",[:initial,"wib"],[:final,"ble"]], AV1))
    assert_equal(false, LDAPserver::Filter.run([:substrings,"bar",[:initial,"sp"],[:final,"ong"]], AV1))
  end

  def test_and
    assert_equal(true, LDAPserver::Filter.run([:and,[:true],[:true]], AV1))
    assert_equal(false, LDAPserver::Filter.run([:and,[:false],[:true]], AV1))
    assert_equal(false, LDAPserver::Filter.run([:and,[:true],[:false]], AV1))
    assert_equal(false, LDAPserver::Filter.run([:and,[:false],[:false]], AV1))
  end

  def test_or
    assert_equal(true, LDAPserver::Filter.run([:or,[:true],[:true]], AV1))
    assert_equal(true, LDAPserver::Filter.run([:or,[:false],[:true]], AV1))
    assert_equal(true, LDAPserver::Filter.run([:or,[:true],[:false]], AV1))
    assert_equal(false, LDAPserver::Filter.run([:or,[:false],[:false]], AV1))
  end

end
