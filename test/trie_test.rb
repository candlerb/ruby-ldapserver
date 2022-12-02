require File.dirname(__FILE__) + '/test_helper'
require 'ldap/server/trie'

class TestTrie < Test::Unit::TestCase

  def test_trie_base
    trie = LDAP::Server::Trie.new do |trie|
      trie.insert 'ou=Users,dc=mydomain,dc=com,op=bind', 'UsersBindTree'
      trie.insert 'ou=Users,dc=mydomain,dc=com,op=search', 'UsersSearchTree'
      trie.insert 'ou=Groups,dc=mydomain,dc=com,op=search', 'GroupsSearchTree'
      trie.insert 'dc=mydomain,dc=com,op=search', 'RootSearchValue'
      trie.insert 'dc=com,op=search', ''
    end

    assert_equal trie.lookup('ou=Users,dc=mydomain,dc=com,op=bind'), 'UsersBindTree'
    assert_equal trie.lookup('ou=Users,dc=mydomain,dc=com,op=search'), 'UsersSearchTree'
    assert_equal trie.lookup('ou=Groups,dc=mydomain,dc=com,op=search'), 'GroupsSearchTree'
    assert_equal trie.lookup('dc=mydomain,dc=com,op=search'), 'RootSearchValue'
    assert_equal trie.lookup('dc=com,op=search'), ''
    assert_nil trie.lookup 'dc=mydomain,dc=com,op=bind'
    assert_nil trie.lookup nil

    assert_raises LDAP::Server::Trie::NodeNotFoundError do
      trie.lookup 'ou=DoesNotExist,dc=mydomain,dc=com,op=search'
    end
  end

  def test_trie_wildcard
    trie = LDAP::Server::Trie.new do |trie|
      trie.insert 'uid=:uid,ou=Users,dc=mydomain,dc=com', 'SpecificUsers'
      trie.insert 'ou=Users,dc=mydomain,dc=com', 'Users'
      trie.insert 'ou=Users,dc=:domain,dc=:tld', 'Domain'
    end

    assert_equal trie.lookup('uid=john,ou=Users,dc=mydomain,dc=com'), 'SpecificUsers'
    assert_equal trie.lookup('uid=jane,ou=Users,dc=mydomain,dc=com'), 'SpecificUsers'
    assert_equal trie.lookup('ou=Users,dc=mydomain,dc=com'), 'Users'
    assert_equal trie.lookup('ou=Users,dc=otherdomain,dc=net'), 'Domain'
  end

  def test_trie_match
    trie = LDAP::Server::Trie.new do |trie|
      trie.insert 'uid=:uid,ou=Users,dc=mydomain,dc=com', 'SpecificUsers'
      trie.insert 'ou=Users,dc=mydomain,dc=com', 'Users'
      trie.insert 'dc=mydomain,dc=com', 'Domains'
    end

    assert_equal trie.match('uid=john,ou=Users,dc=mydomain,dc=com'),
                                ['uid=:uid,ou=Users,dc=mydomain,dc=com', 'SpecificUsers']
    assert_equal trie.match('cn=john,ou=Users,dc=mydomain,dc=com'),
                                ['ou=Users,dc=mydomain,dc=com', 'Users']
    assert_equal trie.match('ou=Users,dc=mydomain,dc=com'),
                                ['ou=Users,dc=mydomain,dc=com', 'Users']
    assert_equal trie.match('dc=mydomain,dc=com'),
                                ['dc=mydomain,dc=com', 'Domains']
    assert_equal trie.match('dc=otherdomain,dc=com'),
                                [nil, nil]
  end

end
