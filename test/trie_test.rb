require File.dirname(__FILE__) + '/test_helper'
require 'ldap/server/trie'

class TestTrie < Test::Unit::TestCase

  def test_trie
    trie = LDAP::Trie.new do |trie|
      trie.insert 'ou=Users,dc=thalarion,dc=be,op=bind', 'UsersBindTree'
      trie.insert 'ou=Users,dc=thalarion,dc=be,op=search', 'UsersSearchTree'
      trie.insert 'ou=Groups,dc=thalarion,dc=be,op=search', 'GroupsSearchTree'
      trie.insert 'dc=thalarion,dc=be,op=search', 'RootSearchValue'
    end

    assert trie.lookup('ou=Users,dc=thalarion,dc=be,op=bind') == 'UsersBindTree'
    assert trie.lookup('ou=Users,dc=thalarion,dc=be,op=search') == 'UsersSearchTree'
    assert trie.lookup('ou=Groups,dc=thalarion,dc=be,op=search') == 'GroupsSearchTree'
    assert trie.lookup('dc=thalarion,dc=be,op=search') == 'RootSearchValue'
    assert trie.lookup('ou=DoesNotExist,dc=thalarion,dc=be,op=search').nil?
    assert trie.lookup('dc=thalarion,dc=be,op=bind').nil?
  end

end
