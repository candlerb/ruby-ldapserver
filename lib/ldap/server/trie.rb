# Quick implementation of an LDAP prefix tree or 'trie'

require 'ldap/server/dn'

module LDAP
class Trie
  @root

  def initialize
    @root = Node.new
    yield self if block_given?
  end

  def <<(dn)
    insert dn, nil
  end

  def insert(dn, value = nil)
    split_dn = LDAP::Server::DN.new(dn)
    @root.insert split_dn, value
  end

  def lookup(dn)
    split_dn = LDAP::Server::DN.new(dn)
    @root.lookup split_dn
  end

  def print_tree
    @root.print_tree
  end

end

class Node
  @parent
  @value
  @children

  def initialize(parent = nil, value = nil)
    @parent = parent
    @value = value
    @children = Hash.new
  end

  def insert(dn, value)
    dn.reverse_each do |pair|
      component = LDAP::Server::DN.join(pair)
      @children[component] = Node.new(self) if @children[component].nil?
      dn.dname.pop
      if dn.any?
        @children[component].insert dn, value
      else
        @children[component].value = value
      end
    end
  end

  def lookup(dn)
    if dn.dname.empty?
      return @value
    end
    dn.reverse_each do |pair|
      component = LDAP::Server::DN.join(pair)
      return nil if @children[component].nil?
      dn.dname.pop
      return @children[component].lookup dn
    end
  end

  def value
    @value
  end

  def value=(value)
    @value = value
  end

  def print_tree(prefix = '')
    if @value
      p "#{prefix}=> #{@value}"
    end
    @children.each do |key, value|
        p "#{prefix}#{key}"
      @children[key].to_s("#{prefix}  ")
    end
  end
end
end
