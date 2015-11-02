# Quick implementation of an LDAP prefix tree or 'trie'

require 'ldap/server/dn'

module LDAP
class Server
class Trie
  attr_accessor :parent, :value, :children

  def initialize(parent = nil, value = nil)
    @parent = parent
    @value = value
    @children = Hash.new

    yield self if block_given?
  end

  def <<(dn)
    insert(dn)
  end

  def insert(dn, value = nil)
    dn = LDAP::Server::DN.new(dn || '') if not dn.is_a? LDAP::Server::DN
    dn.reverse_each do |component|
      @children[component] = Trie.new(self) if @children[component].nil?
      dn.dname.pop
      if dn.any?
        @children[component].insert dn, value
      else
        @children[component].value = value
      end
    end
  end

  # Lookup a node and returns its value or nil if it's not in the tree
  def lookup(dn)
    dn = LDAP::Server::DN.new(dn || '') if not dn.is_a? LDAP::Server::DN
    return @value if dn.dname.empty?
    component = dn.dname.pop
    @children.each do |key, value|
      if key.keys.first == component.keys.first
        if key.values.first.start_with?(':') or key.values.first == component.values.first
          return value.lookup dn
        end
      end
    end
    return nil
  end

  # Lookup a node and return its value or the value of the nearest ancestor
  def match(dn, path = '')
    dn = LDAP::Server::DN.new(dn || '') if not dn.is_a? LDAP::Server::DN
    return path, @value if dn.dname.empty?
    component = dn.dname.pop
    @children.each do |key, value|
      if key.keys.first == component.keys.first
        if key.values.first.start_with?(':') or key.values.first == component.values.first
          path.prepend ',' unless path.empty?
          path.prepend "#{LDAP::Server::DN.join key}"
          new_path, new_value = value.match dn, path
          if new_value
            return new_path, new_value
          else
            return (@value ? path : nil), @value
          end
        end
      end
    end
    return path, @value
  end

  def print_tree(prefix = '')
    if @value
      p "#{prefix}{{#{@value}}}"
    end
    @children.each do |key, value|
        p "#{prefix}#{key.keys.first} => #{key.values.first}"
      @children[key].print_tree("#{prefix}  ")
    end
  end
end
end
end
