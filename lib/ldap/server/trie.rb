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

  def match(dn)
    split_dn = LDAP::Server::DN.new(dn)
    @root.match split_dn, ''
  end

  def print_tree
    @root.print_tree
  end

end

class Node
  attr_accessor :parent, :value, :children

  def initialize(parent = nil, value = nil)
    @parent = parent
    @value = value
    @children = Hash.new
  end

  def insert(dn, value)
    dn.reverse_each do |component|
      @children[component] = Node.new(self) if @children[component].nil?
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
  def match(dn, path)
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

  def value
    @value
  end

  def value=(value)
    @value = value
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
