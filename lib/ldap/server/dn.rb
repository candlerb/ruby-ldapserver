require 'ldap/server/util'

module LDAP
class Server

  class DN
    @dname

    # Combines a set of elements to a syntactically correct DN
    # elements is [elements, ...] where elements
    # can be either { attr => val } or [attr, val]
    def self.join(elements)
      LDAP::Server::Operation.join_dn(elements)
    end

    def initialize(dn)
      @dname = LDAP::Server::Operation.split_dn(dn)
    end

    # Returns the value of the first occurrence of attr (bottom-up)
    def find_first(attr)
      @dname.each do |pair|
        return pair[attr.to_s] if pair[attr.to_s]
      end
      nil
    end

    # Returns the value of the last occurrence of attr (bottom-up)
    def find_last(attr)
      @dname.reverse_each do |pair|
        return pair[attr.to_s] if pair[attr.to_s]
      end
      nil
    end

    # Returns all values of all occurrences of attr (bottom-up)
    def find(attr)
      result = []
      @dname.each do |pair|
        result << pair[attr.to_s] if pair[attr.to_s]
      end
      result
    end

    # Returns the value of the n-th occurrence of attr (top-down, 0 is first element)
    def find_nth(attr, n)
      i = 0
      @dname.each do |pair|
        if pair[attr.to_s]
          return pair[attr.to_s] if i == n
          i += 1
        end
      end
      nil
    end

    # Whether or not the DN starts with dn (bottom-up)
    # dn is a string
    def starts_with?(dn)
      needle = LDAP::Server::Operation.split_dn(dn)

      # Needle is longer than haystack
      return false if needle.length > @dname.length

      needle_index = 0
      haystack_index = 0

      while needle_index < needle.length
        return false if @dname[haystack_index] != needle[needle_index]
        needle_index += 1
        haystack_index += 1
      end
      true
    end

    # Whether or not the DN ends with dn (top-down)
    # dn is a string
    def ends_with?(dn)
      needle = LDAP::Server::Operation.split_dn(dn)

      # Needle is longer than haystack
      return false if needle.length > @dname.length

      needle_index = needle.length - 1
      haystack_index = @dname.length - 1

      while needle_index >= 0
        return false if @dname[haystack_index] != needle[needle_index]
        needle_index -= 1
        haystack_index -= 1
      end
      true
    end

    # Whether or not the DN equals dn (values are case sensitive)
    # dn is a string
    def equals?(dn)
      split_dn = LDAP::Server::Operation.split_dn(dn)

      return false if split_dn.length != @dname.length

      @dname.each_with_index do |pair, index|
        return false if pair != split_dn[index]
      end
      true
    end

    # Whether or not the DN equals dn's format (values are ignored) (case insensitive)
    # dn is a string
    def equals_format?(dn)
      split_dn = LDAP::Server::Operation.split_dn(dn)

      return false if split_dn.length != @dname.length

      @dname.each_with_index do |pair, index|
        return false if pair.keys != split_dn[index].keys
      end
      true
    end
  end

end
end
