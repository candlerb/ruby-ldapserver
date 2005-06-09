#!/usr/local/bin/ruby -w

# This is a trivial LDAP server which just stores directory entries in RAM.
# It does no validation or authentication. This is intended just to
# demonstrate the API, it's not for real-world use!!

$:.unshift('../lib')

require 'ldapserver/tcpserver'
require 'ldapserver/connection'
require 'ldapserver/operation'

class HashOperation < LDAPserver::Operation
  def initialize(connection, messageID, hash)
    super(connection, messageID)
    @hash = hash
  end

  def search(basedn, scope, deref, filter, attrs)
    @hash.each do |dn, av|
      send_SearchResultEntry(dn, av)
    end
  end

  def add(dn, av)
    dn.downcase!
    raise LDAPserver::EntryAlreadyExists if @hash[dn]
    @hash[dn] = av
  end

  def del(dn)
    dn.downcase!
    raise LDAPserver::NoSuchObject unless @hash.has_key?(dn)
    @hash.delete(dn)
  end

  def modify(dn, ops)
    entry = @hash[dn]
    raise LDAPserver::NoSuchObject unless entry
    ops.each do |op, attr, vals|
      case op 
      when :add
        entry[attr] ||= []
        entry[attr] += vals
        entry[attr].uniq!
      when :delete
        if vals == []
          entry.delete(attr)
        else
          vals.each { |v| entry[attr].delete(v) }
          entry.delete(attr) if entry[attr] == {}
        end
      when :replace
        entry[attr] = vals
      end
    end
  end
end

# This is the shared object which carries our actual directory entries.
# It's just a hash of {dn=>entry}, where each entry is {attr=>[val,val,...]}

directory = {}

# Listen for incoming LDAP connections. For each one, create a Connection
# object, which will invoke a HashOperation object for each request.

t = LDAPserver::tcpserver(:port=>1389) do
  LDAPserver::Connection::new(self).handle_requests(HashOperation, directory)
end
t.join
