#!/usr/local/bin/ruby -w

# This is a trivial LDAP server which just stores directory entries in RAM.
# It does no validation or authentication. This is intended just to
# demonstrate the API, it's not for real-world use!!

$:.unshift('../lib')

require 'ldapserver/tcpserver'
require 'ldapserver/connection'
require 'ldapserver/operation'

# We subclass the Operation class, overriding the methods to do what we need

class HashOperation < LDAPserver::Operation
  def initialize(connection, messageID, hash)
    super(connection, messageID)
    @hash = hash   # an object reference to our directory data
  end

  def search(basedn, scope, deref, filter)
    basedn.downcase!

    case scope
    when LDAPserver::BaseObject
      # client asked for single object by DN
      obj = @hash[basedn]
      raise LDAPserver::NoSuchObject unless obj
      send_SearchResultEntry(basedn, obj) if LDAPserver::Filter.run(filter, obj)

    when LDAPserver::WholeSubtree
      @hash.each do |dn, av|
        next unless dn.index(basedn, -basedn.length)    # under basedn?
        next unless LDAPserver::Filter.run(filter, av)  # attribute filter?
        send_SearchResultEntry(dn, av)
      end

    else
      raise LDAPserver::UnwillingToPerform, "OneLevel not implemented"

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
        end
      when :replace
        entry[attr] = vals
      end
      entry.delete(attr) if entry[attr] == []
    end
  end
end

# This is the shared object which carries our actual directory entries.
# It's just a hash of {dn=>entry}, where each entry is {attr=>[val,val,...]}

directory = {}

# Let's put some backing store on it

require 'yaml'
begin
  File.open("ldapdb.yaml") { |f| directory = YAML::load(f.read) }
rescue Errno::ENOENT
end

at_exit do
  File.open("ldapdb.new","w") { |f| f.write(YAML::dump(directory)) }
  File.rename("ldapdb.new","ldapdb.yaml")
end

# Listen for incoming LDAP connections. For each one, create a Connection
# object, which will invoke a HashOperation object for each request.

t = LDAPserver::tcpserver(:port=>1389, :nodelay=>true, :listen=>10) do
  LDAPserver::Connection::new(self).handle_requests(HashOperation, directory)
end
t.join
