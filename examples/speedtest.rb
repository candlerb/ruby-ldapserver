#!/usr/local/bin/ruby

require 'ldap'

CHILDREN = 10
CONNECTS = 1	# per child
SEARCHES = 100	# per connection

pids = []
CHILDREN.times do
  pids << fork do
    CONNECTS.times do
      conn = LDAP::Conn.new("localhost",1389)
      conn.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 3)
      conn.bind
      SEARCHES.times do
        res = conn.search("uid=1,dc=example,dc=com", LDAP::LDAP_SCOPE_BASE,
                          "(objectclass=*)") do |e|
          #puts "#{$$} #{e.dn.inspect}"
        end
      end
      conn.unbind
    end
  end
end
pids.each { |p| Process.wait(p) }
