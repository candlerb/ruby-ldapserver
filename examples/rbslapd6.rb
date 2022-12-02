#!/usr/local/bin/ruby -w

# Slightly modified version of rbslapd5.rb which demonstrates dropping
# root privileges after binding to port 389
#
# Run this script with `sudo`

$:.unshift('../lib')
$debug = true

require 'fileutils'

require 'ldap/server'
require 'ldap/server/router'

$logger = Logger.new($stderr)

class LDAPController
  def self.bind(request, version, dn, password, params)
    $logger.info "Processing bind route for \'#{dn}\' with password \'#{password}\'"
  end

  def self.search(request, baseObject, scope, deref, filter, params)
    $logger.info "Processing search route for #{baseObject}"

    h = {
        'uid' => 'jdoe',
        'objectClass' => 'userAccount',
        'givenName' => 'John',
        'sn' => 'Doe'
    }
    request.send_SearchResultEntry("uid=jdoe,#{baseObject}", h)
  end
end

router = LDAP::Server::Router.new($logger) do
  bind    nil => "LDAPController#bind"

  search  "ou=Users,dc=mydomain,dc=com" => "LDAPController#search"
end

params = {
  :nodelay => true,
  :listen => 10,
  :router => router
}

# Listen on IP address and port

params[:bindaddr] = '127.0.0.1' # Leave this blank to listen on 0.0.0.0
params[:port] = 389
params[:user] = 'ldap'
params[:group] = 'ldap'

addr_server = LDAP::Server.new params
addr_server.run_tcpserver

# Listen on socket

params.delete :bindaddr
params.delete :port
params[:socket] = '/tmp/rbslapd6.sock'

FileUtils::rm_f params[:socket]

socket_server = LDAP::Server.new params
socket_server.run_tcpserver

trap 'INT' do
  addr_server.stop
  socket_server.stop
end

addr_server.join
socket_server.join
