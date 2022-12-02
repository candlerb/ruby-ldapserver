#!/usr/local/bin/ruby -w

# Example server that listens on both a port and a UNIX domain socket
# Try it using:
#   $ ldapsearch -LLL -H ldap://localhost:1389 -D uid=whatever -b ou=Users,dc=mydomain,dc=com
#   $ ldapsearch -LLL -H ldapi://%2ftmp%2frbslapd5.sock -D uid=whatever -b ou=Users,dc=mydomain,dc=com

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
params[:port] = 1389

addr_server = LDAP::Server.new params
addr_server.run_tcpserver

# Listen on socket

params.delete :bindaddr
params.delete :port
params[:socket] = '/tmp/rbslapd5.sock'

FileUtils::rm_f params[:socket]

socket_server = LDAP::Server.new params
socket_server.run_tcpserver

trap 'INT' do
  addr_server.stop
  socket_server.stop
end

addr_server.join
socket_server.join
