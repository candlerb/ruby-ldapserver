#!/usr/local/bin/ruby -w

# This is a modified version of rbslapd1.rb which uses a Router instead of
# subclassing the LDAP::Server::Operation class.

# This is a trivial LDAP server which just stores directory entries in RAM.
# It does no validation or authentication. This is intended just to
# demonstrate the API, it's not for real-world use!!

$:.unshift('../lib')
$debug = true

require 'ldap/server'
require 'ldap/server/router'

$logger = Logger.new($stderr)

class LDAPController
  def self.bind(request, version, dn, password, params)
    $logger.debug "Catchall bind request"
    raise LDAP::ResultError::UnwillingToPerform, "Invalid bind DN"
  end

  def self.bindUser(request, version, dn, password, params)
    if params[:uid].nil? or
        params[:uid] != 'admin' or
        password != 'adminpassword'
      $logger.debug "Denied access for user #{params[:uid]}"
      raise LDAP::ResultError::InvalidCredentials, "Invalid credentials"
    end

    $logger.debug "Authenticated user #{params[:uid]}"
  end
end

router = LDAP::Router.new($logger) do
  # Different syntax but same thing
  bind    nil => "LDAPController#bind"
  route   :bind, nil => "LDAPController#bind"

  # Bind a route using variables. A hash with the variables will be passed
  # to your function as last argument.
  bind    "uid=:uid,ou=Users,dc=mydomain,dc=com" => "LDAPController#bindUser"
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

s = LDAP::Server.new(
  :port       => 1389,
  :nodelay    => true,
  :listen     => 10,
# :ssl_key_file   => "key.pem",
# :ssl_cert_file  => "cert.pem",
# :ssl_on_connect => true,
  :router     => router
)
s.run_tcpserver
s.join
