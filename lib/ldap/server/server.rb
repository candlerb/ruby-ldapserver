require 'ldapserver/connection'
require 'ldapserver/operation'
require 'openssl'

module LDAPserver

  class Server

    DEFAULT_OPT = {
	:port=>389,
	:nodelay=>true,
    }

    # Create a new server. Options include all those to tcpserver/preforkserver
    # plus:
    #   :operation_class=>Class			- set Operation handler class
    #   :operation_args=>[...]			- args to Operation.new
    #   :ssl_key_file=>pem, :ssl_cert_file=>pem	- enable SSL
    #   :ssl_ca_path=>directory			- verify peer certificates

    def initialize(opt = DEFAULT_OPT)
      @opt = opt
      @opt[:server] = self
      @opt[:operation_class] ||= LDAPserver::Operation
      @opt[:operation_args] ||= []
      LDAPserver::Server.ssl_prepare(@opt)

    end

    # create opt[:ssl_ctx] from the other ssl options

    def self.ssl_prepare(opt)
      if opt[:ssl_key_file] and opt[:ssl_cert_file]
        ctx = OpenSSL::SSL::SSLContext.new
        ctx.key = OpenSSL::PKey::RSA.new(File::read(opt[:ssl_key_file]))
        ctx.cert = OpenSSL::X509::Certificate.new(File::read(opt[:ssl_cert_file]))
        if opt[:ssl_ca_path]
          ctx.ca_path = opt[:ssl_ca_path]
          ctx.verify_mode = 
            OpenSSL::SSL::VERIFY_PEER|OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
        else
          $stderr.puts "Warning: SSL peer certificate won't be verified"
        end
        opt[:ssl_ctx] = ctx
      end
    end

    def run_tcpserver
      require 'ldapserver/tcpserver'

      opt = @opt
      @thread = LDAPserver::tcpserver(@opt) do
        LDAPserver::Connection::new(self,opt).handle_requests
      end
    end

    def run_prefork
      require 'ldapserver/preforkserver'

      opt = @opt
      @thread = LDAPserver::preforkserver(@opt) do
        LDAPserver::Connection::new(self,opt).handle_requests
      end
    end

    def join
      @thread.join
    end

    def stop
      @thread.raise Interrupt
      @thread.join
    end

    def setup_root
      # set up a minimal root DSE

      @root_dse = {
	# 
	'objectClass' => ['top','extensibleObject'],
	# RFC 2251
	'namingContexts' => [],
	'subschemaSubentry' => ["cn=Subschema"],	# see also...
	'altServer' => [],
	'supportedExtension' => [],
	'supportedControl' => [],
	'supportedSASLMechanisms' => [],
	'supportedLDAPVersion' => ['3'],	# note 1
      }
      # note 1: despite LDAP defining syntax types and associating them
      # with attributes, everything is encoded as a string

      @subschema = {
	'objectClass' => ['top','extensibleObject'],
	'cn' => ['Subschema'],				# ...see also
	'objectClasses' => [
	  "( 2.5.6.0 NAME 'top' DESC 'top of the superclass chain' ABSTRACT MUST objectClass )",
	  "( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject' DESC 'RFC2252: extensible object' SUP top AUXILIARY )",
        ],
	'attributeTypes' => [],
	'matchingRules' => [],
	'matchingRuleUse' => [],
	'dITStructureRules' => [],
	'dITContentRules' => [],
	'nameForms' => [],
	'ldapSyntaxes' => [],
      }
    end
  end
end
