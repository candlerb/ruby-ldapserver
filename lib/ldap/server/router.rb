require 'ldap/server/dn'
require 'ldap/server/util'
require 'ldap/server/trie'
require 'ldap/server/request'

module LDAP
class Router
  @logger
  @routes

  def initialize(logger, &block)
    @logger = logger

    @routes = Hash.new
    @routes = Trie.new do |trie|
      # Add an artificial LDAP component
      trie << "op=bind"
      trie << "op=search"
    end

    self.instance_eval(&block)
  end

  ######################
  ### Initialization ###
  ######################
  def route(operation, hash)
    hash.each do |key, value|
      if key.nil?
        @routes.insert "op=#{operation.to_s}", value
        @logger.info "#{operation.to_s} all routes to #{value}"
      else
        @routes.insert "#{key},op=#{operation.to_s}", value
        @logger.info "#{operation.to_s} #{key} to #{value}"
      end
    end
  end

  def method_missing(name, *args, &block)
    if [:bind, :search, :add, :modify, :modifydn, :del, :compare].include? name
      send :route, name, *args
    else
      super
    end
  end


  ##########################################
  ### Methods to parse each request type ###
  ##########################################

  def do_bind(connection, messageId, protocolOp, controls) # :nodoc:
    request = Request.new(connection, messageId)
    version = protocolOp.value[0].value
    dn = protocolOp.value[1].value
    dn = nil if dn == ""
    authentication = protocolOp.value[2]

    case authentication.tag   # tag_class == :CONTEXT_SPECIFIC (check why)
    when 0
      route_bind(request, version, dn, authentication.value)
    when 3
      mechanism = authentication.value[0].value
      credentials = authentication.value[1].value
      # sasl_bind(version, dn, mechanism, credentials)
      # FIXME: needs to exchange further BindRequests
      # route_bind(request, version, dn, mechanism, credentials)
      raise LDAP::ResultError::AuthMethodNotSupported
    else
      raise LDAP::ResultError::ProtocolError, "BindRequest bad AuthenticationChoice"
    end
    request.send_BindResponse(0)
    return dn, version

  rescue LDAP::ResultError => e
    request.send_BindResponse(e.to_i, :errorMessage=>e.message)
    return nil, version
  end


  ##########################################
  ### Methods to route each request type ###
  ##########################################
  def route_bind(request, version, dn, password)
    route, action = @routes.match("#{dn},op=bind")
    @logger.error "Route #{route} has no action!" if action.nil?

    class_name = action.split('#').first
    method_name = action.split('#').last

    params = LDAP::Server::DN.new("#{dn},op=bind").parse(route)
    begin
      Object.const_get(class_name).send method_name, request, version, dn, password, params
    rescue NoMethodError => e
      @logger.error e
    end
  end


  ######################################################
  ### Methods to actually perform the work requested ###
  ### The methods below are examples to illustrate   ###
  ### the arguments given to the various functions   ###
  ######################################################

  # Handle a simple bind request; raise an exception if the bind is
  # not acceptable, otherwise just return to accept the bind.
  #
  # Write your own class method using this signature

#  def simple_bind(request, version, dn, password, params)
#    if version != 3
#      raise LDAP::ResultError::ProtocolError, "version 3 only"
#    end
#    if dn
#      raise LDAP::ResultError::InappropriateAuthentication, "This server only supports anonymous bind"
#    end
#  end

end
end
