require 'ldap/server/dn'
require 'ldap/server/util'
require 'ldap/server/trie'
require 'ldap/server/request'
require 'ldap/server/filter'

module LDAP
class Router
  @logger
  @routes

  # Scope
  BaseObject    = 0
  SingleLevel   = 1
  WholeSubtree  = 2

  # DerefAliases
  NeverDerefAliases   = 0
  DerefInSearching    = 1
  DerefFindingBaseObj = 2
  DerefAlways         = 3

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

  def log(e, level)
    @logger.send level, e.message
    e.backtrace.each { |line| @logger.send level, "\tfrom#{line}" }

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


  ####################################################
  ### Methods to parse and route each request type ###
  ####################################################

  def parse_route(dn, method)
    route, action = @routes.match("#{dn},op=#{method.to_s}")
    if action.nil?
      @logger.error "Route #{route} has no action!"
      raise LDAP::ResultError::UnwillingToPerform
    end

    class_name = action.split('#').first
    method_name = action.split('#').last

    params = LDAP::Server::DN.new("#{dn},op=#{method.to_s}").parse(route)

    return class_name, method_name, params
  end

  def do_bind(connection, messageId, protocolOp, controls) # :nodoc:
    request = Request.new(connection, messageId)
    version = protocolOp.value[0].value
    dn = protocolOp.value[1].value
    dn = nil if dn.empty?
    authentication = protocolOp.value[2]

    # Find a route in the routing tree
    class_name, method_name, params = parse_route(dn, :bind)

    case authentication.tag   # tag_class == :CONTEXT_SPECIFIC (check why)
    when 0
      Object.const_get(class_name).send method_name, request, version, dn, authentication.value, params
    when 3
      mechanism = authentication.value[0].value
      credentials = authentication.value[1].value
      # sasl_bind(version, dn, mechanism, credentials)
      # FIXME: needs to exchange further BindRequests
      # route_sasl_bind(request, version, dn, mechanism, credentials)
      raise LDAP::ResultError::AuthMethodNotSupported
    else
      raise LDAP::ResultError::ProtocolError, "BindRequest bad AuthenticationChoice"
    end
    request.send_BindResponse(0)
    return dn, version
  rescue NoMethodError => e
    log e, :error
    request.send_BindResponse(LDAP::ResultError::OperationsError.new.to_i, :errorMessage => e.message)
    return nil, version
  rescue LDAP::ResultError => e
    request.send_BindResponse(e.to_i, :errorMessage => e.message)
    return nil, version
  end

  def do_search(connection, messageId, protocolOp, controls) # :nodoc:
    request = Request.new(connection, messageId)
    server = connection.opt[:server]
    schema = connection.opt[:schema]
    baseObject = protocolOp.value[0].value
    scope = protocolOp.value[1].value
    deref = protocolOp.value[2].value
    client_sizelimit = protocolOp.value[3].value
    client_timelimit = protocolOp.value[4].value.to_i
    request.typesOnly = protocolOp.value[5].value
    filter = LDAP::Server::Filter::parse(protocolOp.value[6], schema)
    request.attributes = protocolOp.value[7].value.collect {|x| x.value}

    sizelimit = request.server_sizelimit
    sizelimit = client_sizelimit if client_sizelimit > 0 and
                 (sizelimit.nil? or client_sizelimit < sizelimit)
    request.sizelimit = sizelimit

    if baseObject.empty? and scope == BaseObject
      request.send_SearchResultEntry("", server.root_dse) if
        server.root_dse and LDAP::Server::Filter.run(filter, server.root_dse)
      request.send_SearchResultDone(0)
      return
    elsif schema and baseObject == schema.subschema_dn
      request.send_SearchResultEntry(baseObject, schema.subschema_subentry) if
        schema and schema.subschema_subentry and
        LDAP::Server::Filter.run(filter, schema.subschema_subentry)
      request.send_SearchResultDone(0)
      return
    end

    t = request.server_timelimit || 10
    t = client_timelimit if client_timelimit > 0 and client_timelimit < t

    # Find a route in the routing tree
    class_name, method_name, params = parse_route(baseObject, :search)

    Timeout::timeout(t, LDAP::ResultError::TimeLimitExceeded) do
      Object.const_get(class_name).send method_name, request, baseObject, scope, deref, filter, params
    end
    request.send_SearchResultDone(0)

  # Note that TimeLimitExceeded is a subclass of LDAP::ResultError
  rescue LDAP::ResultError => e
    request.send_SearchResultDone(e.to_i, :errorMessage=>e.message)

  rescue Abandon
    # send no response

  # Since this Operation is running in its own thread, we have to
  # catch all other exceptions. Otherwise, in the event of a programming
  # error, this thread will silently terminate and the client will wait
  # forever for a response.

  rescue Exception => e
    log e, :error
    request.send_SearchResultDone(LDAP::ResultError::OperationsError.new.to_i, :errorMessage=>e.message)
  end


  ###########################################################
  ### Methods to actually perform the work requested      ###
  ### Use the signatures below to write your own handlers ###
  ###########################################################

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

    # Handle a search request
    #
    # Call request. send_SearchResultEntry for each result found. Raise
    # an exception if there is a problem. timeLimit, sizeLimit and
    # typesOnly are taken care of, but you need to perform all
    # authorisation checks yourself, using @connection.binddn

#    def search(basedn, scope, deref, filter)
#      debug "search(#{basedn}, #{scope}, #{deref}, #{filter})"
#      raise LDAP::ResultError::UnwillingToPerform, "search not implemented"
#    end
end
end
