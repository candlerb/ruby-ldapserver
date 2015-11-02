module LDAP
class Server

  class Request
    attr_accessor :connection, :typesOnly, :attributes, :rescount, :sizelimit

    # Object to handle a single LDAP request. This object is created on
    # every request by the router, and is passed as argument to the defined
    # routes.

    def initialize(connection, messageId)
      @connection = connection
      @respEnvelope = OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::Integer(messageId),
        # protocolOp,
        # controls [0] OPTIONAL,
      ])
      @schema = @connection.opt[:schema]
      @server = @connection.opt[:server]
      @rescount = 0
    end

    ##################################################
    ### Utility methods to send protocol responses ###
    ##################################################

    def send_LDAPMessage(protocolOp, opt={}) # :nodoc:
      @respEnvelope.value[1] = protocolOp
      if opt[:controls]
        @respEnvelope.value[2] = OpenSSL::ASN1::Set(opt[:controls], 0, :IMPLICIT, APPLICATION)
      else
        @respEnvelope.value.delete_at(2)
      end

      @connection.write(@respEnvelope.to_der)
    end

    def send_LDAPResult(tag, resultCode, opt={}) # :nodoc:
      seq = [
        OpenSSL::ASN1::Enumerated(resultCode),
        OpenSSL::ASN1::OctetString(opt[:matchedDN] || ""),
        OpenSSL::ASN1::OctetString(opt[:errorMessage] || ""),
      ]
      if opt[:referral]
        rs = opt[:referral].collect { |r| OpenSSL::ASN1::OctetString(r) }
        seq << OpenSSL::ASN1::Sequence(rs, 3, :IMPLICIT, :APPLICATION)
      end
      yield seq if block_given?   # opportunity to add more elements

      send_LDAPMessage(OpenSSL::ASN1::Sequence(seq, tag, :IMPLICIT, :APPLICATION), opt)
    end

    def send_BindResponse(resultCode, opt={})
      send_LDAPResult(1, resultCode, opt) do |resp|
        if opt[:serverSaslCreds]
          resp << OpenSSL::ASN1::OctetString(opt[:serverSaslCreds], 7, :IMPLICIT, :APPLICATION)
        end
      end
    end

    # Send a found entry. Avs are {attr1=>val1, attr2=>[val2,val3]}
    # If schema given, return operational attributes only if
    # explicitly requested

    def send_SearchResultEntry(dn, avs, opt={})
      @rescount += 1
      if @sizelimit
        raise LDAP::ResultError::SizeLimitExceeded if @rescount > @sizelimit
      end

      if @schema
        # normalize the attribute names
        @attributes = @attributes.map { |a| a == '*' ? a : @schema.find_attrtype(a).to_s }
      end

      sendall = @attributes == [] || @attributes.include?("*")
      avseq = []

      avs.each do |attr, vals|
        if !@attributes.include?(attr)
          next unless sendall
          if @schema
            a = @schema.find_attrtype(attr)
            next unless a and (a.usage.nil? or a.usage == :userApplications)
          end
        end

        if @typesOnly
          vals = []
        else
          vals = [vals] unless vals.kind_of?(Array)
          # FIXME: optionally do a value_to_s conversion here?
          # FIXME: handle attribute;binary
        end

        avseq << OpenSSL::ASN1::Sequence([
          OpenSSL::ASN1::OctetString(attr),
          OpenSSL::ASN1::Set(vals.collect { |v| OpenSSL::ASN1::OctetString(v.to_s) })
        ])
      end

      send_LDAPMessage(OpenSSL::ASN1::Sequence([
          OpenSSL::ASN1::OctetString(dn),
          OpenSSL::ASN1::Sequence(avseq),
        ], 4, :IMPLICIT, :APPLICATION), opt)
    end

    def send_SearchResultDone(resultCode, opt={})
      send_LDAPResult(5, resultCode, opt)
    end

    def send_ModifyResponse(resultCode, opt={})
      send_LDAPResult(7, resultCode, opt)
    end

    def send_AddResponse(resultCode, opt={})
      send_LDAPResult(9, resultCode, opt)
    end

    def send_DelResponse(resultCode, opt={})
      send_LDAPResult(11, resultCode, opt)
    end

    def send_ModifyDNResponse(resultCode, opt={})
      send_LDAPResult(13, resultCode, opt)
    end

    def send_CompareResponse(resultCode, opt={})
      send_LDAPResult(15, resultCode, opt)
    end

    def send_ExtendedResponse(resultCode, opt={})
      send_LDAPResult(24, resultCode, opt) do |resp|
        if opt[:responseName]
          resp << OpenSSL::ASN1::OctetString(opt[:responseName], 10, :IMPLICIT, :APPLICATION)
        end
        if opt[:response]
          resp << OpenSSL::ASN1::OctetString(opt[:response], 11, :IMPLICIT, :APPLICATION)
        end
      end
    end

    ############################################################
    ### Methods to get parameters related to this connection ###
    ############################################################

    # Server-set maximum time limit. Override for more complex behaviour
    # (e.g. limit depends on @connection.binddn). Nil uses hardcoded default.

    def server_timelimit
      @connection.opt[:timelimit]
    end

    # Server-set maximum size limit. Override for more complex behaviour
    # (e.g. limit depends on @connection.binddn). Return nil for unlimited.

    def server_sizelimit
      @connection.opt[:sizelimit]
    end

  end

end
end
