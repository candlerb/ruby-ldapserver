module LDAPserver

  class Operation

    # Return true if connection is not authenticated

    def anonymous?
      @connection.binddn.nil?
    end

    # Split dn into its component parts. This is pretty horrible legacy
    # stuff from X500; see RFC2253 for the full gore. It's stupid that
    # the LDAP protocol sends the DN in string form, rather than in
    # ASN1 form (as it does with search filters, for example), even though
    # the DN syntax is defined in ASN1!
    #
    # Nothing is done for case-sensitivity. If your attributes and values
    # are case-insensitive (as they usually are), you need to downcase them.
    #
    # Note that only v2 clients should add extra space around the comma.
    #
    # I haven't implemented any special checks for the multivalued RDN
    # (attr1=val1+attr2=val2) nonsense. It's not clear to me whether the
    # specs require that these two DNs are treated as identical:
    #    OU=Sales+CN=J. Smith,O=Widget Inc.,C=US
    #    CN=J. Smith+OU=Sales,O=Widget Inc.,C=US
    #
    # FIXME: These methods are also broken w.r.t. UTF8 handling
    #
    # FIXME: An example in RFC2253 suggests that carriage-return
    # can be escaped to \0D, without explaining exactly which
    # characters NEED to be escaped in this way. Argh!!

    def split_dn(dn)
      # convert \\ to \x5c, \+ to \x2b etc
      dn2 = dn.gsub(/\\([^a-fA-F0-9])/) { |x| "\\x%02x" % x[0] }

      # Now we know that \\ and \, do not exist, it's safe to split
      parts = dn2.split(/\s*,\s*/)

      # And now we can decode the parts
      parts.each do |p|
        p.gsub!(/\\x([a-f0-9][a-f0-9])/i) { |x| x.hex.chr }
      end

      return parts
    end

    def join_dn(dn)
      dn = ""
      dn.each do |part|
        dn << "," if dn != ""
        dn << part.gsub(/^([# ])/, /\\\1/).
                   gsub(/( )$/, /\\\1/).
                   gsub(/([,+"\\<>;])/, /\\\1/)
      end
      return dn
    end
  end # class Operation
end # module LDAPserver

