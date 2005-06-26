require 'ldap/server/result'

module LDAP
class Server

  # LDAP filters are parsed into a LISP-like internal representation:
  #
  #   [:true]
  #   [:false]
  #   [:undef]
  #   [:and, ..., ..., ...]
  #   [:or, ..., ..., ...]
  #   [:not, ...]
  #   [:eq, attr, val]
  #   [:substrings, attr, [:initial, val], [:any, val], [:final, val]]
  #   [:ge, attr, val]
  #   [:le, attr, val]
  #   [:present, attr]
  #   [:approx, attr, val]
  #
  # This is done rather than a more object-oriented approach, in the
  # hope that it will make it easier to match certain filter structures
  # when converting them into something else. e.g. certain LDAP filter
  # constructs can be mapped to some fixed SQL queries.
  #
  # See RFC 2251 4.5.1 for the three-state(!) boolean logic from LDAP

  class Filter

    # Parse a filter in OpenSSL::ASN1 format into our own format.
    #
    # There are some trivial optimisations we make: e.g.
    #   (&(objectclass=*)(cn=foo)) -> (&(cn=foo)) -> (cn=foo)

    def self.parse(asn1)
      case asn1.tag
      when 0 # and
        conds = asn1.value.collect { |a| parse(a) }
        conds.delete([:true])
        return [:true] if conds.size == 0
        return conds.first if conds.size == 1
        return [:false] if conds.include?([:false])
        return conds.unshift(:and)

      when 1 # or
        conds = asn1.value.collect { |a| parse(a) }
        conds.delete([:false])
        return [:false] if conds.size == 0
        return conds.first if conds.size == 1
        return [:true] if conds.include?([:true])
        return conds.unshift(:or)

      when 2 # not
        cond = parse(asn1.value[0])
        case cond
        when [:false];	return [:true]
	when [:true];	return [:false]
	when [:undef];	return [:undef]
	end
	return [:not, cond]

      when 3 # equalityMatch
        attr = asn1.value[0].value.downcase
        val = asn1.value[1].value
        return [:true] if attr == "objectclass" and val == "top"
        return [:eq, attr, val]

      when 4 # substrings
        res = [:substrings, asn1.value[0].value.downcase]
        asn1.value[1].value.each do |ss|
          case ss.tag
          when 0
            res << [:initial, ss.value]
          when 1
            res << [:any, ss.value]
          when 2
            res << [:final, ss.value]
          end
        end
        return res

      when 5 # greaterOrEqual
        return [:ge, asn1.value[0].value.downcase, asn1.value[1].value]

      when 6 # lessOrEqual
        return [:le, asn1.value[0].value.downcase, asn1.value[1].value]

      when 7 # present
        attr = asn1.value.downcase
        return [:true] if attr == "objectclass"
        return [:present, attr]

      when 8 # approxMatch
        return [:approx, asn1.value[0].value.downcase, asn1.value[1].value]

      #when 9 # extensibleMatch

      else
        raise ProtocolError, "Unrecognised Filter tag #{asn1.tag}"
      end
    end

    # Run a parsed filter against an attr=>[val] hash.
    #
    # Returns true, false or nil.

    def self.run(filter, av)
      case filter.first
      when :and
        res = true
        filter[1..-1].each do |elem|
          r = run(elem, av)
          return false if r == false
          res = nil if r.nil?
        end
        return res

      when :or
        res = false
        filter[1..-1].each do |elem|
          r = run(elem, av)
          return true if r == true
          res = nil if r.nil?
        end
        return res

      when :not
        case run(filter[1], av)
        when true; 	return false
        when false;	return true
        else		return nil
        end

      when :eq
        attr, val = filter[1], filter[2]
        x = av[attr]
        # RFC2251 is a bit ambiguous. We are supposed to return Undefined
        # (nil) if the attribute is "not recognised" by the server. Does
        # that mean there are no instances of this attribute, or that the
        # attribute is not in the schema? I think it's the latter.
        # So we can't check that condition without a schema lookup.
        return false if x.nil?
        x.each { |v| return true if v == val }
        return false

      when :substrings
        attr = filter[1]
        x = av[attr]
        return false if x.nil?
        x.each do |v|
          # return true unless one of the substring conditions does not match
          return true unless filter[2..-1].find do |type,str|
            case type
            when :initial
              not v.index(str) == 0
            when :any
              not v.index(str)
            when :final
              not v.index(str, -str.length)
            else
              raise ProtocolError, "Unrecognised substring tag #{type.inspect}"
            end
          end
        end
        return false

      when :ge
        attr, val = filter[1], filter[2]
        x = av[attr]
        return false if x.nil?
        x.each { |v| return true if v >= val }
        return false

      when :le
        attr, val = filter[1], filter[2]
        x = av[attr]
        return false if x.nil?
        x.each { |v| return true if v <= val }
        return false

      when :present
        return av.has_key?(filter[1])

      when :approx
        attr, val = filter[1], filter[2]
        x = av[attr]
        return false if x.nil?
        x.each { |v| return true if approxmatch(v, val) }
        return false

      when :true
        return true

      when :false
        return false

      when :undef
        return nil
      end

      raise OperationsError, "Unimplemented filter #{filter.first.inspect}"
    end

    # I don't see any standard 'approx match' semantics, so define this yourself:

    #def self.approxmatch(a,b)
    #end
  end # class Filter
end # class Server
end # module LDAP

