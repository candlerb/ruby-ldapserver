require 'ldap/server/result'
require 'ldap/server/match'

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
  #
  # If a schema is provided: attribute names are looked up in it to
  # find suitable matching rules. These are pushed in front of the array,
  # e.g.  [:eq, attr, val] becomes [MatchingRule, :eq, attr, val]; also the
  # attribute name will also be normalised to its first form as listed
  # in the schema, e.g. 'commonname' becomes 'cn', 'objectclass' becomes
  # 'objectClass' etc.

  class Filter

    # Parse a filter in OpenSSL::ASN1 format into our own format.
    #
    # There are some trivial optimisations we make: e.g.
    #   (&(objectclass=*)(cn=foo)) -> (&(cn=foo)) -> (cn=foo)

    def self.parse(asn1, schema=nil)
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
        if schema
          a = schema.find_attr(attr)
          return [:undef] unless a and a.equality
          return [a.equality, :eq, a.name, val]
        end
        return [:eq, attr, val]

      when 4 # substrings
        attr = asn1.value[0].value.downcase
        res = [:substrings, attr]
        if schema
          a = schema.find_attr(attr)
          return [:undef] unless a and a.substr
          res = [a.substr, :substrings, a.name]
        end
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
        attr = asn1.value[0].value.downcase
        val = asn1.value[1].value
        if schema
          a = schema.find_attr(attr)
          return [:undef] unless a and a.ordering
          return [a.ordering, :ge, a.name, val]
        end
        return [:ge, attr, val]

      when 6 # lessOrEqual
        attr = asn1.value[0].value.downcase
        val = asn1.value[1].value
        if schema
          a = schema.find_attr(attr)
          return [:undef] unless a and a.ordering
          return [a.ordering, :le, a.name, val]
        end
        return [:le, attr, val]

      when 7 # present
        attr = asn1.value.downcase
        return [:true] if attr == "objectclass"
        if schema
          a = schema.find_attr(attr)
          attr = a.name if a
        end
        return [:present, attr]

      when 8 # approxMatch
        attr = asn1.value[0].value.downcase
        val = asn1.value[1].value
        if schema
          a = schema.find_attr(attr)
          # I don't know how properly to deal with approxMatch. I'm assuming
          # that the object will have an equality MatchingRule, and we
          # can defer to that.
          return [a.equality, :approx, a.name, val] if a and a.equality
        end
        return [:approx, attr, val]

      #when 9 # extensibleMatch
      #  FIXME

      else
        raise ProtocolError, "Unrecognised Filter tag #{asn1.tag}"
      end
    end

    # Run a parsed filter against an attr=>[val] hash.
    #
    # Returns true, false or nil.

    def self.run(filter, av)

      # Quack! e.g. [duck, :eq, 'bar', '123'] sends duck.eq([vals], '123')
      # where [vals] are the values for attribute 'bar' in this entry
      if not filter[0].is_a?(Symbol) and filter[0].respond_to?(filter[1])
        return filter[0].send(filter[1], av[filter[2]], *filter[3..-1])
      end

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

      when :present
        return av.has_key?(filter[1])

      # Fallbacks for when there is no schema

      when :eq, :substrings, :ge, :le
        return LDAP::Server::MatchingRule::DefaultMatch.send(filter[0], av[filter[1]], *filter[2..-1])

      #when :approx
      #  I'm not sure how to deal with approx. No semantics are defined
      #  in RFC2251 (perhaps they are in X500?) So I've assumed that anyone
      #  who wants it will add a method to the equality MatchingRule for
      #  their attribute.

      when :true
        return true

      when :false
        return false

      when :undef
        return nil
      end

      raise OperationsError, "Unimplemented filter #{filter.first.inspect}"
    end

    module EqualityMatch
      def normalize(x)
        x
      end

      def eq(vals,m)
        m = normalize(m)
        vals.each { |v| return true if m == normalize(v) }
        return false
      end
    end



  end # class Filter
end # class Server
end # module LDAP
