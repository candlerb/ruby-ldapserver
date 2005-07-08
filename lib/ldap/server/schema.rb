require 'ldap/server/syntax'
require 'ldap/server/result'

module LDAP
class Server

  class Schema

    def initialize
      @attrtypes = {}		# name/alias => AttributeType instance
      @objectclasses = {}
    end

    # Add an AttributeType to the schema

    def add_attrtype(str)
      a = AttributeType.new(str)
      @attrtypes[a.oid] = a if a.oid
      a.names.each do |n|
        @attrtypes[n.downcase] = a
      end
    end

    # Locate an attributetype object by name/alias/oid (or raise exception)

    def find_attrtype(n)
      return n if n.nil? or n.is_a?(LDAP::Server::Schema::AttributeType)
      r = @attrtypes[n.downcase]
      raise LDAP::Server::UndefinedAttributeType, "Unknown AttributeType #{n.inspect}" unless r
      r
    end

    # Return array of all AttributeType objects in this schema

    def all_attrtypes
      @attrtypes.values.uniq
    end

    # Add an ObjectClass to the schema

    def add_objectclass(str)
      o = ObjectClass.new(str)
      @objectclasses[o.oid] = o if o.oid
      o.names.each do |n|
        @objectclasses[n.downcase] = o
      end
    end

    # Locate an objectclass object by name/alias/oid (or raise exception)

    def find_objectclass(n)
      return n if n.nil? or n.is_a?(LDAP::Server::Schema::ObjectClass)
      r = @objectclasses[n.downcase]
      raise LDAP::Server::ObjectClassViolation, "Unknown ObjectClass #{n.inspect}" unless r
      r
    end

    # Return array of all ObjectClass objects in this schema

    def all_objectclasses
      @objectclasses.values.uniq
    end

    # Load an OpenLDAP-format schema from a named file (see notes under 'load')

    def load_file(filename)
      File.open(filename) { |f| load(f) }
    end

    # Load an OpenLDAP-format schema from a string or IO object (anything
    # which responds to 'each_line'). Lines starting 'attributetype'
    # or 'objectclass' contain one of those objects. Does not implement
    # named objectIdentifier prefixes (used in the dyngroup.schema file
    # supplied with openldap, but not documented in RFC2252)

    def load(str_or_io)
      meth = :junk_line
      data = ""
      str_or_io.each_line do |line|
        case line
        when /^\s*#/, /^\s*$/
          next
        when /^objectclass\s*(.*)$/i
          send(meth, data)
          meth = :add_objectclass
          data = $1
        when /^attributetype\s*(.*)$/i
          send(meth, data)
          meth = :add_attrtype
          data = $1
        else
          data << line
        end
      end
      send(meth,data)
      self
    end

    def junk_line(data)
      return if data.empty?
      raise LDAP::Server::InvalidAttributeSyntax,
        "Expected 'attributetype' or 'objectclass', got #{data}"
    end
    private :junk_line

    # Load in the base set of objectclasses and attributetypes, being
    # the same set as OpenLDAP preloads internally. Includes objectclasses
    # 'top', 'objectclass'; attributetypes 'objectclass' , 'cn',
    # 'userPassword' and 'distinguishedName'; plus extras needed for
    # publishing a v3 schema via LDAP

    def load_base
      load(<<EOS)
attributetype ( 1.3.6.1.4.1.250.1.57 NAME 'labeledURI' DESC 'RFC2079: Uniform Resource Identifier with optional label' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 2.5.4.35 NAME 'userPassword' DESC 'RFC2256/2307: password of user' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{128} )
attributetype ( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC2256: common name(s) for which the entity is known by' SUP name )
attributetype ( 2.5.4.41 NAME 'name' DESC 'RFC2256: common supertype of name attributes' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )
attributetype ( 2.5.4.49 NAME 'distinguishedName' DESC 'RFC2256: common supertype of DN attributes' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributetype ( 2.16.840.1.113730.3.1.34 NAME 'ref' DESC 'namedref: subordinate referral URL' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE distributedOperation )
attributetype ( 2.5.4.1 NAME ( 'aliasedObjectName' 'aliasedEntryName' ) DESC 'RFC2256: name of aliased object' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.1466.101.120.16 NAME 'ldapSyntaxes' DESC 'RFC2252: LDAP syntaxes' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.54 USAGE directoryOperation )
attributetype ( 2.5.21.8 NAME 'matchingRuleUse' DESC 'RFC2252: matching rule uses' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.31 USAGE directoryOperation )
attributetype ( 2.5.21.6 NAME 'objectClasses' DESC 'RFC2252: object classes' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 USAGE directoryOperation )
attributetype ( 2.5.21.5 NAME 'attributeTypes' DESC 'RFC2252: attribute types' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 USAGE directoryOperation )
attributetype ( 2.5.21.4 NAME 'matchingRules' DESC 'RFC2252: matching rules' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.30 USAGE directoryOperation )
attributetype ( 1.3.6.1.1.5 NAME 'vendorVersion' DESC 'RFC3045: version of implementation' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )
attributetype ( 1.3.6.1.1.4 NAME 'vendorName' DESC 'RFC3045: name of implementation vendor' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )
attributetype ( 1.3.6.1.4.1.4203.1.3.5 NAME 'supportedFeatures' DESC 'features supported by the server' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )
attributetype ( 1.3.6.1.4.1.1466.101.120.14 NAME 'supportedSASLMechanisms' DESC 'RFC2252: supported SASL mechanisms' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE dSAOperation )
attributetype ( 1.3.6.1.4.1.1466.101.120.15 NAME 'supportedLDAPVersion' DESC 'RFC2252: supported LDAP versions' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 USAGE dSAOperation )
attributetype ( 1.3.6.1.4.1.1466.101.120.7 NAME 'supportedExtension' DESC 'RFC2252: supported extended operations' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )
attributetype ( 1.3.6.1.4.1.1466.101.120.13 NAME 'supportedControl' DESC 'RFC2252: supported controls' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )
attributetype ( 1.3.6.1.4.1.1466.101.120.5 NAME 'namingContexts' DESC 'RFC2252: naming contexts' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 USAGE dSAOperation )
attributetype ( 1.3.6.1.4.1.1466.101.120.6 NAME 'altServer' DESC 'RFC2252: alternative servers' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 USAGE dSAOperation )
attributetype ( 2.5.18.10 NAME 'subschemaSubentry' DESC 'RFC2252: name of controlling subschema entry' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.18.9 NAME 'hasSubordinates' DESC 'X.501: entry has children' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.18.4 NAME 'modifiersName' DESC 'RFC2252: name of last modifier' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.18.3 NAME 'creatorsName' DESC 'RFC2252: name of creator' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.18.2 NAME 'modifyTimestamp' DESC 'RFC2252: time which object was last modified' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.18.1 NAME 'createTimestamp' DESC 'RFC2252: time which object was created' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.21.9 NAME 'structuralObjectClass' DESC 'X.500(93): structural object class of entry' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.4.0 NAME 'objectClass' DESC 'RFC2256: object classes of the entity' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
# These ones aren't published by OpenLDAP, but are referenced by the 'subschema' objectclass
attributetype ( 2.5.21.1 NAME 'dITStructureRules' EQUALITY integerFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.17 USAGE directoryOperation )
attributetype ( 2.5.21.7 NAME 'nameForms' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.35 USAGE directoryOperation )
attributetype ( 2.5.21.2 NAME 'dITContentRules' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.16 USAGE directoryOperation )

objectclass ( 2.5.20.1 NAME 'subschema' DESC 'RFC2252: controlling subschema (sub)entry' AUXILIARY MAY ( dITStructureRules $ nameForms $ ditContentRules $ objectClasses $ attributeTypes $ matchingRules $ matchingRuleUse ) )
#Don't have definition for subtreeSpecification:
#objectClass ( 2.5.17.0 NAME 'subentry' SUP top STRUCTURAL MUST ( cn $ subtreeSpecification ) )
objectClass ( 1.3.6.1.4.1.4203.1.4.1 NAME ( 'OpenLDAProotDSE' 'LDAProotDSE' ) DESC 'OpenLDAP Root DSE object' SUP top STRUCTURAL MAY cn )
objectClass ( 2.16.840.1.113730.3.2.6 NAME 'referral' DESC 'namedref: named subordinate referral' SUP top STRUCTURAL MUST ref )
objectClass ( 2.5.6.1 NAME 'alias' DESC 'RFC2256: an alias' SUP top STRUCTURAL MUST aliasedObjectName )
objectClass ( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject' DESC 'RFC2252: extensible object' SUP top AUXILIARY )
objectClass ( 2.5.6.0 NAME 'top' DESC 'top of the superclass chain' ABSTRACT MUST objectClass )
EOS
    end

    # After loading object classes and attrs: resolve oid strings to point
    # to objects. This will expose schema inconsistencies (e.g. objectclass
    # has unknown SUP class or points to unknown attributeType). However,
    # unknown Syntaxes just create new Syntax objects.

    def resolve_oids

      all_attrtypes.each do |a|
        a.instance_eval { @syntax = LDAP::Server::Syntax.find(@syntax) }
        if a.sup
          s = find_attrtype(a.sup)
          a.instance_eval {
            @sup = s
            # ??? inherit properties (FIXME: This breaks to_def)
            @equality ||= s.equality
            @ordering ||= s.ordering
            @substr ||= s.substr
            @syntax ||= s.syntax
            @maxlen ||= s.maxlen
            @singlevalue ||= s.singlevalue
            @collective ||= s.collective
            @nousermod ||= s.nousermod
            @usage ||= s.usage
          }
        end
        # TODO: equality, ordering, substr
      end

      all_objectclasses.each do |o|
        if o.sup
          s = o.sup.collect { |ss| find_objectclass(ss) }
          o.instance_eval { @sup = s }
        end
        if o.must
          s = o.must.collect { |ss| find_attrtype(ss) }
          o.instance_eval { @must = s }
        end
        if o.may
          s = o.may.collect { |ss| find_attrtype(ss) }
          o.instance_eval { @may = s }
        end
      end

    end

    # Validate an AV-hash {attr=>[vals], attr=>[vals], ...}
    # where attr are attribute names, and vals are all strings, e.g.
    # as provided by an LDAP client.
    # Return a new hash where 'attr' has been replaced by the canonical
    # name of the attribute. If 'normalize' is true then the values are
    # converted into their nearest-equivalent Ruby classes. The
    # objectClass attribute always has any missing superclasses added;
    # if 'normalize' then you get an array of ObjectClass objects.

    def validate(av, normalize=false)
      oc = nil
      res = {}
      got_attr = {}
      av.each do |attr,vals|
        vals = [] if vals.nil?
        vals = [vals] unless vals.is_a?(Array)
        attr = find_attr(attr)
        got_attr[attr] = true

        # FIXME: I don't know if these are the right results to return
        # for the various types of validation errors

        raise LDAP::Server::ObjectClassViolation,
          "Attribute #{attr} is SINGLE-VALUE" if attr.singlevalue and vals.size != 1

        if attr.name == 'objectClass'
          oc = vals.collect do |val|
            find_objectclass(val)
          end
        else
          v2 = []
          vals.each do |val|
            # ?? should we always reject val.nil? and val == ""
            raise LDAP::Server::ConstraintViolation,
              "Cannot modify #{attr}" if attr.nousermod
            raise LDAP::Server::InvalidAttributeSyntax,
              "Bad value for #{attr}: #{val.inspect}" if attr.syntax and ! attr.syntax.match(val)
            raise LDAP::Server::InvalidAttributeSyntax,
              "Value too long for #{attr}" if attr.maxlen and val.length > attr.maxlen
            v2 << attr.value_from_s(val) if normalize
          end
          res[attr.name] = normalize ? v2 : vals
        end
      end

      # Now do objectClass checks.
      unless oc
        raise LDAP::Server::ObjectClassViolation,
          "objectClass attribute missing"
      end

      # Add superior objectClasses (note: growing an array while you
      # iterate over it seems to work in ruby-1.8.2 anyway!)
      oc.each do |objectclass|
        objectclass.sup.each do |s|
          oc.push(s) unless oc.include?(s)
        end
      end
      res['objectClass'] = normalize ? oc : oc.collect { |oo| oo.to_s }

      # Ensure that all MUST attributes are present
      allow_attr = {}
      oc.each do |objectclass|
        objectclass.must.each do |m|
          unless got_attr[m]
            raise LDAP::Server::ObjectClassViolation,
              "Attribute #{attr} missing required by objectClass #{objectclass}"
          end
          allow_attr[m] = true
        end
        objectclass.may.each do |m|
          allow_attr[m] = true
        end
      end

      # Now check all the attributes given are permitted by MUST or MAY
      got_attr.each do |attr,dummy|
        unless allow_attr[attr]
          raise LDAP::Server::ObjectClassViolation, "Attribute #{attr} not permitted by objectClass"
        end
      end

      res
    end

    #####################################################################

    # Class holding an instance of an AttributeTypeDescription (RFC2252 4.2)

    class AttributeType

      attr_reader :oid, :names, :desc, :obsolete, :sup, :equality, :ordering
      attr_reader :substr, :syntax, :maxlen, :singlevalue, :collective
      attr_reader :nousermod, :usage

      def initialize(str)
        m = LDAP::Server::Syntax::AttributeTypeDescription.match(str)
        raise "Bad AttributeTypeDescription #{str.inspect}" unless m
        @oid = m[1]
        @names = (m[2]||"").scan(/'(.*?)'/).flatten
	@desc = m[3]
	@obsolete = ! m[4].nil?
	@sup = m[5]
	@equality = m[6]
	@ordering = m[7]
	@substr = m[8]
	@syntax = m[9]
	@maxlen = m[10] && m[10].to_i
	@singlevalue = ! m[11].nil?
	@collective = ! m[12].nil?
	@nousermod = ! m[13].nil?
	@usage = m[14] && m[14].intern
        # This is the cache of the stringified version. Rather than
        # initialize to str, we set nil to force it to be rebuilt
        @def = nil
      end

      def name
        @names.first
      end

      def to_s
        (@names && @names.first) || @oid
      end

      def changed
        @def = nil
      end

      def to_def
        return @def if @def
        ans = "( #{@oid} "
        if @names.nil? or @names.empty?
          # nothing
        elsif @names.size == 1
          ans << "NAME '#{@names.first}' "
        else
          ans << "NAME ( "
          @names.each { |n| ans << "'#{n}' " }
          ans << ") "
        end
        ans << "DESC '#{@desc}' " if @desc
        ans << "OBSOLETE " if @obsolete
        ans << "SUP #{@sup} " if @sup			# oid
        ans << "EQUALITY #{@equality} " if @equality	# oid
        ans << "ORDERING #{@ordering} " if @ordering	# oid
        ans << "SUBSTR #{@substr} " if @substr		# oid
        ans << "SYNTAX #{@syntax}#{@maxlen && "{#{@maxlen}}"} " if @syntax
        ans << "SINGLE-VALUE " if @singlevalue
        ans << "COLLECTIVE " if @collective
        ans << "NO-USER-MODIFICATION " if @nousermod
        ans << "USAGE #{@usage} " if @usage
        ans << ")"
        @def = ans
      end
    end # class AttributeType

    #####################################################################

    # Class holding an instance of an ObjectClassDescription (RFC2252 4.4)

    class ObjectClass

      attr_reader :oid, :names, :desc, :obsolete, :sup, :struct, :must, :may

      SCAN_WOID = /#{LDAP::Server::Syntax::WOID}/x

      def initialize(str)
        m = LDAP::Server::Syntax::ObjectClassDescription.match(str)
        raise "Bad ObjectClassDescription #{str.inspect}" unless m
        @oid = m[1]
        @names = (m[2]||"").scan(/'(.*?)'/).flatten
	@desc = m[3]
	@obsolete = ! m[4].nil?
	@sup = (m[5]||"").scan(SCAN_WOID).flatten
        @struct = m[6] ? m[6].downcase.intern : :structural
        @must = (m[7]||"").scan(SCAN_WOID).flatten
        @may = (m[8]||"").scan(SCAN_WOID).flatten
        @def = nil
      end

      def name
        @names.first
      end

      def to_s
        (@names && @names.first) || @oid
      end

      def changed
        @def = nil
      end

      def to_def
        return @def if @def
        ans = "( #{@oid} "
        if @names.nil? or @names.empty?
          # nothing
        elsif @names.size == 1
          ans << "NAME '#{@names.first}' "
        else
          ans << "NAME ( "
          @names.each { |n| ans << "'#{n}' " }
          ans << ") "
        end
        ans << "DESC '#{@desc}' " if @desc
        ans << "OBSOLETE " if @obsolete
        ans << joinoids("SUP ",@sup," ")
        ans << "#{@struct.to_s.upcase} " if @struct
        ans << joinoids("MUST ",@must," ")
        ans << joinoids("MAY ",@may," ")
        ans << ")"
        @def = ans
      end

      def joinoids(pfx,arr,sfx)
        return "" unless arr and !arr.empty?
        return "#{pfx}#{arr}#{sfx}" unless arr.is_a?(Array)
        a = arr.collect { |elem| elem.to_s }
        if a.size == 1
          return "#{pfx}#{a.first}#{sfx}"
        else
          return "#{pfx}( #{a.join(" $ ")} )#{sfx}"
        end
      end
    end # class ObjectClass

  end # class Schema

end # class Server
end # module LDAP
