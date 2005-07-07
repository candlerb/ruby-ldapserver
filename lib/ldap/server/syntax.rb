module LDAP
class Server

  # A class which describes LDAP SyntaxDescriptions. For now there is
  # a global pool of Syntax objects (rather than each Schema object
  # having its own pool)

  class Syntax
    attr_reader :oid, :hr, :desc

    # Create a new Syntax object

    def initialize(oid, desc=nil, hr=false, re=nil)
      @oid = oid
      @desc = desc
      @hr = hr	# human-readable?
      @re = re  # regular expression for parsing
      @def = nil
    end

    def to_s
      @oid
    end

    # Create a new Syntax object, given its description string

    def self.from_def(str, *args)
      m = LDAPSyntaxDescription.match(str)
      raise "Bad SyntaxTypeDescription #{str.inspect}" unless m
      new(m[1], m[2], *args)
    end

    # Convert this object to its description string

    def to_def
      return @def if @def
      ans = "( #@oid "
      ans << "DESC '#@desc' " if @desc
      ans << ")"
      @def = ans
    end

    # Return true or a MatchData object if the given value is allowed
    # by this syntax

    def match(val)
      return true if @re.nil?
      @re.match(value_to_s(val))
    end

    # Convert a value for this syntax into its canonical string representation

    def value_to_s(val)
      val.to_s
    end

    # Convert a string value for this syntax into a Ruby-like value

    def value_from_s(val)
      val
    end

    @@syntaxes = {}

    # Add a new syntax definition

    def self.add(*args)
      s = new(*args)
      @@syntaxes[s.oid] = s
    end

    # Find a Syntax object given an oid. If not known, return a new empty
    # Syntax object associated with this oid.

    def self.find(oid)
      return oid if oid.nil? or oid.is_a?(LDAP::Server::Syntax)
      return @@syntaxes[oid] if @@syntaxes[oid]
      add(oid)
    end

    # Shared constants for regexp-based syntax parsers

    KEYSTR = "[a-zA-Z][a-zA-Z0-9;-]*"
    NUMERICOID = "( \\d[\\d.]+\\d )"
    WOID = "\\s* ( #{KEYSTR} | \\d[\\d.]+\\d ) \\s*"
    _WOID = "\\s* (?: #{KEYSTR} | \\d[\\d.]+\\d ) \\s*"
    OIDS = "( #{_WOID} | \\s* \\( #{_WOID} (?: \\$ #{_WOID} )* \\) \\s* )"
    _QDESCR = "\\s* ' #{KEYSTR} ' \\s*"
    QDESCRS = "( #{_QDESCR} | \\s* \\( (?:#{_QDESCR})+ \\) \\s* )"
    QDSTRING = "\\s* ' (.*?) ' \\s*"
    NOIDLEN = "(\\d[\\d.]+\\d) (?: \\{ (\\d+) \\} )?"
    ATTRIBUTEUSAGE = "(userApplications|directoryOperation|distributedOperation|dSAOperation)"

  end

  class Syntax

    # These are the 'SHOULD' support syntaxes from RFC2252 section 6

    AttributeTypeDescription =
    add("1.3.6.1.4.1.1466.115.121.1.3", "Attribute Type Description", true,
    %r! \A \s* \( \s*
	    #{NUMERICOID} \s*
	(?: NAME #{QDESCRS} )?
	(?: DESC #{QDSTRING} )?
	(   OBSOLETE \s* )?
	(?: SUP #{WOID} )?
	(?: EQUALITY #{WOID} )?
	(?: ORDERING #{WOID} )?
	(?: SUBSTR #{WOID} )?
	(?: SYNTAX \s* #{NOIDLEN} \s* )?	# capture 2
	(   SINGLE-VALUE \s* )?
	(   COLLECTIVE \s* )?
	(   NO-USER-MODIFICATION \s* )?
	(?: USAGE \s* #{ATTRIBUTEUSAGE} )?
    \s* \) \s* \z !xu)

    add("1.3.6.1.4.1.1466.115.121.1.5", "Binary", false)
    # FIXME: value_to_s should BER-encode the value??

    add("1.3.6.1.4.1.1466.115.121.1.6", "Bit String", true, /\A'([01]*)'B\z/)
    # FIXME: convert to FixNum?

    o = add("1.3.6.1.4.1.1466.115.121.1.7", "Boolean", true, /\A(TRUE|FALSE)\z/)
    def o.value_to_s(v)
      return v if v.is_a?(string)
      v ? "TRUE" : "FALSE"
    end
    def o.value_from_s(v)
      v.upcase == "TRUE"
    end

    add("1.3.6.1.4.1.1466.115.121.1.8", "Certificate", false)
    add("1.3.6.1.4.1.1466.115.121.1.9", "Certificate List", false)
    add("1.3.6.1.4.1.1466.115.121.1.10", "Certificate Pair", false)
    add("1.3.6.1.4.1.1466.115.121.1.11", "Country String", true, /\A[A-Z]{2}\z/)
    add("1.3.6.1.4.1.1466.115.121.1.12", "DN", true)
    # FIXME: validate DN?
    add("1.3.6.1.4.1.1466.115.121.1.15", "Directory String", true)
    # missed due to lack of interest: "DIT Content Rule Description"
    add("1.3.6.1.4.1.1466.115.121.1.22", "Facsimile Telephone Number", true)
    add(" 1.3.6.1.4.1.1466.115.121.1.23", "Fax", false)
    add("1.3.6.1.4.1.1466.115.121.1.24", "Generalized Time", true)
    # FIXME: Validate Generalized Time (find X.208) and convert to/from Ruby
    add("1.3.6.1.4.1.1466.115.121.1.26", "IA5 String", true)
    o = add("1.3.6.1.4.1.1466.115.121.1.27", "Integer", true, /\A\d+\z/)
    def o.value_from_s(v)
      v.to_i
    end
    add("1.3.6.1.4.1.1466.115.121.1.28", "JPEG", false)
    add("1.3.6.1.4.1.1466.115.121.1.30", "Matching Rule Description", true,
    %r! \A \s* \( \s*
	    #{NUMERICOID} \s*
	(?: NAME #{QDESCRS} )?
	(?: DESC #{QDSTRING} )?
	(   OBSOLETE \s* )?
	    SYNTAX \s* #{NUMERICOID} \s*
    \s* \) \s* \z !xu)
    add("1.3.6.1.4.1.1466.115.121.1.31", "Matching Rule Use Description", true,
    %r! \A \s* \( \s*
	    #{NUMERICOID} \s*
	(?: NAME #{QDESCRS} )?
	(?: DESC #{QDSTRING} )?
	(   OBSOLETE \s* )?
	    APPLIES \s* #{OIDS} \s*
    \s* \) \s* \z !xu)
    add("1.3.6.1.4.1.1466.115.121.1.33", "MHS OR Address", true)
    add("1.3.6.1.4.1.1466.115.121.1.34", "Name and Optional UID", true)
    # missed due to lack of interest: "Name Form Description"
    add("1.3.6.1.4.1.1466.115.121.1.36", "Numeric String", true, /\A\d+\z/)
    ObjectClassDescription =
    add("1.3.6.1.4.1.1466.115.121.1.37", "Object Class Description", true,
    %r! \A \s* \( \s*
	#{NUMERICOID} \s*
	(?: NAME #{QDESCRS} )?
	(?: DESC #{QDSTRING} )?
	(   OBSOLETE \s* )?
	(?: SUP #{OIDS} )?
	(?: ( ABSTRACT|STRUCTURAL|AUXILIARY ) \s* )?
	(?: MUST #{OIDS} )?
	(?: MAY #{OIDS} )?
    \s* \) \s* \z !xu)
    add("1.3.6.1.4.1.1466.115.121.1.38", "OID", true, /\A#{WOID}\z/)
    add("1.3.6.1.4.1.1466.115.121.1.39", "Other Mailbox", true)
    o = add("1.3.6.1.4.1.1466.115.121.1.41", "Postal Address", true)
    def o.value_from_s(v)
      v.split(/\$/)
    end
    def o.value_to_s(v)
      return v.join("$") if v.is_a?(Array)
      return v
    end
    add("1.3.6.1.4.1.1466.115.121.1.43", "Presentation Address", true)
    add("1.3.6.1.4.1.1466.115.121.1.44", "Printable String", true)
    add("1.3.6.1.4.1.1466.115.121.1.50", "Telephone Number", true)
    add("1.3.6.1.4.1.1466.115.121.1.53", "UTC Time", true)

    LDAPSyntaxDescription =
    add("1.3.6.1.4.1.1466.115.121.1.54", "LDAP Syntax Description", true,
    %r! \A \s* \( \s*
	    #{NUMERICOID} \s*
	(?: DESC #{QDSTRING} )?
    \s* \) \s* \z !xu)

    # Missed due to lack of interest: "DIT Structure Rule Description"

    # A few others from RFC2252 section 4.3.2
    add("1.3.6.1.4.1.1466.115.121.1.4", "Audio", false)
    add("1.3.6.1.4.1.1466.115.121.1.40", "Octet String", true)
  end    
    
end # class Server
end # module LDAP
