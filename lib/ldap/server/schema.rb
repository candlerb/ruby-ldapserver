module LDAP
class Server

  class Schema

    def initialize
      @attr_types = {}		# name/alias => AttributeType instance
    end

    def add_attrtype(str)
      a = AttributeType.new(str)
      a.names.each do |n|
        @attr_types[n.downcase] = a
      end
    end

    class AttributeType
      NUMERICOID = '(\d[\d.]+\d)'
      QDESCR = '\s* \' [a-zA-Z][a-zA-Z0-9;-]* \' \s*'
      QDESCRS = "( #{QDESCR} | \\s* \\( (#{QDESCR})+ \\) \\s* )"
      QDSTRING = '\s* \' (.*?) \' \s*'
      WOID = '\s* ( [a-zA-Z][a-zA-Z0-9;-]* | \d[\d.]+\d ) \s*'
      NOIDLEN = '(\d[\d.]+\d) (\{\d+\})?'
      ATTRIBUTEUSAGE = '(userApplications|directoryOperation|distributedOperation|dSAOperation)'

      PARSER = %r! \A \s* \( \s*
	#{NUMERICOID} \s*
	( NAME #{QDESCRS} )?		# capture 2
        ( DESC #{QDSTRING} )?
        ( OBSOLETE \s* )?
        ( SUP #{WOID} )?
        ( EQUALITY #{WOID} )?
        ( ORDERING #{WOID} )?
        ( SUBSTR #{WOID} )?
        ( SYNTAX \s* #{NOIDLEN} \s* )?	# capture 2
        ( SINGLE-VALUE \s* )?
        ( COLLECTIVE \s* )?
        ( NO-USER-MODIFICATION \s* )?
        ( USAGE \s* #{ATTRIBUTEUSAGE} )?
        \s* \) \s* \z !xu

       attr_reader :oid, :names, :desc, :obsolete, :sup, :equality, :ordering
       attr_reader :substr, :syntax, :maxlen, :singlevalue, :collective
       attr_reader :nousermod, :usage

      def initialize(str)
        raise "Bad AttributeType #{str.inspect}" unless PARSER =~ str
        @oid = $1
	@desc = $6
	@obsolete = $7 && true
	@sup = $9
	@equality = $11
	@ordering = $13
	@substr = $15
	@syntax = $17
	@maxlen = $18
	@singlevalue = $19 && true
	@collective = $20 && true
	@nousermod = $21 && true
	@usage = $23 && $23.intern
        # do this last because it replaces last match variables
        @names = ($3||"").scan(/'(.*?)'/).flatten
      end

      def name
        @names.first
      end

      def to_s
        @oid
      end

      def to_def
        ans = "( #{@oid} "
        if not @names or @names.size == 0
          # nothing
        elsif @names.size == 1
          ans << "NAME '#{@names[0]}' "
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
      end
    end # class AttributeType

  end # class Schema

end # class Server
end # module LDAP
