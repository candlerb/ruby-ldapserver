require 'ldap/server/syntax'

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
	@syntax = LDAP::Server::Syntax.find(m[9])
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
        @oid
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
        if @names && @names[0]
          @names[0]
        else
          @oid
        end
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
          ans << "NAME '#{@names[0]}' "
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
          return "#{pfx}#{a[0]}#{sfx}"
        else
          return "#{pfx}( #{a.join(" $ ")} )#{sfx}"
        end
      end
    end # class ObjectClass

  end # class Schema

end # class Server
end # module LDAP
