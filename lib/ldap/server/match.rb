module LDAP
class Server

  class MatchingRule
    @@rules = {}    # oid / name / alias => object

    def find(x)
      @@rules[x]
    end

    def all
      r = @@rules.values
      r.uniq!
      r
    end

    def initialize(oid, names, syntax)
      @oid = oid
      @names = names
      @names = [@names] unless @names.is_a?(Array)
      @syntax = syntax
      @def = nil

      # Maintain index
      @@rules[@oid] = self
      @names.each { |n| @@rules[n.downcase] = self }
    end

    def name
      (@names && names[0]) || @oid
    end

    def to_def
      return @def if @def
      ans = "( #{@oid} "
      if names.nil? or @names.empty?
        # nothing
      elsif @names.size == 1
        ans << "NAME '#{@names[0]}' "
      else
        ans << "NAME ( "
        @names.each { |n| ans << "'#{n}' " }
        ans << ") "
      end
      ans << "SYNTAX #{@syntax} " if @syntax
      ans << ")"
      @def = ans
    end

    def normalize(x)
      x
    end

    # Now some things we can mixin to a MatchingRule when needed.
    # Replace 'normalize' with a function which gives the canonical
    # version of a value for comparison.

    module Equality
      def eq(vals, m)
        return false if vals.nil?
        m = normalize(m)
        vals.each { |v| return true if normalize(v) == m }
        return false
      end
    end

    module Ordering
      def ge(vals, m)
        return false if vals.nil?
        m = normalize(m)
        vals.each { |v| return true if normalize(v) >= m }
        return false
      end

      def le(vals, m)
        return false if vals.nil?
        m = normalize(m)
        vals.each { |v| return true if normalize(v) <= m }
        return false
      end
    end

    module Substrings
      def substrings(vals, *ss)
        return false if vals.nil?
        m = normalize(m)
        vals.each do |v|
          v = normalize(v)
          # return true unless one of the substring conditions does not match
          return true unless ss.find do |type,str|
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
      end
    end # module Substrings

    class DefaultMatchingClass
      include MatchingRule::Equality
      include MatchingRule::Ordering
      include MatchingRule::Substrings
      def normalize(x)
        x
      end
    end

    DefaultMatch = DefaultMatchingClass.new

  end # class MatchingRule

  #
  # And now, here are some matching rules you can use
  #

  class MatchingRule

    # DirectoryString semantics (what are they?)

    module StringDowncase
      def normalize(x); x.downcase; end
    end

    CaseIgnoreMatch = self.new('2.5.13.2', 'caseIgnoreMatch', '1.3.6.1.4.1.1466.115.1').instance_eval do
      extend Equality
      extend StringDowncase
    end

    # IA5 stuff. What's the correct way to do 'downcase' for UTF8 strings?

    module IA5Downcase
      def normalize(x)
        x.downcase
      end
    end

    CaseExactIA5Match = self.new('1.3.6.1.4.1.1466.109.114.1', 'caseExactIA5Match', '1.3.6.1.4.1.1466.115.121.1.26').instance_eval do
      extend Equality
    end

    CaseIgnoreIA5Match = self.new('1.3.6.1.4.1.1466.109.114.2', 'caseIgnoreIA5Match', '1.3.6.1.4.1.1466.115.121.1.26').instance_eval do
      extend Equality
      extend IA5Downcase
    end

    CaseExactIA5SubstringsMatch = self.new('1.3.6.1.4.1.4203.1.2.1', 'caseExactIA5SubstringsMatch', '1.3.6.1.4.1.1466.115.121.1.26').instance_eval do
      extend Substrings
    end

    CaseIgnoreIA5SubstringsMatch = self.new('1.3.6.1.4.1.1466.109.114.3', 'caseIgnoreIA5SubstringsMatch', '1.3.6.1.4.1.1466.115.121.1.26').instance_eval do
      extend Substrings
      extend IA5Downcase
    end

  end # class MatchingRule

end # class Server
end # module LDAP
