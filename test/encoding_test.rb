require File.dirname(__FILE__) + '/test_helper'

Thread.abort_on_exception = true

# This test suite requires the ruby-ldap client library to be installed.
#
# Unfortunately, this library is not ruby thread-safe (it blocks until
# it gets a response). Hence we have to fork a child to perform the actual
# LDAP requests, which is nasty. However, it does give us a completely
# independent source of LDAP packets to try.

require 'ldap/server/operation'
require 'ldap/server/server'

require 'net/ldap'

# We subclass the Operation class, overriding the methods to do what we need

class MockOperation < LDAP::Server::Operation
  def initialize(connection, messageId)
    super(connection, messageId)
    @@lastop = [:connect]
  end

  def simple_bind(version, user, pass)
    @@lastop = [:simple_bind, version.to_i, user, pass]
  end

  def search(basedn, scope, deref, filter)
    @@lastop = [:search, basedn, scope.to_i, deref.to_i, filter, @attributes]
    send_SearchResultEntry("cn=foo", {"a"=>["1","2"], "b"=>"boing"})
    send_SearchResultEntry("cn=bar", {"a"=>["3","4","5"], "b"=>"wibble"})
  end

  def add(dn, av)
    @@lastop = [:add, dn, av]
  end

  def del(dn)
    @@lastop = [:del, dn]
  end

  def modify(dn, ops)
    @@lastop = [:modify, dn, ops]
  end

  def modifydn(dn, newrdn, deleteoldrdn, newSuperior)
    @@lastop = [:modifydn, dn, newrdn, deleteoldrdn, newSuperior]
  end

  def compare(dn, attr, val)
    @@lastop = [:compare, dn, attr, val]
    return val != "false"
  end

  def self.lastop
    @@lastop
  end
end

class TestLdap < Test::Unit::TestCase
  HOST = '127.0.0.1'
  PORT = 1389

  def start_client
    in_ = Queue.new
    out = Queue.new
    Thread.new do
      do_child(in_, out)
    end
    return in_, out
  end

  def ensure_server_started
    @serv || start_server
  end

  def start_server(opts={})
    # back to a single process (the parent). Now we start our
    # listener thread
    @serv = LDAP::Server.new({
        :bindaddr		=> '127.0.0.1',
        :port			=> PORT,
        :nodelay		=> true,
        :operation_class	=> MockOperation,
      }.merge(opts))

    @serv.run_tcpserver
  end

  def setup
    @client_in, @client_out = start_client
    @serv = nil
  end

  def teardown
    if @serv
      @serv.stop
      @serv = nil
    end
    if @client
      @client_in << "quit"
      err = @client_out.pop
      raise err if "OK" != err
      @client = nil
    end
  end

  # Process commands on stdin in child

  def do_child in_, out
    while true
      begin
        a = in_.deq
        conn ||= Net::LDAP.new(host: HOST, port: PORT)
        case a
        when "bind2"
          #     TODO: Net::LDAP only supports protocol 3
          conn.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 2)
          conn.auth("foo","bar")
          conn.bind
        when "bind3"
          conn.auth("foo","bar")
          conn.bind
        # these examples taken from the ruby-ldap examples
        when "add1"
          entry1 = {
            objectclass: ['top', 'domain'],
            o: ['TTSKY.NET'],
            dc: ['localhost'],
          }
          conn.add(dn: "dc=localhost, dc=domain", attributes: entry1)
        when "add2"
          entry2 = {
            objectclass: ['top', 'person'],
            cn: ['Takaaki Tateishi'],
            sn: ['ttate','Tateishi', "zero\000zero"],
          }
          conn.add(dn: "cn=Takaaki Tateishi, dc=localhost, dc=localdomain", attributes: entry2)
        when "del"
          conn.delete(dn: "cn=Takaaki-Tateishi, dc=localhost, dc=localdomain")
        when /^compare (.*)/
          begin
            case conn.compare("cn=Takaaki Tateishi, dc=localhost, dc=localdomain",
                         "cn", $1)
            when true; out << "OK true"; next
            when false; out << "OK false"; next
            end
          rescue LDAP::ResultError => e
            # For older versions of ruby-ldap
            case e.message
            when /Compare True/i; out << "OK true"; next
            when /Compare False/i; out << "OK false"; next
            end
            raise
          end
        when "modrdn"
          conn.modify_rdn(olddn: "cn=Takaaki Tateishi, dc=localhost, dc=localdomain",
                      newrdn: "cn=Takaaki-Tateishi",
                      delete_attributes: true)
        when "modify"
          entry = [
            [:add, :objectclass, ['top', 'domain']],
            [:delete, :o, []],
            [:replace, :dc, ['localhost']],
          ]
          conn.modify(dn: "dc=localhost, dc=domain", operations: entry)
        when "search"
          res = {}
          conn.search(base: "dc=localhost, dc=localdomain",
                      scope: Net::LDAP::SearchScope_WholeSubtree,
                      filter: "(objectclass=*)") do |e|
            entry = e.to_h
            dn = entry.delete(:dn).first
            res[dn] = entry
          end
          exp = {
            "cn=foo" => {a: ["1","2"], b: ["boing"]},
            "cn=bar" => {a: ["3","4","5"], b: ["wibble"]},
          }
          if res != exp
            raise "Bad Search Result, expected\n#{exp.inspect}\ngot\n#{res.inspect}"
          end
        when "search2"
          res = {}
          # FIXME: ruby-ldap doesn't seem to allow DEREF options to be set
          conn.search(base: "dc=localhost, dc=localdomain",
                      scope: Net::LDAP::SearchScope_BaseObject,
                      filter: "(&(cn=foo)(objectclass=*)(|(!(sn=*))(ou>=baz)(o<=z)(cn=*and*er)))",
                      attributes: [:a, :b]) do |e|
            entry = e.to_h
            dn = entry.delete(:dn).first
            res[dn] = entry
          end
        when "search_range"
          res = {}
          conn.search(base: "dc=localhost, dc=localdomain",
                      scope: Net::LDAP::SearchScope_BaseObject,
                      attributes: ["a;range=1-2", "b"]) do |e|
            entry = e.to_h
            dn = entry.delete(:dn).first
            res[dn] = entry
          end
        when "search_range_limit"
          res = {}
          conn.search(base: "dc=localhost, dc=localdomain",
                      scope: Net::LDAP::SearchScope_WholeSubtree,
                      filter: "(objectclass=*)") do |e|
            entry = e.to_h
            dn = entry.delete(:dn).first
            res[dn] = entry
          end
          exp = {
            "cn=foo" => {a: ["1","2"], b: ["boing"]},
            "cn=bar" => {a: [], "a;range=0-1": ["3","4"], b: ["wibble"]},
          }
          if res != exp
            raise "Bad Search Result, expected\n#{exp.inspect}\ngot\n#{res.inspect}"
          end
        when "quit"
          out << "OK"
          break
        else
          raise "Bad command! #{a.inspect}"
        end
        out << "OK"
      rescue Exception => e
        $stderr.puts "Child exception: #{e}\n\t#{e.backtrace.join("\n\t")}"
        out << "ERR #{e}"
      end
    end
  end

  def req(cmd)
    ensure_server_started
    @client_in << cmd
    res = @client_out.deq.chomp
    assert_match(/^OK/, res)
    res
  end

  def test_bind2
    pend("net-ldap gem doesn't support protocol 2")
    req("bind2")
    assert_equal([:simple_bind, 2, "foo", "bar"], MockOperation.lastop)
    # cannot bind any more; ldap client library says "already binded." (sic)
  end

  def test_bind3
    req("bind3")
    assert_equal([:simple_bind, 3, "foo", "bar"], MockOperation.lastop)
    # cannot bind any more; ldap client library says "already binded." (sic)
  end

  def test_add
    req("add1")
    assert_equal([:add, "dc=localhost, dc=domain", {
      'objectclass'=>['top', 'domain'],
      'o'=>['TTSKY.NET'],
      'dc'=>['localhost'],
    }], MockOperation.lastop)
    req("add2")
    assert_equal([:add, "cn=Takaaki Tateishi, dc=localhost, dc=localdomain", {
      'objectclass'=>['top', 'person'],
      'cn'=>['Takaaki Tateishi'],
      'sn'=>['ttate','Tateishi',"zero\000zero"],
    }], MockOperation.lastop)
  end

  def test_del
    req("del")
    assert_equal([:del, "cn=Takaaki-Tateishi, dc=localhost, dc=localdomain"], MockOperation.lastop)
  end

  def test_compare
    pend("net-ldap gem doesn't support compare requests")
    r = req("compare Takaaki Tateishi")
    assert_match(/OK true/, r)
    assert_equal([:compare, "cn=Takaaki Tateishi, dc=localhost, dc=localdomain",
      "cn", "Takaaki Tateishi"], MockOperation.lastop)
    r = req("compare false")
    assert_match(/OK false/, r)
    assert_equal([:compare, "cn=Takaaki Tateishi, dc=localhost, dc=localdomain",
      "cn", "false"], MockOperation.lastop)
  end

  def test_modrdn
    req("modrdn")
    assert_equal([:modifydn, "cn=Takaaki Tateishi, dc=localhost, dc=localdomain",
      "cn=Takaaki-Tateishi", true, nil], MockOperation.lastop)
    # FIXME: ruby-ldap doesn't support the four-argument form
  end

  def test_modify
    req("modify")
    assert_equal([:modify, "dc=localhost, dc=domain", {
        'objectclass' => [:add, 'top', 'domain'],
        'o' => [:delete],
        'dc' => [:replace, 'localhost'],
    }], MockOperation.lastop)
  end

  def test_search
    req("search")
    assert_equal([:search, "dc=localhost, dc=localdomain",
      LDAP::Server::WholeSubtree,
      LDAP::Server::NeverDerefAliases,
      [:true], []], MockOperation.lastop)
    req("search2")
    assert_equal([:search, "dc=localhost, dc=localdomain",
      LDAP::Server::BaseObject,
      LDAP::Server::NeverDerefAliases,
      [:and, [:eq, "cn", nil, "foo"],
             [:or,  [:not, [:present, "sn"]],
                    [:ge, "ou", nil, "baz"],
                    [:le, "o", nil, "z"],
                    [:substrings, "cn", nil, nil, "and", "er"],
             ],
      ], ["a","b"]], MockOperation.lastop)
  end

  def test_search_with_range
    req("search_range")
    assert_equal([:search, "dc=localhost, dc=localdomain",
      LDAP::Server::BaseObject,
      LDAP::Server::NeverDerefAliases,
      [:true], ["a","b"]], MockOperation.lastop)
  end

  def test_search_with_range_limit
    start_server(attribute_range_limit: 2)
    req("search_range_limit")
    assert_equal([:search, "dc=localhost, dc=localdomain",
      LDAP::Server::WholeSubtree,
      LDAP::Server::NeverDerefAliases,
      [:true], []], MockOperation.lastop)
  end
end
