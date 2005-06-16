require 'socket'

module LDAPserver

  module_function

  # Accept connections on a port, and for each one start a new thread
  # and run the given block. Returns the Thread object for the listener.
  #
  # FIXME:
  # - have a limit on total number of concurrent connects
  # - have a limit on connections from a single IP, or from a /24
  #   (to avoid the trivial DoS that the first limit creates)
  # - ACL using source IP address (or perhaps that belongs in application)
  
  def tcpserver(*args, &blk)
    opt = args.pop
    logger = opt[:logger] || $stderr
    server = TCPServer.new(opt[:bindaddr] || "0.0.0.0", opt[:port])
    Thread.new do
      begin
        while session = server.accept
          # subtlety: copy 'session' into a block-local variable because
          # it will change when the next session is accepted
          Thread.new(session) do |s|
            begin
              s.instance_eval(*args, &blk)
            rescue Exception => e
              logger << "[#{s.peeraddr[3]}]: #{e}: #{e.backtrace[0]}\n"
            ensure
              s.close
            end
          end
        end
      # This is the 'server shutdown' exception
      rescue Interrupt
        server.close if server and not server.closed?
      end
    end
  end

end # module LDAPserver

if __FILE__ == $0
  # simple test
  puts "Running a test POP3 server on port 1110"
  t = LDAPserver::tcpserver(:port=>1110) do
    print "+OK I am a fake POP3 server\r\n"
    while line = gets
      case line
      when /^quit/i
        break
      when /^crash/i
        raise Errno::EPERM, "dammit!"
      else
        print "-ERR I don't understand #{line}"
      end
    end
    print "+OK bye\r\n"
  end
  #sleep 10; t.kill	# run for fixed time period
  t.join		# or: run until Ctrl-C
end 
