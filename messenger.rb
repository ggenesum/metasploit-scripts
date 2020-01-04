# Author: Wave
print_status("Hello World")
@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false,  "This help menu"],
  "-m"  => [ true,  "Message, writte quoted"],
)
message = "Hello World"
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
###########usage###########usage###########usage###########usage#######
def usage
print_status("This script will spawn a msgbox with the mesage of your choice")
  print_line(@exec_opts.usage)
  raise Rex::Script::Completed
end
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
###########Write message vbs script on host##########################
def write_msg_to_target(message)
print_status("Writting message script on host...")
location = session.sys.config.getenv('TEMP')
msgvbs = "#{location}\\messenger.vbs"
mg = @client.fs.file.new(msgvbs, "wb")
mg.write("msgbox(\"#{message}\")")
mg.close
return msgvbs
end
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##############options##############options##############options########
@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    usage
  when "-m"
    message = val
end
}
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##############MAIN##############MAIN##############MAIN##############MAIN

msgvbs = write_msg_to_target(message)
print_good("messagebox spawned !")
print_status("pressing ctrl+c will not close the msgbox")
cmd_exec("wscript \"#{msgvbs}\"")
print_good("Host closed msgbox")




