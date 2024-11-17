# Steel_Mountain

Hack into a Mr. Robot themed Windows machine. Use metasploit for initial access, utilise powershell for Windows privilege escalation enumeration and learn a new technique to get Administrator access.

![Introduction](/steel_mountain.png)


Who is the employee of the month?

    Bill Harper

![Inspect](/BillHarper.png)

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

