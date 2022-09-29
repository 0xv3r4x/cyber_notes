# Investigating Windows | TryHackMe

We first check the version and year of the Windows machine:

![[systeminfo.png]]

Then, we check which user logged in last (before us):

![[user_last_logon.png]]

We see that the `Administrator` user was the last to log on (`9/9/2022 2:54:53 PM`) only preceded by `John` (`3/2/2019 5:48:32 PM`).

When the machine started up, there was a suspicious file running from `C:\TMP`.  We can check the startup processes within the registry (**HKEY_LOCAL_MACHINE->SOFTWARE->Microsoft->Windows->CurrentVersion->Run**).

![[suspicious_startup_file.png]]

As shown, the `C:\TMP\p.exe` attempts to conenct to the IP `10.34.2.3`.

We can also use `net user` to see that `Jenny` and `Guest` have administrator privileges:

![[net_user_admin_privs.png]]

To view scheduled tasks, we can use the **Task Scheduler** application.  When we view the "**Task Scheduler Library**", we can see each scheduled task and what they do (actions).  Based on this, we can determine that the **Clean file system** task is malicious:

![[malicious_scheduled_task.png]]

From the above, the task attempts to run `C:\TMP\nc.ps1` listening on the local port (`-l`) `1348` for incoming connections.  This first took place on `02/03/2019`.

We can then check the Windows Event Viewer to determine when special privileges were assigned to a new logon - Event ID `4672`.

![[event_viewer_special_privs.png]]

Going back to the **Task Scheduler** application, we can see that the `GameOver` task attempts to execute a `C:\TMP\mim.exe` file and dumps its contents out to `C:\TMP\o.txt`. 

![[mim_exe.png]]

A quick look at this file's contents indicates that it is **mimikatz**.

![[mim_out_txt.png]]

We can then check the `hosts` file (`C:\Windows\System32\drivers\etc\hosts`) for any outgoing connections.  This reveals a suspicious IP attached to `google.com`, indicating DNS poisoning:

![[etc_hosts.png]]

We then open the `C:\inetpub\wwwroot` directory which is where IIS (**I**nternet **I**nformation **S**ervices) commonly stores its files.  We see three files, namely `b.jsp`, `shell.gif`, and `tests.jsp`:

![[inetpub_wwwroot_directory.png]]

It appears the attacker uploaded a `tests.jsp` shell to the server's website.

![[test_jsp.png]]

We can then use the **Windows Firewall with Advanced Security** application to view the ports which the attacker opened:

![[firewall_inbound_rules_1337.png]]

From the above, it appers the attacker opened port `1337` to allow for inbound connections.  Because the rule is at the top of the file, it will be read first.



-----

###### Task 1 - Investigating Windows

1. What is the version and year of the Windows machine?

```
Windows Server 2016
```

2. Which user logged in last?

```
Administrator
```

3. When did John last log onto the system?

```
03/02/2019 5:48:32 PM
```

4. What IP does the system connect to when it first starts?

```
10.34.2.3
```

5. What two accounts had administrator privileges (other than `Administrator`)?

```
Jenny,Guest
```

6. What is the name of the scheduled task that is malicious?

```
Clean file system
```

7. What file was the task trying to run daily?

```
nc.ps1
```

8. What port did this file listen locally for?

```
1348
```

9. When did Jenny last logon?

```
Never
```

10. At what time did Windows first assign special privileges to a new logon?

```
03/02/2019 04:04:49 PM
```

11. What tool was used to get Windows passwords?

```
mimikatz
```

12. What was the attacker's external command and control server's IP?

```
76.32.97.132
```

13. What was the extension name of the shell uploaded via the server's website?

```
tests.jsp
```

14. What was the last port the attacker opened?

```
1337
```

15. Check for DNS poisoning, what site was targeted?

```
google.com
```