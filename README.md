# ssh-mitm-python
Python scripts to execute a mitm attack on an ssh connection.

The sshmitm.py script executes an arp poisoning to become a MITM between a victim and the LAN gateway, then redirects all SSH traffic to a fake SSH server (sshserver.py). The fake server acts as a proxy to the real SSH server and can read the unencrypted traffic. It also logs all the credentials to a sqlite3 database and all the unencrypted communication to a log file in the logs folder.

If the victim has never connected before to a ssh server with the same IP address, the attack will be successful unless the client checks the server fingerprint manually. If the victim has connected before to the server the ssh client will display a scary warning because it will detect a change in the server fingerprint.

## usage
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
