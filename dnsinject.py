import getopt
import sys
import os
import scapy.all as scapy
import netifaces as ni
global dns_ip
dns_ip = dict()




def hf_lookup(hf):
    f = open(hf, 'r')
    for l in f:
        domain = l.split(",")[1].strip()
        ip = l.split(",")[0].strip()
        dns_ip[domain] = ip


def main():
    print(sys.argv)
    arg = sys.argv
    ndi = (arg[arg.index("-i")+1].strip() if "-i" in arg else ni.gateways()['default'][ni.AF_INET][1])
    hnf = (arg[arg.index("-h")+1].strip() if "-h" in arg else False)
    if hnf: hf_lookup(hnf)
    
        
    print(ndi)
    print(hnf)
    print(dns_ip)
    #scapy.sniff(iface=str(ndi), filter=str(hnf), prn=realsniffer)



if __name__ == "__main__":
    main()
