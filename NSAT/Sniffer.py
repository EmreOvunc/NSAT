#!/usr/bin/python

# Sniffer Module #

from Libraries import *

Monitor_Types = ['arp', 'ip', 'tcp', 'udp', 'icmp' ,"dhcp", "dns"]

def Monitor_Module(monitor_type, opt_resolve, opt_save, args_multi):
    if str(args_multi) == 'True':
        multi_Monitor(monitor_type, opt_resolve, opt_save)
    else:
        for order in range(0, len(Monitor_Types)):
            if Monitor_Types[order] == monitor_type[0]:
                globals()[str(Monitor_Types[order]) + '_Monitor'](opt_resolve, opt_save)


def multi_Monitor(monitor_type, opt_resolve, opt_save):
    multi_packet = ''
    for pro in range(0, len(monitor_type)):
        if pro != len(monitor_type) - 1:
            if monitor_type[pro] == "dhcp":
                multi_packet = multi_packet + "port 67 and port 68"
                multi_packet = multi_packet + ' or '

            elif monitor_type[pro] == "dns":
                multi_packet = multi_packet + "port 53"
                multi_packet = multi_packet + ' or '

            else:
                multi_packet = multi_packet + monitor_type[pro]
                multi_packet = multi_packet + ' or '
        else:
            if str(monitor_type) == "dhcp":
                multi_packet = multi_packet + "port 67 and port 68"

            elif monitor_type[pro] == "dns":
                multi_packet = multi_packet + "port 53"

            else:
                multi_packet = multi_packet + monitor_type[pro]

    if opt_save == True:
        if opt_resolve == True:
            os.system('tcpdump ' + multi_packet + '-nn -w ' + desktop + 'tcpdump-Multi.pcap')
        else:
            os.system('tcpdump ' + multi_packet + ' -w ' + desktop + 'tcpdump-Multi.pcap')
    else:
        if opt_resolve == True:
            os.system('tcpdump ' + multi_packet + ' -nn ')
        else:
            print multi_packet
            os.system('tcpdump ' + multi_packet)

def arp_Monitor(opt_resolve, opt_save):
    if opt_save == True:
        if opt_resolve == True:
            os.system('tcpdump arp -nn -w ' + desktop + 'tcpdump-ARP.pcap')
        else:
            os.system('tcpdump arp -w ' + desktop + 'tcpdump-ARP.pcap')
    else:
        if opt_resolve == True:
            os.system('tcpdump arp -nn')
        else:
            os.system('tcpdump arp')

def dhcp_Monitor(opt_resolve, opt_save):
    if opt_save == True:
        if opt_resolve == True:
            os.system('tcpdump port 67 and 68 -nn -w ' + desktop + 'tcpdump-DHCP.pcap')
        else:
            os.system('tcpdump port 67 and 68 -w ' + desktop + 'tcpdump-DHCP.pcap')
    else:
        if opt_resolve == True:
            os.system('tcpdump port 67 and 68 -nn')
        else:
            os.system('tcpdump port 67 and 68')

def dns_Monitor(opt_resolve, opt_save):
    if opt_save == True:
        if opt_resolve == True:
            os.system('tcpdump port 53 -nn -w ' + desktop + 'tcpdump-DNS.pcap')
        else:
            os.system('tcpdump port 53 -w ' + desktop + 'tcpdump-DNS.pcap')
    else:
        if opt_resolve == True:
            os.system('tcpdump port 53 -nn')
        else:
            os.system('tcpdump port 53')

def ip_Monitor(opt_resolve, opt_save):
    if opt_save == True:
        if opt_resolve == True:
            os.system('tcpdump ip -nn -w ' + desktop + 'tcpdump-IP.pcap')
        else:
            os.system('tcpdump ip -w ' + desktop + 'tcpdump-IP.pcap')
    else:
        if opt_resolve == True:
            os.system('tcpdump ip -nn')
        else:
            os.system('tcpdump ip')

def tcp_Monitor(opt_resolve, opt_save):
    if opt_save == True:
        if opt_resolve == True:
            os.system('tcpdump tcp -nn -w ' + desktop + 'tcpdump-TCP.pcap')
        else:
            os.system('tcpdump tcp -w ' + desktop + 'tcpdump-TCP.pcap')
    else:
        if opt_resolve == True:
            os.system('tcpdump tcp -nn')
        else:
            os.system('tcpdump tcp')

def udp_Monitor(opt_resolve, opt_save):
    if opt_save == True:
        if opt_resolve == True:
            os.system('tcpdump udp -nn -w ' + desktop + 'tcpdump-UDP.pcap')
        else:
            os.system('tcpdump udp -w ' + desktop + 'tcpdump-UDP.pcap')
    else:
        if opt_resolve == True:
            os.system('tcpdump udp -nn')
        else:
            os.system('tcpdump udp')

def icmp_Monitor(opt_resolve, opt_save):
    if opt_save == True:
        if opt_resolve == True:
            os.system('tcpdump icmp -nn -w ' + desktop + 'tcpdump-ICMP.pcap')
        else:
            os.system('tcpdump icmp -w ' + desktop + 'tcpdump-ICMP.pcap')
    else:
        if opt_resolve == True:
            os.system('tcpdump icmp -nn')
        else:
            os.system('tcpdump icmp')
