#!/usr/bin/python

### Engine ###

from Libraries import *

def engine():
    parser = argparse.ArgumentParser(description="Network Security Assessment Tool [EmreOvunc-AyseSimgeOzger-UmutBasaran]")

    pcap_module = parser.add_argument_group('[Pcap Analysis Module]')
    pcap_module.add_argument("--file",help="give a pcap file to read")
    pcap_module.add_argument("--virus-scan", help="scan files in pcap to detect threads", action='store_true')

    pcap_module = parser.add_argument_group('[Packet Generation Module]')
    pcap_module.add_argument("--packet-type",choices=["arp","ip","icmp","tcp","udp","dns"] ,help="select a packet type to generate")
    pcap_module.add_argument("--auto",help="generate auto packets" ,action='store_true')
    pcap_module.add_argument("--manual",help="generate manual packets", action='store_true')

    pcap_module = parser.add_argument_group('[Attack Module]')
    pcap_module.add_argument("--attack-type",choices=["dos","arpspoof","icmpflood","tcpflood","synflood","fuzzer","sshoverload"] ,help="select a type of attack")

    pcap_module = parser.add_argument_group('[Recon Module]')
    pcap_module.add_argument("--recon-type", choices=["subdomain","portscan","banner","traceroute"],help="select a type of recon")

    pcap_module = parser.add_argument_group('[Sniffer Module]')
    pcap_module.add_argument("--sniff-type", choices=["arp","ip","tcp","udp","icmp","dhcp"], nargs='+' ,help="select a type of sniffing filters")
    pcap_module.add_argument("--resolve", help="do not resolve protocol and port numbers", action='store_true')
    pcap_module.add_argument("--save", help="to save all traffics in a pcap file", action='store_true')
    pcap_module.add_argument("--multi", help="to select more sniffing filters", action='store_true')

    parser.add_argument("--module",choices=["attack","generate","pcap","recon","sniffer"], help="select a module to run", required=True)
    parser.add_argument('--version', action='version', version='NSAT-Project v1.5.1')
    parser.epilog="Ex: Engine.py --module attack --attack-type icmpflood"
    #parser.usage="Ex: Engine.py --module generate --packet-type arp --auto"

    args = parser.parse_args()

    pcap_module_flag = 0
    generate_module_flag = 0
    attack_module_flag = 0
    recon_module_flag = 0
    sniffer_module_flag = 0


    if args.module == "pcap" and str(args.file) != "None":
        if  str(args.packet_type) != "None":
            print "[ERROR] '--packet-type' can be used for pcap analysis module!\n"
            pcap_module_flag += 1

        if  args.auto == True:
            print "[ERROR] '--auto' can be used for generation module!\n"
            pcap_module_flag += 1

        if  args.manual == True:
            print "[ERROR] '--manual' can be used for generation module!\n"
            pcap_module_flag += 1

        if  str(args.attack_type) != "None":
            print "[ERROR] '--attack-type' can be used for attack module!\n"
            pcap_module_flag += 1

        if  str(args.recon_type) != "None":
            print "[ERROR] '--recon-type' can be used for recon module!\n"
            pcap_module_flag += 1

        if  str(args.sniff_type) == "False":
            print "[ERROR] '--sniff-type' can be used for sniffer module!\n"
            pcap_module_flag += 1

        if  args.resolve == True:
            print "[ERROR] '--resolve' can be used for sniffer module!\n"
            pcap_module_flag += 1

        if  args.save == True:
            print "[ERROR] '--save' can be used for sniffer module!\n"
            pcap_module_flag += 1

        if  args.multi == True:
            print "[ERROR] '--multi' can be used for sniffer module!\n"
            pcap_module_flag += 1

        if pcap_module_flag == 0:
            try:
                Read_Pcap(args.file,args.virus_scan)
            except IOError:
                print "[ERROR] Given pcap file does not found!"
            except:
                print "[ERROR] Pcap Module does not load!"

    elif args.module == "pcap" and str(args.file) == "None":
        if str(args.packet_type) != "None":
            print "[ERROR] '--packet-type' can be used for pcap analysis module!"
            pcap_module_flag += 1

        if  args.auto == True:
            print "[ERROR] '--auto' can be used for generation module!\n"
            pcap_module_flag += 1

        if  args.manual == True:
            print "[ERROR] '--manual' can be used for generation module!\n"
            pcap_module_flag += 1

        if str(args.attack_type) != "None":
            print "[ERROR] '--attack-type' can be used for attack module!"
            pcap_module_flag += 1

        if str(args.recon_type) != "None":
            print "[ERROR] '--recon-type' can be used for recon module!"
            pcap_module_flag += 1

        if str(args.sniff_type) != "None":
            print "[ERROR] '--sniff-type' can be used for sniffer module!"
            pcap_module_flag += 1

        if  args.resolve == True:
            print "[ERROR] '--resolve' can be used for sniffer module!\n"
            pcap_module_flag += 1

        if  args.save == True:
            print "[ERROR] '--save' can be used for sniffer module!\n"
            pcap_module_flag += 1

        if  args.multi == True:
            print "[ERROR] '--multi' can be used for sniffer module!\n"
            pcap_module_flag += 1

        print "[ERROR] Please, give a pcap file to analyze with '--file'\n\nEx: Engine.py --module pcap --file /path/to/file.pcap"

    elif args.auto == True and args.manual == True:
        print "[ERROR] Do not use '--auto' and '--manual' parameters together!\nEx: Engine.py --module pcap --packet-type arp --auto\nEx: Engine.py --module pcap --packet-type icmp --manual"

    elif args.module == "generate" and args.auto == False and args.manual == False and str(args.packet_type) != "None":
        print "[ERROR] Please, add one of generating type with '--auto' or '--manual'\n\nEx: Engine.py --module pcap --packet-type arp --auto\nEx: Engine.py --module pcap --packet-type icmp --manual"

    elif args.module == "generate" and args.auto == False and args.manual == False and str(args.packet_type) == "None":
        print "[ERROR] Please, select a packet type with -'-packet-type'\n\nPacket Types = arp , ip , icmp , tcp , udp , dns\n\nEx: Engine.py --module generate --packet-type icmp --manual"

    elif args.module == "generate" and args.auto == True:
        if str(args.file) != "None":
            print "[ERROR] '--file' can be used for pcap analysis module!\n"
            generate_module_flag += 1

        if args.virus_scan == True:
            print "[ERROR] '--virus-scan' can be used for pcap analysis module!\n"
            generate_module_flag += 1

        if str(args.attack_type) != "None":
            print "[ERROR] '--attack-type' can be used for attack module!\n"
            generate_module_flag += 1

        if str(args.recon_type) != "None":
            print "[ERROR] '--recon-type' can be used for recon module!\n"
            generate_module_flag += 1

        if str(args.sniff_type) != "None":
            print "[ERROR] '--sniff-type' can be used for sniffer module!\n"
            generate_module_flag += 1

        if  args.resolve == True:
            print "[ERROR] '--resolve' can be used for sniffer module!\n"
            generate_module_flag += 1

        if  args.save == True:
            print "[ERROR] '--save' can be used for sniffer module!\n"
            generate_module_flag += 1

        if  args.multi == True:
            print "[ERROR] '--multi' can be used for sniffer module!\n"
            generate_module_flag += 1

        if generate_module_flag == 0:
            try:
                Generation_Module(args.packet_type,"auto","generate")
            except gaierror:
                print "\n[ERROR] IP address has wrong format!"
            except:
                print "\n[ERROR] Generation Module Manual does not load!"

    elif args.module == "generate" and args.manual == True:
        if str(args.file) != "None":
            print "[ERROR] '--file' can be used for pcap analysis module!\n"
            generate_module_flag += 1

        if args.virus_scan == True:
            print "[ERROR] '--virus-scan' can be used for pcap analysis module!\n"
            generate_module_flag += 1

        if str(args.attack_type) != "None":
            print "[ERROR] '--attack-type' can be used for attack module!\n"
            generate_module_flag += 1

        if str(args.recon_type) != "None":
            print "[ERROR] '--recon-type' can be used for recon module!\n"
            generate_module_flag += 1

        if str(args.sniff_type) != "None":
            print "[ERROR] '--sniff-type' can be used for sniffer module!\n"
            generate_module_flag += 1

        if  args.resolve == True:
            print "[ERROR] '--resolve' can be used for sniffer module!\n"
            generate_module_flag += 1

        if  args.save == True:
            print "[ERROR] '--save' can be used for sniffer module!\n"
            generate_module_flag += 1

        if  args.multi == True:
            print "[ERROR] '--multi' can be used for sniffer module!\n"
            generate_module_flag += 1

        if generate_module_flag == 0:
            try:
                Generation_Module(args.packet_type,"manual","generate")
            except gaierror:
                print "\n[ERROR] IP address has wrong format!"
            except:
                print "\n[ERROR] Generation Module Manual does not load!"

    elif args.module == "attack" and str(args.attack_type) != "None":
        if str(args.file) != "None":
            print "[ERROR] '--file' can be used for pcap analysis module!\n"
            attack_module_flag += 1

        if args.virus_scan == True:
            print "[ERROR] '--virus-scan' can be used for pcap analysis module!\n"
            attack_module_flag += 1

        if str(args.recon_type) != "None":
            print "[ERROR] '--recon-type' can be used for recon module!\n"
            attack_module_flag += 1

        if str(args.sniff_type) != "None":
            print "[ERROR] '--sniff-type' can be used for sniffer module!\n"
            attack_module_flag += 1

        if  args.resolve == True:
            print "[ERROR] '--resolve' can be used for sniffer module!\n"
            attack_module_flag += 1

        if  args.save == True:
            print "[ERROR] '--save' can be used for sniffer module!\n"
            attack_module_flag += 1

        if  args.multi == True:
            print "[ERROR] '--multi' can be used for sniffer module!\n"
            attack_module_flag += 1

        if  args.auto == True:
            print "[ERROR] '--auto' can be used for generation module!\n"
            attack_module_flag += 1

        if  args.manual == True:
            print "[ERROR] '--manual' can be used for generation module!\n"
            attack_module_flag += 1

        if str(args.packet_type) != "None":
            print "[ERROR] '--packet-type' can be used for generation module!\n"
            attack_module_flag += 1

        if attack_module_flag == 0:
            try:
                Attack_Module(args.attack_type)
            except:
                print "[ERROR] Attack Module does not load!"

    elif args.module == "attack" and str(args.attack_type) == "None":
        print "[ERROR] Please, select an attack type with '--attack-type'.\n\nAttack types: dos , arpspoof , icmpflood , tcpflood , synflood , fuzzer , sshoverload\n\nEx: Engine.py --module attack --attack-type icmpflood"

    elif args.module == "recon" and str(args.recon_type) == "None":
        print "[ERROR] Please, select a recon type with '--recon-type'.\n\nScan types: subdomain , portscan , banner , traceroute\n\nEx: Engine.py --module recon --recon-type portscan"

    elif args.module == "recon" and str(args.recon_type) != "None":
        if str(args.file) != "None":
            print "[ERROR] '--file' can be used for pcap analysis module!\n"
            recon_module_flag += 1

        if args.virus_scan == True:
            print "[ERROR] '--virus-scan' can be used for pcap analysis module!\n"
            recon_module_flag += 1

        if str(args.sniff_type) != "None":
            print "[ERROR] '--sniff-type' can be used for sniffer module!\n"
            recon_module_flag += 1

        if  args.resolve == True:
            print "[ERROR] '--resolve' can be used for sniffer module!\n"
            recon_module_flag += 1

        if  args.save == True:
            print "[ERROR] '--save' can be used for sniffer module!\n"
            recon_module_flag += 1

        if  args.multi == True:
            print "[ERROR] '--multi' can be used for sniffer module!\n"
            recon_module_flag += 1

        if  args.auto == True:
            print "[ERROR] '--auto' can be used for generation module!\n"
            recon_module_flag += 1

        if  args.manual == True:
            print "[ERROR] '--manual' can be used for generation module!\n"
            recon_module_flag += 1

        if str(args.attack_type) != "None":
            print "[ERROR] '--attack-type' can be used for attack module!\n"
            recon_module_flag += 1

        if str(args.packet_type) != "None":
            print "[ERROR] '--packet-type' can be used for generation module!\n"
            recon_module_flag += 1

        if recon_module_flag == 0:
            try:
                Scan_Module(args.recon_type)
            except:
                print "[ERROR] Scan Module does not load!"

    elif args.module == "sniffer" and str(args.sniff_type) == "None":
        print "[ERROR] Please, select a sniffing type with '--sniff-type'.\n\nMonitor types: arp , ip , tcp , udp , icmp , dhcp , dns\n\nEx: Engine.py --module sniffer --sniff-type dns"

    elif args.module == "sniffer" and str(args.sniff_type) != "None":
        if str(args.file) != "None":
            print "[ERROR] '--file' can be used for pcap analysis module!\n"
            sniffer_module_flag += 1

        if args.virus_scan == True:
            print "[ERROR] '--virus-scan' can be used for pcap analysis module!\n"
            sniffer_module_flag += 1

        if  args.auto == True:
            print "[ERROR] '--auto' can be used for generation module!\n"
            sniffer_module_flag += 1

        if  args.manual == True:
            print "[ERROR] '--manual' can be used for generation module!\n"
            sniffer_module_flag += 1

        if str(args.attack_type) != "None":
            print "[ERROR] '--attack-type' can be used for attack module!\n"
            sniffer_module_flag += 1

        if str(args.recon_type) != "None":
            print "[ERROR] '--recon-type' can be used for recon module!\n"
            sniffer_module_flag += 1

        if str(args.packet_type) != "None":
            print "[ERROR] '--packet-type' can be used for generation module!\n"
            sniffer_module_flag += 1

        if sniffer_module_flag == 0:
            if str(args.multi) == "True":
                if len(args.sniff_type) == 1:
                    print "[ERROR] '--multi' parameter for only multiple sniffing types!\nEx: Engine.py --module sniffer --sniff-type tcp"
                else:
                    try:
                        Monitor_Module(args.sniff_type, args.resolve, args.save, args.multi)
                    except:
                        print "[ERROR] Monitor Module does not load!"
            else:
                if len(args.sniff_type) == 1:
                    try:
                        Monitor_Module(args.sniff_type, args.resolve, args.save, args.multi)
                    except:
                        print "[ERROR] Monitor Module does not load!"
                else:
                    print "[ERROR] Please, add '--multi' parameter for more sniffing types!\nEx: Engine.py --module sniffer --sniff-type tcp arp --multi"
    else:
        print "[ERROR] Please, select one of available modules with '--module'\nEx: Engine.py --module attack --attack-type icmpflood\nEx: Engine.py --module pcap --file /path/to/file.pcap --virus-scan\nEx: Engine.py --module recon --recon-type portscan\nEx: Engine.py --module monitor --monitor-type udp\nEx: Engine.py --module generate --packet-type arp --auto"

if __name__ == "__main__":
    if not os.geteuid() == 0:
        sys.exit('NSAT must be run as root!')
    try:
        f1 = open('/usr/share/wireshark/init.lua', 'r+')
        f2 = open('/usr/share/wireshark/init.lua', 'r+')
        for line in f1:
            f2.write(line.replace('disable_lua = false', 'disable_lua = true'))
        f1.close()
        f2.close()
    except:
        pass
    engine()

