#!/usr/bin/python

#### Packet Generation ####

from Libraries import *

Packet_Type=["arp","ip","icmp","tcp","udp","dns"]
Default_DNS_Server = "8.8.8.8"

def Generation_Module(args_1,args_2,called):
    for order in range(0, len(Packet_Type)):
        if (Packet_Type[order] == args_1):
            globals()[str(Packet_Type[order])+"_"](args_2,called)

def DNS_Server():
    dns_server = raw_input("DNS Server: ")
    if dns_server == '':
        dns_server = DNS_Server()
    else:
        try:
            int(str(dns_server).split(".")[0])
            int(str(dns_server).split(".")[1])
            int(str(dns_server).split(".")[2])
            int(str(dns_server).split(".")[3])
        except:
            print "\n[ERROR] Given dns server IP address invalid format.\n"
            dns_server = DNS_Server()
    return dns_server

def SourceIP():
    srcIP = raw_input("Source IP: ")
    if srcIP == '':
        srcIP = SourceIP()
    else:
        try:
            int(str(srcIP).split(".")[0])
            int(str(srcIP).split(".")[1])
            int(str(srcIP).split(".")[2])
            int(str(srcIP).split(".")[3])
        except:
            print "\n[ERROR] Given IP address invalid format.\n"
            srcIP = SourceIP()
    return srcIP

def DestinationIP():
    dstIP = raw_input("Destination IP: ")
    if dstIP == '':
        dstIP = DestinationIP()
    else:
        try:
            int(str(dstIP).split(".")[0])
            int(str(dstIP).split(".")[1])
            int(str(dstIP).split(".")[2])
            int(str(dstIP).split(".")[3])
        except:
            print "\n[ERROR] Given IP address invalid format.\n"
            dstIP = DestinationIP()
    return dstIP

def TargetDomain():
    dstDomain =  raw_input("Target Domain: ")
    if dstDomain == '':
        dstDomain = TargetDomain()
    return dstDomain

def SourceHardware():
    srcMAC = raw_input("Source Mac Address: ")
    if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", srcMAC.lower()):
        return srcMAC
    elif srcMAC == '':
        srcMAC = SourceHardware()
    else:
        print "\n[ERROR] Given mac address invalid format.\n"
        SourceHardware()
    return srcMAC

def DestinationHardware():
    dstMAC = raw_input("Destination Mac Address: ")
    if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", dstMAC.lower()):
        return dstMAC
    elif dstMAC == '':
        dstMAC == DestinationHardware()
    else:
        print "\n[ERROR] Given mac address invalid format.\n"
    return dstMAC

def PortControl(host_Port):
    try:
        val = int(host_Port)
    except ValueError:
        print "[ERROR] Please enter a port number!"
        sys.exit()
    return host_Port

def DestinationPort():
    dstPort = raw_input("Destination Port: ")
    if dstPort == '':
        dstPort = DestinationPort()
    dstPort = PortControl(dstPort)
    return int(dstPort)

def SourcePort():
    srcPort = raw_input("Source Port: ")
    if srcPort == '':
        srcPort = SourcePort()
    srcPort = PortControl(srcPort)
    return int(srcPort)

def RandomIP():
    ip = ".".join(map(str, (random.randint(0, 255)for _ in range(4))))
    return ip

def RandomPort():
    port = random.randint(1,65535)
    return port

def RandomInteger():
    randomint = random.randint(1000,99999)
    return randomint

def RandomMAC():
    mac = [ random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff),random.randint(0x00, 0xff),random.randint(0x00, 0xff),random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def send_Packet(Packet,called):
    if called == "attack":
        send(Packet)
    else:
        send_ack = raw_input("Do you want to send your packet? (Y/n): ")
        if send_ack == "Y" or send_ack == "y":
            send(Packet)
        elif send_ack == "N" or send_ack == "n":
            sys.exit()
        else:
            send_Packet(Packet,called)

class arp_:
    def __init__(self,howtype,called):
        self.type = type
        self.ARP_Packet = ARP()
        self.ARP_Packet.hwtype = 0x1
        self.ARP_Packet.ptype = 0x800
        self.ARP_Packet.plen = 4
        self.ARP_Packet.op = "who-has"

        if howtype == "auto":
            self.ARP_Auto(called)
        elif howtype == "manual":
            self.ARP_Manual(called)

    def ARP_Auto(self,called):
        self.ARP_Packet.psrc = RandomIP()
        self.ARP_Packet.hwsrc = RandomMAC()

        if called != "attack":
            self.ARP_Packet.pdst = DestinationIP()
            send_Packet(self.ARP_Packet, called)
        else:
            pass

    def ARP_Manual(self,called):


        arp_hwtype = raw_input("[ARP] Hardware Type (hwtype) [Press enter for 0x1]: ")
        if arp_hwtype == "":
            arp_hwtype = 0x1
        else:
            try:
                int(arp_hwtype, 16)
                arp_hwtype = int(arp_hwtype,16)
            except ValueError:
                print "\n[ERROR] Given hwtype invalid format!\n[LOG] Hwtype sets 0x1\n"
                arp_hwtype = 0x1

        arp_ptype = raw_input("[ARP] Protocol Type (ptype) [Press enter for 0x800]: ")
        if arp_ptype == "":
            arp_ptype = 0x1
        else:
            try:
                int(arp_ptype, 16)
                arp_ptype = int(arp_ptype, 16)
            except ValueError:
                print "\n[ERROR] Given ptype invalid format!\n[LOG] Ptype sets 0x800\n"
                arp_ptype = 0x800


        arp_plen = raw_input("[ARP] Protocol Length (plen) [Press enter for 4]: ")
        if arp_plen == "":
                arp_plen = 4
        else:
            try:
                int(arp_plen)
                arp_plen = int(arp_plen)
            except ValueError:
                print "\n[ERROR] Given plen invalid format!\n[LOG] Plen sets 4\n"
                arp_plen = 4

        arp_op = raw_input("[ARP] Operation (op) [Press enter for who-has]: ")
        if arp_op == "":
            arp_op = 'who-has'
        else:
            try:
                int(arp_op)
                arp_op = int(arp_op)
            except ValueError:
                print "\n[ERROR] Given op code invalid format!\n[LOG] Op code sets 'who-has'\n"
                arp_op = "who-has"

        self.ARP_Packet.op = arp_op
        self.ARP_Packet.plen = arp_plen
        self.ARP_Packet.ptype = arp_ptype
        self.ARP_Packet.hwtype = arp_hwtype
        self.ARP_Packet.psrc = SourceIP()
        self.ARP_Packet.pdst = DestinationIP()
        self.ARP_Packet.hwsrc = SourceHardware()

        try:
            send_Packet(self.ARP_Packet,called)
        except:
            print "\n[ERROR] ARP Packet could not send!"

class ip_:
    def __init__(self,howtype,called):
        self.IP_Packet = IP()
        self.IP_Packet.version = 4
        self.IP_Packet.ihl = None
        self.IP_Packet.tos = 0x0
        self.IP_Packet.len = None
        self.IP_Packet.id = 1
        self.IP_Packet.frag = 0
        self.IP_Packet.ttl = 64
        self.IP_Packet.proto = "hopopt"
        self.IP_Packet.chksum = None

        if howtype == "auto":
            self.IP_Auto(called)
        elif howtype == "manual":
            self.IP_Manual(called)

    def IP_Auto(self,called):
        if called != "attack":
            self.IP_Packet.src = SourceIP()
            self.IP_Packet.dst = DestinationIP()
            send_Packet(self.IP_Packet,called)
        else:
            self.IP_Packet.src = RandomIP()

    def IP_Manual(self, called):
        ip_version = raw_input("[IP] Version [Press enter for 4]:")
        if ip_version == "":
            ip_version = 4
        else:
            try:
                int(ip_version)
                ip_version = int(ip_version)
            except ValueError:
                    print "\n[ERROR] Given IP version is invalid!\n[LOG] IP version sets 4.\n"
                    ip_version = 4

        ip_ihl = raw_input("[IP] IP Header Length (ihl) [Press enter for None]: ")
        if ip_ihl == "":
            ip_ihl = None
        else:
            try:
                int(ip_ihl)
                ip_ihl = int(ip_ihl)
            except ValueError:
                print "\n[ERROR] Given header length is invalid!\n[LOG] Length sets 'None'.\n"
                ip_ihl = None

        ip_tos = raw_input("[IP] Type of Service (tos) [Press enter for 0x0]: ")
        if ip_tos == "":
            ip_tos = 0x0
        else:
            try:
                int(ip_tos, 16)
                ip_tos = int(ip_tos, 16)
            except ValueError:
                print "\n[ERROR] Given tos invalid format!\n[LOG] Tos number sets 0x0\n"
                ip_tos = 0x0

        ip_len = raw_input("[IP] Length (len) [Press enter for None]: ")
        if ip_len == "":
            ip_len = None
        else:
            try:
                int(ip_len)
                ip_len = int(ip_len)
            except ValueError:
                print "\n[ERROR] Given length invalid format!\n[LOG] Length sets 'None'\n"
                ip_len = None

        ip_id = raw_input("[IP] Identification (id) [Press enter for 1]: ")
        if ip_id == "":
            ip_id = 1
        else:
            try:
                int(ip_id)
                ip_id = int(ip_id)
            except ValueError:
                    print "\n[ERROR] Given id invalid format!\n[LOG] ID number sets 1\n"
                    ip_id = 1

        ip_frag = raw_input("[IP] Fragmentation Offset (frag) [Press enter for 0]: ")
        if ip_frag == "":
            ip_frag = 0
        else:
            try:
                int(ip_frag)
                ip_frag = int(ip_frag)
            except ValueError:
                print "\n[ERROR] Given frag number format!\n[LOG] Frag number sets 0\n"
                ip_frag = 0

        ip_flags = raw_input("[IP] Flag number [Press enter for 0 - Reserved]: ")
        if ip_flags == "":
            ip_flags = None
        else:
            try:
                int(ip_flags)
                ip_flags = int(ip_flags)
            except ValueError:
                print "\n[ERROR] Given flag number format!\n[LOG] Flag number sets 'None'\n"
                ip_flags = None

        ip_ttl = raw_input("[IP] Time to Live (ttl) [Press enter for 64]: ")
        if ip_ttl == "":
            ip_ttl = 64
        else:
            try:
                int(ip_ttl)
                ip_ttl = int(ip_ttl)
            except ValueError:
                    print "\n[ERROR] Given ttl invalid format!\n[LOG] TTL number sets 64\n"
                    ip_ttl = 64


        ip_proto = raw_input("[IP] Protocol (proto) [Press enter for hopopt]: ")
        if ip_proto == "":
            ip_proto = 'hopopt'
        else:
            try:
                int(ip_proto)
                ip_proto = int(ip_proto)
            except ValueError:
                print "\n[ERROR] Given protocol number invalid format!\n[LOG] Protocol number sets 'hopopt'\n"
                ip_proto = "hopopt"

        ip_chksum = raw_input("[IP] Checksum [Press enter for None]: ")
        if ip_chksum == "":
            ip_chksum = None
        else:
            try:
                int(ip_chksum, 16)
                ip_chksum = int(ip_chksum, 16)
            except ValueError:
                print "\n[ERROR] Given checksum number invalid format!\n[LOG] Checksum number sets 'None'\n"
                ip_chksum = None

        self.IP_Packet.chksum = ip_chksum
        self.IP_Packet.version = ip_version
        self.IP_Packet.frag = ip_frag
        self.IP_Packet.ttl = ip_ttl
        self.IP_Packet.chksum = ip_chksum
        self.IP_Packet.flags = ip_flags
        self.IP_Packet.proto = ip_proto
        self.IP_Packet.id = ip_id
        self.IP_Packet.len = ip_len
        self.IP_Packet.tos = ip_tos
        self.IP_Packet.ihl = ip_ihl
        self.IP_Packet.src = SourceIP()
        self.IP_Packet.dst = DestinationIP()

        try:
            send_Packet(self.IP_Packet,called)
        except:
            print "\n[ERROR] IP Packet could not send!"

class icmp_:
    def __init__(self, howtype, called):
        self.ICMP_Packet = ICMP()
        self.ICMP_Packet.type = "echo-request"
        self.ICMP_Packet.code = 0
        self.ICMP_Packet.chksum = None
        self.ICMP_Packet.id = 0x0
        self.ICMP_Packet.seq = 0x0

        if howtype == "auto":
            self.ICMP_Auto(called)
        elif howtype == "manual":
            self.ICMP_Manual(called)

    def ICMP_Auto(self, called):
        if called != "attack":
            destIP = DestinationIP()
            send(IP(dst=destIP)/(self.ICMP_Packet))
        else:
            pass

    def ICMP_Manual(self,called):
        icmp_type = raw_input("[ICMP] Type [Press enter for echo-request]:")
        if icmp_type == "":
            icmp_type = 'echo-request'
        else:
            try:
                int(icmp_type)
                icmp_type = int(icmp_type)
            except ValueError:
                print "\n[ERROR] Given type invalid format!\n[LOG] Type sets 'echo-request'\n"
                icmp_type = "echo-request"


        icmp_code = raw_input("[ICMP] Code [Press enter for 0]:")
        if icmp_code == "":
            icmp_code = None
        else:
            try:
                int(icmp_code)
                icmp_code = int(icmp_code)
            except ValueError:
                print "\n[ERROR] Given code invalid format!\n[LOG] Code sets 0\n"
                icmp_code = 0


        icmp_chksum = raw_input("[ICMP] Checksum [Press enter for None]:")
        if icmp_chksum == "":
            icmp_chksum = None
        else:
            try:
                int(icmp_chksum, 16)
                icmp_chksum = int(icmp_chksum, 16)
            except ValueError:
                print "\n[ERROR] Given checksum invalid format!\n[LOG] Checksum sets None\n"
                icmp_chksum = None

        icmp_id = raw_input("[ICMP] ID [Press enter for 0x0]:")
        if icmp_id == "":
            icmp_id = 0x0
        else:
            try:
                int(icmp_id, 16)
                icmp_id = int(icmp_id, 16)
            except ValueError:
                print "\n[ERROR] Given ID invalid format!\n[LOG] ID sets 0x0\n"
                icmp_id = 0x0

        icmp_seq = raw_input("[ICMP] Seq [Press enter for 0x0]:")
        if icmp_seq == "":
            icmp_seq = 0x0
        else:
            try:
                int(icmp_seq, 16)
                icmp_seq = int(icmp_seq, 16)
            except ValueError:
                print "\n[ERROR] Given seq number invalid format!\n[LOG] Seq number sets 0\n"
                icmp_seq = 0x0

        self.ICMP_Packet.type = icmp_type
        self.ICMP_Packet.seq = icmp_seq
        self.ICMP_Packet.id = icmp_id
        self.ICMP_Packet.chksum = icmp_chksum
        self.ICMP_Packet.code = icmp_code
        self.ICMP_Packet.src = SourceIP()
        self.ICMP_Packet.dst = DestinationIP()

        def sendpkt():
            send_ack = raw_input("Do you want to send your packet? (Y/n): ")
            if send_ack == "Y" or send_ack == "y":
                    send(IP(dst=self.ICMP_Packet.dst, src=self.ICMP_Packet.src) / self.ICMP_Packet)
            elif send_ack == "N" or send_ack == "n":
                sys.exit()
            else:
                sendpkt()
            sys.exit()
        sendpkt()

class udp_:
    def __init__(self, howtype, called):
        self.UDP_Packet = UDP()
        self.UDP_Packet.sport = "domain"
        self.UDP_Packet.dport = "domain"
        self.UDP_Packet.len = None
        self.UDP_Packet.chksum = None

        if howtype == "auto":
            self.UDP_Auto(called)
        elif howtype == "manual":
            self.UDP_Manual()

    def UDP_Auto(self,called):
        if called != "attack":
            targetIP = DestinationIP()
            targetPort = DestinationPort()
            sourcePort = SourcePort()

            self.UDP_Packet.sport = sourcePort
            self.UDP_Packet.dport = targetPort

            send(IP(dst=targetIP)/(self.UDP_Packet))

    def UDP_Manual(self):
        udp_sport = raw_input("[UDP] Source Port [Press enter for 53]: ")
        if udp_sport == "":
            udp_sport = "domain"
        else:
            try:
                int(udp_sport)
                udp_sport = int(udp_sport)
            except ValueError:
                print "\n[ERROR] Given source port invalid format!\n[LOG] Source port sets 53.\n"
                udp_sport = "domain"

        udp_dport = raw_input("[UDP] Destination Port [Press enter for 53]: ")
        if udp_dport == "":
            udp_dport = "domain"
        else:
            try:
                int(udp_dport)
                udp_dport = int(udp_dport)
            except ValueError:
                print "\n[ERROR] Given destination port invalid format!\n[LOG] Destination port sets 53.\n"
                udp_dport = "domain"

        udp_len = raw_input("[UDP] Length [Press enter for None]: ")
        if udp_len == "":
            udp_len = None
        else:
            try:
                int(udp_len)
                udp_len = int(udp_len)
            except ValueError:
                print "\n[ERROR] Given length invalid format!\n[LOG] Length sets 'None'.\n"
                udp_len = None

        udp_chksum = raw_input("[UDP] Checksum [Press enter for None]: ")
        if udp_chksum == "":
            udp_chksum = None
        else:
            try:
                int(udp_chksum, 16)
                udp_chksum = int(udp_chksum, 16)
            except ValueError:
                print "\n[ERROR] Given checksum invalid format!\n[LOG] Checksum sets None\n"
                udp_chksum = None

        self.UDP_Packet.sport = udp_sport
        self.UDP_Packet.dport = udp_dport
        self.UDP_Packet.len = udp_len
        self.UDP_Packet.chksum = udp_chksum

        targetIP = DestinationIP()

        try:
            send(IP(dst=targetIP) / self.UDP_Packet)
        except:
            print "\n[ERROR] UDP Packet could not send!"


class tcp_:
    def __init__(self, howtype, called):
        self.TCP_Packet = TCP()
        self.TCP_Packet.sport = "ftp_data"
        self.TCP_Packet.dport = "http"
        self.TCP_Packet.seq = 0
        self.TCP_Packet.ack = 0
        self.TCP_Packet.dataofs = None
        self.TCP_Packet.reserved = 0
        self.TCP_Packet.flags = "S"
        self.TCP_Packet.window = 8192
        self.TCP_Packet.chksum = None
        self.TCP_Packet.urgptr = 0
        self.TCP_Packet.options = ""

        if howtype == "auto":
            self.TCP_Auto(called)
        elif howtype == "manual":
            self.TCP_Manual()

    def TCP_Auto(self,called):
        if called != "attack":
            targetIP = DestinationIP()
            srcPort = SourcePort()
            dstPort = DestinationPort()

            self.TCP_Packet.sport = srcPort
            self.TCP_Packet.dport = dstPort

            send(IP(dst=targetIP)/self.TCP_Packet)

        elif called == "attack":
            self.TCP_Packet.seq = RandomInteger()
            self.TCP_Packet.ack = RandomInteger()
            self.TCP_Packet.sport = RandShort()

    def TCP_Manual(self):
        tcp_sport = raw_input("[TCP] Source Port [Press enter for 21]: ")
        if tcp_sport == "":
            tcp_sport = "ftp"
        else:
            try:
                int(tcp_sport)
                tcp_sport = int(tcp_sport)
            except ValueError:
                print "\n[ERROR] Given source port invalid format!\n[LOG] Source port sets 21.\n"
                tcp_sport = "ftp_data"


        tcp_dport = raw_input("[TCP] Destination Port [Press enter for 80]: ")
        if tcp_dport == "":
            tcp_dport = 80
        else:
            try:
                int(tcp_dport)
                tcp_dport = int(tcp_dport)
            except ValueError:
                print "\n[ERROR] Given destination port invalid format!\n[LOG] Destination port sets 80.\n"
                tcp_dport = "http"


        tcp_seq = raw_input("[TCP] Seq Number [Press enter for 0]: ")
        if tcp_seq == "":
            tcp_seq = 0
        else:
            try:
                int(tcp_seq)
                tcp_seq = int(tcp_seq)
            except ValueError:
                print "\n[ERROR] Given seq number invalid format!\n[LOG] Seq number sets 0.\n"
                tcp_seq = 0

        tcp_ack = raw_input("[TCP] Ack Number [Press enter for 0]: ")
        if tcp_ack == "":
            tcp_ack = 0
        else:
            try:
                int(tcp_ack)
                tcp_ack = int(tcp_ack)
            except ValueError:
                print "\n[ERROR] Given destination port invalid format!\n[LOG] Ack number sets 0.\n"
                tcp_ack = 0

        tcp_dataofs = raw_input("[TCP] Dataoffset [Press enter for None]: ")
        if tcp_dataofs == "":
            tcp_dataofs = None
        else:
            try:
                int(tcp_dataofs)
                tcp_dataofs = int(tcp_dataofs)
            except ValueError:
                print "\n[ERROR] Given dataoffset invalid format!\n[LOG] Dataoffset number sets None.\n"
                tcp_dataofs = None

        tcp_reserved = raw_input("[TCP] Reserved [Press enter for 0]: ")
        if tcp_reserved == "":
            tcp_reserved = 0
        else:
            try:
                int(tcp_reserved)
                tcp_reserved = int(tcp_reserved)
            except ValueError:
                print "\n[ERROR] Given reserved invalid format!\n[LOG] Reserved number sets 0.\n"
                tcp_reserved = 0


        tcp_flags = raw_input("[TCP] Flags [Press enter for 'S']: ")
        try:
            if tcp_flags == "":
                pass
            elif str(tcp_flags) == "R" or str(tcp_flags) == "r" or str(tcp_flags) == "S" or str(tcp_flags) == "s" or str(tcp_flags) == "F" or str(tcp_flags) == "f" or str(tcp_flags) == "a" or str(tcp_flags) == "A" or str(tcp_flags) == "U" or str(tcp_flags) == "u" or str(tcp_flags) == "P" or str(tcp_flags) == "p":
                tcp_flags = str(tcp_flags)
            else:
                print "\n[ERROR] Given flag is invalid, available flags 'S','R','F','A','U','P'\n[LOG] Flag sets 'S'\n"
                tcp_flags = "S"
        except:
            print "\n[ERROR] Given flag is invalid, available flags 'S','R','F','A','U','P'\n[LOG] Flag sets 'S'\n"
            tcp_flags = "S"

        tcp_window = raw_input("[TCP] Window [Press enter for 8192]: ")
        if tcp_window == "":
            tcp_window = 8192
        else:
            try:
                int(tcp_window)
                tcp_window = int(tcp_window)
            except ValueError:
                print "\n[ERROR] Given window size invalid format!\n[LOG] Window size sets 8192.\n"
                tcp_window = 8192

        tcp_chksum = raw_input("[TCP] Checksum [Press enter for None]: ")
        if tcp_chksum == "":
            tcp_chksum = None
        else:
            try:
                int(tcp_chksum, 16)
                tcp_chksum = int(tcp_chksum, 16)
            except ValueError:
                print "\n[ERROR] Given checksum invalid format!\n[LOG] Checksum sets None.\n"
                tcp_chksum = None

        tcp_urgptr = raw_input("[TCP] Urgent Pointer [Press enter for 0]: ")
        if tcp_urgptr == "":
            tcp_urgptr = 0
        else:
            try:
                int(tcp_urgptr)
                tcp_urgptr = int(tcp_urgptr)
            except ValueError:
                print "\n[ERROR] Given urgent number invalid format!\n[LOG] Urgent number sets 0.\n"
                tcp_urgptr = 0

        self.TCP_Packet.sport = tcp_sport
        self.TCP_Packet.dport = tcp_dport
        self.TCP_Packet.seq = tcp_seq
        self.TCP_Packet.ack = tcp_ack
        self.TCP_Packet.dataofs = tcp_dataofs
        self.TCP_Packet.reserved = tcp_reserved
        self.TCP_Packet.flags = tcp_flags
        self.TCP_Packet.window = tcp_window
        self.TCP_Packet.chksum = tcp_chksum
        self.TCP_Packet.urgptr = tcp_urgptr
        targetIP = DestinationIP()

        try:
            send(IP(dst=targetIP) / self.TCP_Packet)
        except:
            print "\n[ERROR] TCP Packet could not send!"

class dns_:
    def __init__(self,howtype,called):
        self.DNS_Packet = DNS()
        self.DNS_Packet.id = 0
        self.DNS_Packet.qr = 0
        self.DNS_Packet.opcode = "QUERY"
        self.DNS_Packet.aa = 0
        self.DNS_Packet.tc = 1
        self.DNS_Packet.rd = 0
        self.DNS_Packet.ra = 0
        self.DNS_Packet.z = 0
        self.DNS_Packet.rcode = "ok"
        self.DNS_Packet.qdcount = 1
        self.DNS_Packet.ancount = 0
        self.DNS_Packet.nscount = 0
        self.DNS_Packet.arcount = 0
        self.DNS_Packet.qd = None
        self.DNS_Packet.an = None
        self.DNS_Packet.ns = None
        self.DNS_Packet.ar = None

        if howtype == "auto":
            self.DNS_Auto(called)
        elif howtype == "manual":
            self.DNS_Manual()

    def DNS_Auto(self, called):
        if called != "attack" :
            target_domain = TargetDomain()
            self.DNS_Packet.rd = 1
            self.DNS_Packet.qd=DNSQR(qname=target_domain)
            dns_answer = sr1(IP(dst=Default_DNS_Server)/UDP(dport=53)/self.DNS_Packet,verbose=0)
            print dns_answer[DNS].summary()

    def DNS_Manual(self):
        query_id = raw_input("[DNS] Query ID [Press enter for 0]: ")
        if query_id == "":
            query_id = 0
        else:
            try:
                int(query_id)
                query_id = int(query_id)
            except ValueError:
                print "\n[ERROR] Given query id invalid format!\n[LOG] Query id sets 0.\n"
                query_id = 0


        query_qr = raw_input("[DNS] Query Response [Press enter for 0]: ")
        if query_qr == "":
            query_qr = 0
        else:
            try:
                int(query_qr)
                query_qr = int(query_qr)
            except ValueError:
                print "\n[ERROR] Given qr number invalid format!\n[LOG] Qr number sets 0.\n"
                query_qr = 0


        query_opcode = raw_input("[DNS] Opcode [Press enter for 'QUERY']: ")
        if query_opcode == "":
            query_opcode = 0
        else:
            try:
                int(query_opcode)
                query_opcode = int(query_opcode)
            except ValueError:
                print "\n[ERROR] Given opcode invalid format!\n[LOG] Opcode sets 'Query'.\n"
                query_opcode = "QUERY"

        query_aa = raw_input("[DNS] Authoritative Answer [Press enter for 0]: ")
        if query_aa == "":
            query_aa = 0
        else:
            try:
                int(query_aa)
                query_aa = int(query_aa)
            except ValueError:
                print "\n[ERROR] Given authoritative number invalid format!\n[LOG] Authoritative number sets 0.\n"
                query_aa = 0

        query_tc = raw_input("[DNS] Truncated [Press enter for 1]: ")
        if query_tc == "":
            query_tc = 0
        else:
            try:
                int(query_tc)
                query_tc = int(query_tc)
            except ValueError:
                print "\n[ERROR] Given truncated number invalid format!\n[LOG] Truncated number sets 1.\n"
                query_tc = 1

        query_rd = raw_input("[DNS] Recursion Desired [Press enter for 0]: ")
        if query_rd == "":
            query_rd = 0
        else:
            try:
                int(query_rd)
                query_rd = int(query_rd)
            except ValueError:
                print "\n[ERROR] Given recursion number invalid format!\n[LOG] Recursion number sets 0.\n"
                query_rd = 0

        query_ra = raw_input("[DNS] Recursion Available [Press enter for 0]: ")
        if query_ra == "":
            query_ra = 0
        else:
            try:
                int(query_ra)
                query_ra = int(query_ra)
            except ValueError:
                print "\n[ERROR] Given recursion avaliable number invalid format!\n[LOG] Recursion available number sets 0.\n"
                query_ra = 0

        query_z = raw_input("[DNS] Reserved [Press enter for 0]: ")
        if query_z == "":
            query_z = 0
        else:
            try:
                int(query_z)
                query_z = int(query_z)
            except ValueError:
                print "\n[ERROR] Given reserved number invalid format!\n[LOG] Reserved number sets 0.\n"
                query_z = 0

        query_rcode = raw_input("[DNS] Response Code [Press enter for 'ok']: ")
        if query_rcode == "":
            query_rcode = 0
        else:
            try:
                int(query_rcode)
                query_rcode = int(query_rcode)
            except ValueError:
                print "\n[ERROR] Given response code invalid format!\n[LOG] Response code sets 'ok'.\n"
                query_rcode = 'ok'

        query_qdcount = raw_input("[DNS] Question Record Count [Press enter for 1]: ")
        if query_qdcount == "":
            query_qdcount = 0
        else:
            try:
                int(query_qdcount)
                query_qdcount = int(query_qdcount)
            except ValueError:
                print "\n[ERROR] Given question record number invalid format!\n[LOG] Question record number sets 1.\n"
                query_qdcount = 1

        query_ancount = raw_input("[DNS] Answer Record Count [Press enter for 0]: ")
        if query_ancount == "":
            query_ancount = 0
        else:
            try:
                int(query_ancount)
                query_ancount = int(query_ancount)
            except ValueError:
                print "\n[ERROR] Given answer record number invalid format!\n[LOG] Answer record number sets 0.\n"
                query_ancount = 0

        query_nscount = raw_input("[DNS] Authority Record Count [Press enter for 0]: ")
        if query_nscount == "":
            query_nscount = 0
        else:
            try:
                int(query_nscount)
                query_nscount = int(query_nscount)
            except ValueError:
                print "\n[ERROR] Given authority record number invalid format!\n[LOG] Authority record number sets 0.\n"
                query_nscount = 0

        query_arcount = raw_input("[DNS] Additional Record Count [Press enter for 0]: ")
        if query_arcount == "":
            query_arcount = 0
        else:
            try:
                int(query_arcount)
                query_arcount = int(query_arcount)
            except ValueError:
                print "\n[ERROR] Given additional record number invalid format!\n[LOG] Additional record number sets 0.\n"
                query_arcount = 0

        query_qd = raw_input("[DNS] qd [Press enter for 0]: ")
        if query_qd == "":
            query_qd = 0
        else:
            try:
                int(query_qd)
                query_qd = int(query_qd)
            except ValueError:
                print "\n[ERROR] Given qd number invalid format!\n[LOG] QD number sets 'None'.\n"
                query_qd = None

        query_an = raw_input("[DNS] an [Press enter for 0]: ")
        if query_an == "":
            query_an = 0
        else:
            try:
                int(query_an)
                query_an = int(query_an)
            except ValueError:
                print "\n[ERROR] Given an number invalid format!\n[LOG] AN number sets 'None'.\n"
                query_an = None

        query_ns = raw_input("[DNS] ns [Press enter for 0]: ")
        if query_ns == "":
            query_ns = 0
        else:
            try:
                int(query_ns)
                query_ns = int(query_ns)
            except ValueError:
                print "\n[ERROR] Given ns number invalid format!\n[LOG] NS number sets 'None'.\n"
                query_ns = None

        query_ar = raw_input("[DNS] ar [Press enter for 0]: ")
        if query_ar == "":
            query_ar = 0
        else:
            try:
                int(query_ar)
                query_ar = int(query_ar)
            except ValueError:
                print "\n[ERROR] Given ar number invalid format!\n[LOG] AR number sets 'None'.\n"
                query_ar = None

        target_domain = TargetDomain()
        dns_server = DNS_Server()

        self.DNS_Packet.id = query_id
        self.DNS_Packet.qr = query_qr
        self.DNS_Packet.opcode = query_opcode
        self.DNS_Packet.aa = query_aa
        self.DNS_Packet.tc = query_tc
        self.DNS_Packet.rd = query_rd
        self.DNS_Packet.ra = query_ra
        self.DNS_Packet.z = query_z
        self.DNS_Packet.rcode = query_rcode
        self.DNS_Packet.qdcount = query_qdcount
        self.DNS_Packet.ancount = query_ancount
        self.DNS_Packet.nscount = query_nscount
        self.DNS_Packet.arcount = query_arcount
        self.DNS_Packet.qd = query_qd
        self.DNS_Packet.an = query_an
        self.DNS_Packet.ns = query_ns
        self.DNS_Packet.ar = query_ar
        self.DNS_Packet.qd = DNSQR(qname=target_domain)
        self.DNS_Packet.rd = 1

        try:
            dns_answer = sr1(IP(dst=dns_server) / UDP(dport=53) / self.DNS_Packet, verbose=0)
            print dns_answer[DNS].summary()
        except:
            print "\n[ERROR] DNS Packet could not send!"
