#!/usr/bin/python

### Recon Module ###

from Libraries import *
from Attack_Module import HostControl

Scan_Types = ["subdomain","portscan","banner","traceroute"]

server = [ "www", "www1" , "www2", "ns", "ns1" , "ns2" ,"dns", "dns1", "dns2", "dns3", "pop", "mail", "smtp",
        "pop3", "test", "dev", "ads", "adserver", "adsl", "agent", "channel", "dmz", "sz", "client", "imap",
        "http", "https", "ftp", "ftpserver", "tftp", "ntp", "ids", "ips", "snort", "imail", "pops",
        "imaps", "irc", "linux", "windows", "log", "install", "blog", "host", "printer", "public", "sql",
        "mysql", "router", "cisco", "switch", "telnet", "voip", "webmin", "ssh", "delevlop", "pub", "root",
        "user", "xml", "ww", "telnet", "extern", "intranet", "extranet", "testing", "default", "gateway",
        "radius", "noc", "mobile", "customer", "chat", "siprouter", "sip", "nms", "noc", "office",
        "voice", "support", "spare", "owa", "exchange"]

server_ans = []
portStart = 1
portEnd = 444

def Scan_Module(scan_type):
    for order in range(0, len(Scan_Types)):
        if (Scan_Types[order] == scan_type):
            globals()[str(Scan_Types[order])]()

def subdomain():
    targetDomain = TargetDomain()
    dnsServer = raw_input("DNS Server IP [Press enter for '8.8.8.8']: ")
    if dnsServer == "":
        dnsServer = "8.8.8.8"
    else:
        dnsServer = HostControl(dnsServer)

    for i in range (0, len(server)):
        Query = server[i] + "." + targetDomain

        dns_obj = dns_("auto","attack")
        dns_obj.DNS_Packet.rd = 1
        dns_obj.DNS_Packet.qd = DNSQR(qname=Query)

        ans = sr1(IP(dst=dnsServer)/UDP(sport=RandShort())/dns_obj.DNS_Packet,verbose=0)
        if ans[DNS].ancount != 0:
            server_ans.insert(i,ans[DNSRR].rdata)
        else:
            server_ans.insert(i, "Unkown")

    for i in range(0, len(server)):
        if server_ans[i] != "Unkown":
            try:
                if int(server_ans[i].split(".")[0]) <= 255:
                    print server[i] + "." + targetDomain, server_ans[i]
            except:
                pass

def traceroute():
    targetDomain = TargetDomain()
    os.system("traceroute "+targetDomain)

def portscan():
    if portStart == 80:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.01)
        try:
            con = s.connect((portEnd, 80))
            return True
        except:
            return False

    else:
        targetDomain = TargetDomain()
        for x in range(portStart, portEnd):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.01)
            try:
                con = s.connect((targetDomain, x))
                port = True
            except:
                port = False
            if port == True:
                print 'Port', x, '-> OPEN'

def banner():
    targetDomain = TargetDomain()
    try:
        s = socket.socket()
        s.connect((targetDomain, 80))
        s.send(b'GET /\n\n')
        print(s.recv(10000))
    except:
        print "[ERROR] Target connection failed, try again later!"
