#!/usr/bin/python

### Pcap Analysis Module ###

from Libraries import *
import binascii
import gzip
import subprocess
import platform
import requests
import json
import urllib2,urllib
import hashlib
try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO
from subprocess import check_output

Packet_Types = ["ARP", "IP", "IPv6"]
Packet_Protocols = ["DHCP", "DNS", "HTTP"]
Transport_Protocols = ["TCP", "UDP", "ICMP"]
UDP_Services = ["mdns", "bootpc", "bootps","netbios_ns"]
DHCP_Msg_Type = ["ack", "request"]
IPv6_Types = ["ICMPv6", "Hop-by-Hop", "UDP"]
userhome = os.path.expanduser('~')
desktop = userhome + '/Desktop/'

if os.path.isdir(desktop+"files"):
    os.system("rm -rf "+desktop+"files")

#### Reading Pcap ####
def Read_Pcap(Pcap_File,virus_check):
    if virus_check == True:
        File_Exct(Pcap_File)
    else:
        startPcap(Pcap_File)

def startPcap(Pcap_File):
    Pcap = rdpcap(Pcap_File)
    Pcap_Len = len(Pcap)
    DetectPacket_Header(Pcap, Pcap_Len)

def DetectPacket_Header(Pcap, Pcap_Len):
    for pkt in range(1, Pcap_Len):
        packetFlag = 0
        for order in range(0, len(Packet_Types)):
            if (Packet_Types[order] == str(Pcap[pkt - 1:pkt]).split(" ")[5][2:]):
                globals()[str(Packet_Types[order]) + "_Header"](Pcap, pkt)
	        packetFlag += 1
	if packetFlag == 0:
	    print "\n###[ Packet "+str(pkt)+" ]###"
	    Pcap[pkt].show()

def DetectPacket_Protocol(Pcap, pkt):
    for protocol_order in range(0, len(Packet_Protocols)):
        if (Packet_Protocols[protocol_order] == str(Pcap[pkt - 1:pkt]).split(" ")[43][2:]):
            globals()[str(Packet_Protocols[protocol_order]) + "_Protocol"](Pcap, pkt)


def DetectTransport_Protocol(Pcap, pkt):
    for transport_order in range(0, len(Transport_Protocols)):
        if (Transport_Protocols[transport_order] == str(Pcap[pkt - 1:pkt]).split(" ")[20][2:]):
            globals()[str(Transport_Protocols[transport_order]) + "_Func"](Pcap, pkt)


def DetectUDP_Services(Pcap, pkt):
    for udp_services in range(0, len(UDP_Services)):
        if (UDP_Services[udp_services] == str(Pcap[pkt - 1:pkt]).split(" ")[22][6:]):
            globals()[str(UDP_Services[udp_services])](Pcap, pkt)


def DetectIPv6_Types(Pcap, pkt):
    for ipv6_types in range(0, len(IPv6_Types)):
        if (IPv6_Types[ipv6_types] == str(Pcap[pkt - 1:pkt]).split(" ")[11][3:]):
            if IPv6_Types[ipv6_types] == "Hop-by-Hop":
                IPv6_HopbyHop_v6(Pcap, pkt)
            else:
                globals()[str(IPv6_Types[ipv6_types]) + "_v6"](Pcap, pkt)

def File_Exct(Pcap_File):
    try:
        f1 = open('/usr/share/wireshark/init.lua', 'r+')
        f2 = open('/usr/share/wireshark/init.lua', 'r+')
        for line in f1:
            f2.write(line.replace('disable_lua = true', 'disable_lua = false'))
        f1.close()
        f2.close()
    except:
        pass
    if not os.path.isdir(desktop+"files"):
        os.makedirs(desktop+"files")
    outdirr = desktop + "files/"

    def parse_http_stream(matching_item):
      end_of_header=-1
      file_bytes=binascii.unhexlify(matching_item[1].replace(":","").strip("\""))
      try:
        end_of_header=file_bytes.index('\r\n\r\n')+4
      except ValueError:
        return
      if 'Content-Encoding: gzip' in file_bytes[:end_of_header]:
        buf=StringIO(file_bytes[end_of_header:])
        f = gzip.GzipFile(fileobj=buf)
        file_bytes = f.read()
      else:
        file_bytes = file_bytes[end_of_header:]
      return ["http_stream_"+matching_item[2].strip("\""),file_bytes]

    def parse_smb_stream(matching_item):
      file_bytes=binascii.unhexlify(matching_item[4].replace(":","").strip("\""))
      return ["smb_id_" + matching_item[3].strip("\""), file_bytes]

    def parse_tftp_stream(matching_item):
      file_bytes=binascii.unhexlify(matching_item[5].replace('\"','').replace(":",""))
      file_name=""
      file_name="tftp_stream_" + matching_item[6].strip("\"")

      return [file_name,file_bytes]

    def extract_files(outdir, infile, displayfilter):
      if displayfilter=='':
        hex_stream_data_list = check_output(["tshark", "-r", infile, "-Y", "(http.content_length > 0 || (smb.file_data && smb.remaining==0) || ftp-data || tftp.opcode==3)", "-T", "fields", "-e", "_ws.col.Protocol", "-e", "tcp.reassembled.data", "-e", "tcp.stream", "-e", "smb.fid", "-e", "smb.file_data","-e", "data", "-e", "tftp.source_file", "-e", "tftp.destination_file", "-e", "udp.srcport", "-e", "udp.dstport", "-E", "quote=d","-E", "occurrence=a", "-E", "separator=|"]).split()
      else:
        hex_stream_data_list = check_output(["tshark", "-r", infile, "-Y", displayfilter + " && (http.content_length > 0 || (smb.file_data && smb.remaining==0) || ftp-data || tftp.opcode==3)", "-T", "fields", "-e", "_ws.col.Protocol", "-e", "tcp.reassembled.data", "-e", "tcp.stream", "-e", "smb.fid", "-e", "smb.file_data","-e", "data", "-e", "tftp.source_file", "-e", "tftp.destination_file", "-e", "udp.srcport", "-e", "udp.dstport", "-E", "quote=d","-E", "occurrence=a", "-E", "separator=|"]).split()
      ftp_data_streams=[]
      reassembled_streams=[]
      for matching_item in hex_stream_data_list:
        x_item=matching_item.split("|")
        x_protocol=x_item[0].strip("\"")
        if (x_protocol=='HTTP' or x_protocol=='HTTP/XML'):
          parsed_stream = parse_http_stream(x_item)
          if parsed_stream is not None:
            search_index=[x for x,y in enumerate(reassembled_streams) if parsed_stream[0] in y[0]]
            if len(search_index)>0:
              parsed_stream[0]=parsed_stream[0]+"_"+str(len(search_index))
            reassembled_streams.append(parsed_stream)
        elif x_protocol=='SMB':
          parsed_stream = parse_smb_stream(x_item)
          search_index=[x for x,y in enumerate(reassembled_streams) if (y[0])==parsed_stream[0]]
          if len(search_index)>0:
            reassembled_streams[search_index[0]][1]=reassembled_streams[search_index[0]][1]+parsed_stream[1]
          else:
            reassembled_streams.append(parsed_stream)
        elif x_protocol=='TFTP':
          parsed_stream = parse_tftp_stream(x_item)
          search_index=[x for x,y in enumerate(reassembled_streams) if (y[0])==parsed_stream[0]]
          if len(search_index)>0:
            reassembled_streams[search_index[0]][1]=reassembled_streams[search_index[0]][1]+parsed_stream[1]
          else:
            reassembled_streams.append(parsed_stream)
        elif x_protocol=='FTP-DATA':
          ftp_data_streams.append(x_item[2].strip("\""))
        elif x_protocol!='':
          pass

      for reassembled_item in reassembled_streams:
        fh=open(os.path.join(outdir,reassembled_item[0]),'w')
        fh.write(reassembled_item[1])
        fh.close()

      for stream_number in ftp_data_streams:
        hex_stream_list = check_output(["tshark", "-q", "-n", "-r", infile, "-z", "follow,tcp,raw," + stream_number]).split("\n")
        list_length = len(hex_stream_list)
        hex_stream_text = ''.join(hex_stream_list[6:list_length-2])
        file_bytes=binascii.unhexlify(hex_stream_text)
        fh=open(os.path.join(outdir,'ftp_stream_'+stream_number),'w')
        fh.write(file_bytes)
        fh.close()
    extract_files(outdirr,Pcap_File,"")
    detect_exe(outdirr)
    try:
        f1 = open('/usr/share/wireshark/init.lua', 'r+')
        f2 = open('/usr/share/wireshark/init.lua', 'r+')
        for line in f1:
            f2.write(line.replace('disable_lua = true', 'disable_lua = false'))
        f1.close()
        f2.close()
    except:
        pass

def detect_exe(outdirr):
    global vt
    none = 0
    for file in os.listdir(outdirr):
        mime = subprocess.Popen("/usr/bin/file " + outdirr + file, shell=True,stdout=subprocess.PIPE).communicate()[0]
        if "executable" in mime:
            try:
                vt = vt()
                vt.scanfile(outdirr+file)
                vt.out('print')
                vt.getfile(outdirr+file)
                none = + 1
            except:
                print "[ERROR] Virus scan module does not load!"
    if none == 0:
        print "[LOG] Malicious File Not Found."

class vt:
    def __init__(self):
        try:
            import requests
        except:
            print '[Warning] request module is missing. requests module is required in order to upload new files for scan.\nYou can install it by running: pip install requests.'

        self.api_key = '8b83c9e609de18877677ec074bcdde6193f1660b7940f0d218a5700137f153d1'
        self.api_url = 'https://www.virustotal.com/vtapi/v2/'
        self._output = "print"
        self.errmsg = 'Something went wrong. Please try again later, or contact us.'

    def handleHTTPErros(self, code):
        if code == 404:
            print self.errmsg + '\n[Error 404].'
            return 0
        elif code == 403:
            print 'You do not have permissions to make that call.\nThat should not have happened, please contact us.\n[Error 403].'
            return 0
        elif code == 204:
            print 'The quota limit has exceeded, please wait and try again soon.\nIf this problem continues, please contact us.\n[Error 204].'
            return 0
        else:
            print self.errmsg + '\n[Error ' + str(code) + ']'
            return 0

    def out(self, xformat):
        if xformat == "print":
            self._output = "print"
        elif xformat == "html":
            self._output = "html"
        else:
            self._output = "json"

    def scanfile(self, file):
        url = self.api_url + "file/scan"
        files = {'file': open(file, 'rb')}
        headers = {"apikey": self.api_key}
        try:
            response = requests.post(url, files=files, data=headers)
            xjson = response.json()
            response_code = xjson['response_code']
            verbose_msg = xjson['verbose_msg']
            if response_code == 1:
                print verbose_msg
                return xjson
            else:
                print verbose_msg

        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print '[ERROR] Generic Exception: ' + traceback.format_exc()

    def getfile(self, file):
        if os.path.isfile(file):
            f = open(file, 'rb')
            file = hashlib.sha256(f.read()).hexdigest()
            f.close()
        url = self.api_url + "file/report"
        parameters = {"resource": file, "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        try:
            response = urllib2.urlopen(req)
            xjson = response.read()
            response_code = json.loads(xjson).get('response_code')
            verbose_msg = json.loads(xjson).get('verbose_msg')
            if response_code == 1:
                print verbose_msg
                return self.report(xjson)
            else:
                print verbose_msg

        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()

    def report(self, jsonx):
        avlist = []
        jsonx = json.loads(jsonx)
        total = jsonx.get('total')
        positive = jsonx.get('positives')
        print '\nDetection ratio: ' + str(positive) + "/" + str(total)
        scans = jsonx.get('scans')
        for av in scans.iterkeys():
            res = scans.get(av)
            if res.get('detected') == True:
                avlist.append('+ ' + av + ':  ' + res.get('result'))
        if positive > 0:
            print "[DETECTION] Malicious File Found!"
            print ("Possible Type: " + str((str(avlist[2]).split(":"))[1]))
            return avlist
        else:
            print "[LOG] Malicious File Not Found!"
            return 0

    def setkey(self, key):
        self.api_key = key

def DetectEther_Frame(Pcap,pkt):
    print "\n[Ether]Destination MAC =", str(Pcap[pkt - 1:pkt]).split(" ")[2][4:]
    print "[Ether]Source MAC =", str(Pcap[pkt - 1:pkt]).split(" ")[3][4:]
    print "[Ether]Type =", str(Pcap[pkt - 1:pkt]).split(" ")[4][5:],"\n"

def netbios_ns(Pcap,pkt):
    print "\n[NBNS]Netbios Type =", str(Pcap[pkt - 1:pkt]).split(" ")[26][6:]
    print "[NBNS]Name TRN ID =", str(Pcap[pkt - 1:pkt]).split(" ")[28][12:]
    print "[NBNS]Flags =", str(Pcap[pkt - 1:pkt]).split(" ")[29][6:]
    print "[NBNS]QDCount =", str(Pcap[pkt - 1:pkt]).split(" ")[30][8:]
    print "[NBNS]ANCount =", str(Pcap[pkt - 1:pkt]).split(" ")[31][8:]
    print "[NBNS]NSCount =", str(Pcap[pkt - 1:pkt]).split(" ")[32][8:]
    print "[NBNS]ARCount =", str(Pcap[pkt - 1:pkt]).split(" ")[33][8:]
    print "[NBNS]Question NA ME =", str(Pcap[pkt - 1:pkt]).split(" ")[34][14:]
    print "[NBNS]Suffix =", str(Pcap[pkt - 1:pkt]).split(" ")[35][7:]
    print "[NBNS]Null =", str(Pcap[pkt - 1:pkt]).split(" ")[36][5:]
    print "[NBNS]Question Type =", str(Pcap[pkt - 1:pkt]).split(" ")[37][14:]
    print "[NBNS]Question Class =", str(Pcap[pkt - 1:pkt]).split(" ")[38][15:]

def ICMP_Func(Pcap, pkt):
    print "\n[ICMP]ICMP-Type =", str(Pcap[pkt - 1:pkt]).split(" ")[22][5:]
    print "[ICMP]Code =", str(Pcap[pkt - 1:pkt]).split(" ")[23][5:]
    print "[ICMP]Checksum =", str(Pcap[pkt - 1:pkt]).split(" ")[24][7:]
    print "[ICMP]Unused =", str(Pcap[pkt - 1:pkt]).split(" ")[25][7:]

    IPerror(Pcap, pkt)
    ICMPerror(Pcap, pkt)


def IPerror(Pcap, pkt):
    print "\n[IPerror]Version =", str(Pcap[pkt - 1:pkt]).split(" ")[28][8:]
    print "[IPerror]Internet Header Length (IHL) =", str(Pcap[pkt - 1:pkt]).split(" ")[29][4:]
    print "[IPerror]Type of Service (ToS) =", str(Pcap[pkt - 1:pkt]).split(" ")[30][4:]
    print "[IPerror]Length =", str(Pcap[pkt - 1:pkt]).split(" ")[31][4:]
    print "[IPerror]ID =", str(Pcap[pkt - 1:pkt]).split(" ")[32][3:]

    if (str(Pcap[pkt - 1:pkt]).split(" ")[33])[6:] != "":
        print "[IPerror]Flags =", str(Pcap[pkt - 1:pkt]).split(" ")[33][6:]

    print "[IPerror]Fragment =", str(Pcap[pkt - 1:pkt]).split(" ")[34][5:]
    print "[IPerror]Time to Live (TTL) =", str(Pcap[pkt - 1:pkt]).split(" ")[35][4:]
    print "[IPerror]Protocol =", str(Pcap[pkt - 1:pkt]).split(" ")[36][6:]
    print "[IPerror]Checksum =", str(Pcap[pkt - 1:pkt]).split(" ")[37][7:]
    print "[IPerror]Source IP =", str(Pcap[pkt - 1:pkt]).split(" ")[38][4:]
    print "[IPerror]Destination IP =", str(Pcap[pkt - 1:pkt]).split(" ")[39][4:]


def ICMPerror(Pcap, pkt):
    print "\n[ICMPerror]Type =", str(Pcap[pkt - 1:pkt]).split(" ")[43][5:]
    print "[ICMPerror]Code =", str(Pcap[pkt - 1:pkt]).split(" ")[44][5:]
    print "[ICMPerror]Checksum =", str(Pcap[pkt - 1:pkt]).split(" ")[45][7:]
    print "[ICMPerror]ID =", str(Pcap[pkt - 1:pkt]).split(" ")[46][3:]
    print "[ICMPerror]Sequence =", str(Pcap[pkt - 1:pkt]).split(" ")[47][4:]


def bootpc(Pcap, pkt):
    print "\n[BOOTP]Service =", str(Pcap[pkt - 1:pkt]).split(" ")[26][2:]
    print "[BOOTP]Op Code =", str(Pcap[pkt - 1:pkt]).split(" ")[28][3:]
    print "[BOOTP]Hardware Address Type =", str(Pcap[pkt - 1:pkt]).split(" ")[29][6:]
    print "[BOOTP]Hardware Length =", str(Pcap[pkt - 1:pkt]).split(" ")[30][5:]
    print "[BOOTP]Hops =", str(Pcap[pkt - 1:pkt]).split(" ")[31][5:]
    print "[BOOTP]Transaction Identifier =", str(Pcap[pkt - 1:pkt]).split(" ")[32][4:]
    print "[BOOTP]Seconds =", str(Pcap[pkt - 1:pkt]).split(" ")[33][5:]
    print "[BOOTP]Flags =", str(Pcap[pkt - 1:pkt]).split(" ")[34][6:]
    print "[BOOTP]Client IP Address =", str(Pcap[pkt - 1:pkt]).split(" ")[35][7:]
    print "[BOOTP]Your IP Address =", str(Pcap[pkt - 1:pkt]).split(" ")[36][7:]
    print "[BOOTP]Server IP Address =", str(Pcap[pkt - 1:pkt]).split(" ")[37][7:]
    print "[BOOTP]Gateway IP Address =", str(Pcap[pkt - 1:pkt]).split(" ")[38][7:]
    print "[BOOTP]Client Hardware Address Raw =", str(Pcap[pkt - 1:pkt]).split(" ")[39][7:]
    print "[BOOTP]Server Name Raw =", str(Pcap[pkt - 1:pkt]).split(" ")[40][6:]
    print "[BOOTP]Boot File Name Raw =", str(Pcap[pkt - 1:pkt]).split(" ")[41][5:]


##        print "[BOOTP]Options =", str(Pcap[pkt-1:pkt]).split(" ")[42][8:]

def bootps(Pcap, pkt):
    print "\n[BOOTP]Service =", str(Pcap[pkt - 1:pkt]).split(" ")[26][2:]
    print "[BOOTP]Op Code =", str(Pcap[pkt - 1:pkt]).split(" ")[28][3:]
    print "[BOOTP]Hardware Address Type =", str(Pcap[pkt - 1:pkt]).split(" ")[29][6:]
    print "[BOOTP]Hardware Length =", str(Pcap[pkt - 1:pkt]).split(" ")[30][5:]
    print "[BOOTP]Hops =", str(Pcap[pkt - 1:pkt]).split(" ")[31][5:]
    print "[BOOTP]Transaction Identifier =", str(Pcap[pkt - 1:pkt]).split(" ")[32][4:]
    print "[BOOTP]Seconds =", str(Pcap[pkt - 1:pkt]).split(" ")[33][5:]
    print "[BOOTP]Flags =", str(Pcap[pkt - 1:pkt]).split(" ")[34][6:]
    print "[BOOTP]Client IP Address =", str(Pcap[pkt - 1:pkt]).split(" ")[35][7:]
    print "[BOOTP]Your IP Address =", str(Pcap[pkt - 1:pkt]).split(" ")[36][7:]
    print "[BOOTP]Server IP Address =", str(Pcap[pkt - 1:pkt]).split(" ")[37][7:]
    print "[BOOTP]Gateway IP Address =", str(Pcap[pkt - 1:pkt]).split(" ")[38][7:]
    print "[BOOTP]Client Hardware Address Raw =", str(Pcap[pkt - 1:pkt]).split(" ")[39][7:]
    print "[BOOTP]Server Name Raw =", str(Pcap[pkt - 1:pkt]).split(" ")[40][6:]
    print "[BOOTP]Boot File Name Raw =", str(Pcap[pkt - 1:pkt]).split(" ")[41][5:]


##        print "[BOOTP]Options =", str(Pcap[pkt-1:pkt]).split(" ")[42][8:]

def IGMP(Pcap, pkt):
    pass


def mdns(Pcap, pkt):
    print "\n[MDNS]Raw Data =", str(Pcap[pkt - 1:pkt]).split(" ")[28][5:]


def UDP_Func(Pcap, pkt):
    print "\n[UDP]Transport Protocol =", str(Pcap[pkt - 1:pkt]).split(" ")[20][2:]
    print "[UDP]Source Port =", str(Pcap[pkt - 1:pkt]).split(" ")[22][6:]
    print "[UDP]Destination Port =", str(Pcap[pkt - 1:pkt]).split(" ")[23][6:]
    print "[UDP]Length =", str(Pcap[pkt - 1:pkt]).split(" ")[24][4:]
    print "[UDP]Checksum =", str(Pcap[pkt - 1:pkt]).split(" ")[25][7:]

    DetectUDP_Services(Pcap, pkt)
    if (str(Pcap[pkt - 1:pkt]).split(" ")[26] == "|<LLMNRQuery"):
        LLMNR(Pcap,pkt)

def LLMNR(Pcap,pkt):
    print "\n[LLMNR]ID =", (str(Pcap[pkt - 1:pkt]).split(" ")[28])[3:]
    print "[LLMNR]QR =", (str(Pcap[pkt - 1:pkt]).split(" ")[29])[3:]
    print "[LLMNR]OP Code =", (str(Pcap[pkt - 1:pkt]).split(" ")[30])[7:]
    print "[LLMNR]C =", (str(Pcap[pkt - 1:pkt]).split(" ")[31])[2:]
    print "[LLMNR]TC =", (str(Pcap[pkt - 1:pkt]).split(" ")[32])[3:]
    print "[LLMNR]Z =", (str(Pcap[pkt - 1:pkt]).split(" ")[32])[3:]
    print "[LLMNR]R Code =", (str(Pcap[pkt - 1:pkt]).split(" ")[33])[2:]
    print "[LLMNR]QD Count =", (str(Pcap[pkt - 1:pkt]).split(" ")[34])[6:]
    print "[LLMNR]AN Count =", (str(Pcap[pkt - 1:pkt]).split(" ")[35])[8:]
    print "[LLMNR]NS Count =", (str(Pcap[pkt - 1:pkt]).split(" ")[36])[8:]
    print "[LLMNR]AR Count =", (str(Pcap[pkt - 1:pkt]).split(" ")[37])[8:]
    print "[LLMNR]QD =", (str(Pcap[pkt - 1:pkt]).split(" ")[39])[4:]
    print "[LLMNR]Q Name =", (str(Pcap[pkt - 1:pkt]).split(" ")[41])[6:]
    print "[LLMNR]Q Type =", (str(Pcap[pkt - 1:pkt]).split(" ")[42])[6:]
    print "[LLMNR]Q Class =", (str(Pcap[pkt - 1:pkt]).split(" ")[43])[7:]

def TCP_Func(Pcap, pkt):
    print "\n[TCP]Transport Protocol =", str(Pcap[pkt - 1:pkt]).split(" ")[20][2:]
    print "[TCP]Source Port =", str(Pcap[pkt - 1:pkt]).split(" ")[22][6:]
    print "[TCP]Destination Port =", str(Pcap[pkt - 1:pkt]).split(" ")[23][6:]
    print "[TCP]Sequence Number =", str(Pcap[pkt - 1:pkt]).split(" ")[24][4:]
    print "[TCP]ACK Number =", str(Pcap[pkt - 1:pkt]).split(" ")[25][4:]
    print "[TCP]Data offset =", str(Pcap[pkt - 1:pkt]).split(" ")[26][8:]
    print "[TCP]Reserved =", str(Pcap[pkt - 1:pkt]).split(" ")[27][9:]
    print "[TCP]Flags =", str(Pcap[pkt - 1:pkt]).split(" ")[28][6:]
    print "[TCP]Window Size =", str(Pcap[pkt - 1:pkt]).split(" ")[29][7:]
    print "[TCP]Checksum =", str(Pcap[pkt - 1:pkt]).split(" ")[30][7:]
    print "[TCP]Urgent Pointer =", str(Pcap[pkt - 1:pkt]).split(" ")[31][7:]


##        print "[TCP]Options =", str(Pcap[pkt-1:pkt]).split(" ")[31][7:]

def DHCP_Protocol(Pcap, pkt):
    print "\n[DHCP]Protocol =", str(Pcap[pkt - 1:pkt]).split(" ")[43][2:]
    print "[DHCP]Message Type =", str(Pcap[pkt - 1:pkt]).split(" ")[45][22:]

    for type_order in range(0, len(DHCP_Msg_Type)):
        if DHCP_Msg_Type[type_order] == str(Pcap[pkt - 1:pkt]).split(" ")[45][22:]:
            globals()["DHCP_" + str(DHCP_Msg_Type[type_order])](Pcap, pkt)


def DHCP_ack(Pcap, pkt):
    print "[DHCP-ACK]Server ID =", str(Pcap[pkt - 1:pkt]).split(" ")[46][10:]
    print "[DHCP-ACK]Lease Time =", str(Pcap[pkt - 1:pkt]).split(" ")[47][11:]
    print "[DHCP-ACK]Subnet Mask =", str(Pcap[pkt - 1:pkt]).split(" ")[48][12:]
    print "[DHCP-ACK]Domain =", str(Pcap[pkt - 1:pkt]).split(" ")[49][7:]
    print "[DHCP-ACK]Router =", str(Pcap[pkt - 1:pkt]).split(" ")[50][7:]
    print "[DHCP-ACK]Name Server =", str(Pcap[pkt - 1:pkt]).split(" ")[51][12:]
    print "[DHCP-ACK]NetBIOS Server =", str(Pcap[pkt - 1:pkt]).split(" ")[52][15:]


def DHCP_request(Pcap, pkt):
    print "[DHCP-Request]Client ID =", str(Pcap[pkt - 1:pkt]).split(" ")[47][9:]
    print "[DHCP-Request]Requested IP =", str(Pcap[pkt - 1:pkt]).split(" ")[49][15:]
    print "[DHCP-Request]Hostname =", str(Pcap[pkt - 1:pkt]).split(" ")[50][9:]
    print "[DHCP-Request]Vendor ID =", str(Pcap[pkt - 1:pkt]).split(" ")[51][15:]


def IP_Header(Pcap, pkt):
    print "\n################# Packet[" + str(pkt) + "] #################"

    DetectEther_Frame(Pcap, pkt)

    print "[IP]Packet Header =", (str(Pcap[pkt - 1:pkt]).split(" ")[5])[2:]
    print "[IP]Version =", (str(Pcap[pkt - 1:pkt]).split(" ")[7])[8:]
    print "[IP]Internet Header Length (IHL) =", (str(Pcap[pkt - 1:pkt]).split(" ")[8])[4:]
    print "[IP]Type of Service (ToS) =", (str(Pcap[pkt - 1:pkt]).split(" ")[9])[4:]
    print "[IP]Length =", (str(Pcap[pkt - 1:pkt]).split(" ")[10])[4:]
    print "[IP]Id =", (str(Pcap[pkt - 1:pkt]).split(" ")[11])[3:]

    if (str(Pcap[pkt - 1:pkt]).split(" ")[12])[6:] != "":
        print "[IP]Flags =", (str(Pcap[pkt - 1:pkt]).split(" ")[12])[6:]

    print "[IP]Frag =", (str(Pcap[pkt - 1:pkt]).split(" ")[13])[5:]
    print "[IP]Time to Live (TTL) =", (str(Pcap[pkt - 1:pkt]).split(" ")[14])[4:]
    print "[IP]Protocol =", (str(Pcap[pkt - 1:pkt]).split(" ")[15])[6:]
    print "[IP]Checksum =", (str(Pcap[pkt - 1:pkt]).split(" ")[16])[7:]
    print "[IP]Source IP =", (str(Pcap[pkt - 1:pkt]).split(" ")[17])[4:]
    print "[IP]Destionation IP =", (str(Pcap[pkt - 1:pkt]).split(" ")[18])[4:]

    ##        if (str(Pcap[pkt-1:pkt]).split(" ")[19])[8:10] != "[]":
    ##                print "Options =",(str(Pcap[pkt-1:pkt]).split(" ")[19])[8:]

    if str(Pcap[pkt - 1:pkt]).split(" ")[15][6:] != "igmp":
        DetectTransport_Protocol(Pcap, pkt)
    else:
        IGMP(Pcap, pkt)


def ICMPv6_ND(Pcap, pkt):
    if (str(Pcap[pkt - 1:pkt]).split(" ")[24])[5:] != "":
        print "\n[ICMPv6-ND]Type =", (str(Pcap[pkt - 1:pkt]).split(" ")[24])[5:]
        print "[ICMPv6-ND]Length =", (str(Pcap[pkt - 1:pkt]).split(" ")[25])[4:]

        if (str(Pcap[pkt - 1:pkt]).split(" ")[26][7:] != ""):
            print "[ICMPv6-ND]LLAddr =", (str(Pcap[pkt - 1:pkt]).split(" ")[26])[7:]


def IPv6_HopbyHop_v6(Pcap, pkt):
    print "\n[IPv6-Hop]Next Header =", (str(Pcap[pkt - 1:pkt]).split(" ")[19])[3:]
    print "[IPv6-Hop]Length =", (str(Pcap[pkt - 1:pkt]).split(" ")[20])[4:]
    print "[IPv6-Hop]Autopad =", (str(Pcap[pkt - 1:pkt]).split(" ")[21])[8:]
    print "[IPv6-Hop]Options =", (str(Pcap[pkt - 1:pkt]).split(" ")[24:31])
    print "[IPv6-Hop]Opt. Length =", (str(Pcap[pkt - 1:pkt]).split(" ")[31][7:])
    print "[IPv6-Hop]Opt. Data =", (str(Pcap[pkt - 1:pkt]).split(" ")[32][8:])
    print "[IPv6-Hop]Raw Load =", (str(Pcap[pkt - 1:pkt]).split(" ")[36][5:])


def ICMPv6_v6(Pcap, pkt):
    print "\n[ICMPv6]Type =", (str(Pcap[pkt - 1:pkt]).split(" ")[17])[5:] + " " + (
    str(Pcap[pkt - 1:pkt]).split(" ")[18])
    print "[ICMPv6]Code =", (str(Pcap[pkt - 1:pkt]).split(" ")[19])[5:]
    print "[ICMPv6]Checksum =", (str(Pcap[pkt - 1:pkt]).split(" ")[20])[6:]

    if str(Pcap[pkt - 1:pkt]).split(" ")[21][4:] != "":
        print "[ICMPv6]Res =", (str(Pcap[pkt - 1:pkt]).split(" ")[21])[4:]

    try:
        ICMPv6_ND(Pcap, pkt)
    except:
        pass


def IPv6_Header(Pcap, pkt):
    print "\n################# Packet[" + str(pkt) + "] #################"

    DetectEther_Frame(Pcap, pkt)

    print "[IPv6]Packet Header =", (str(Pcap[pkt - 1:pkt]).split(" ")[5])[2:]
    print "[IPv6]Version =", (str(Pcap[pkt - 1:pkt]).split(" ")[7])[8:]
    print "[IPv6]Traffic Class (TC) =", (str(Pcap[pkt - 1:pkt]).split(" ")[8])[3:]
    print "[IPv6]Flow Label (FL) =", (str(Pcap[pkt - 1:pkt]).split(" ")[9])[3:]
    print "[IPv6]Payload Length =", (str(Pcap[pkt - 1:pkt]).split(" ")[10])[5:]
    print "[IPv6]Next Header =", (str(Pcap[pkt - 1:pkt]).split(" ")[11])[3:]

    if (str(Pcap[pkt - 1:pkt]).split(" ")[12] == "Option"):
        print "[IPv6]Hop Limit =", (str(Pcap[pkt - 1:pkt]).split(" ")[14])[5:]
        print "[IPv6]Source MAC =", (str(Pcap[pkt - 1:pkt]).split(" ")[15])[4:]
        print "[IPv6]Destination MAC =", (str(Pcap[pkt - 1:pkt]).split(" ")[16])[4:]
    else:
        print "[IPv6]Hop Limit =", (str(Pcap[pkt - 1:pkt]).split(" ")[12])[5:]
        print "[IPv6]Source MAC =", (str(Pcap[pkt - 1:pkt]).split(" ")[13])[4:]
        print "[IPv6]Destination MAC =", (str(Pcap[pkt - 1:pkt]).split(" ")[14])[4:]

    DetectIPv6_Types(Pcap, pkt)

def UDP_v6(Pcap, pkt):
    print "\n[UDP]Source Port =", (str(Pcap[pkt - 1:pkt]).split(" ")[17])[6:]
    print "[UDP]Destination Port =", (str(Pcap[pkt - 1:pkt]).split(" ")[18])[6:]
    print "[UDP]Length =", (str(Pcap[pkt - 1:pkt]).split(" ")[19])[4:]
    print "[UDP]Checksum =", (str(Pcap[pkt - 1:pkt]).split(" ")[20])[7:]
    try:
        if (str(Pcap[pkt - 1:pkt]).split(" ")[23][0:4] == "load"):
            print "\n[MDNS]Raw Data =", str(Pcap[pkt - 1:pkt]).split(" ")[23][5:]
    except:
        pass

def ARP_Header(Pcap, pkt):
    print "\n################# Packet[" + str(pkt) + "] #################"

    DetectEther_Frame(Pcap,pkt)

    print "[ARP]Packet Header =", (str(Pcap[pkt - 1:pkt]).split(" ")[5])[2:]
    print "[ARP]Hardware Type =", (str(Pcap[pkt - 1:pkt]).split(" ")[7][7:])
    print "[ARP]Transportation Type =", (str(Pcap[pkt - 1:pkt]).split(" ")[8])[7:]
    print "[ARP]Hardware Address Length =", (str(Pcap[pkt - 1:pkt]).split(" ")[9])[6:]
    print "[ARP]Protocol Address Length =", (str(Pcap[pkt - 1:pkt]).split(" ")[10])[5:]
    print "[ARP]Op Code =", (str(Pcap[pkt - 1:pkt]).split(" ")[11])[3:]
    print "[ARP]Source MAC =", (str(Pcap[pkt - 1:pkt]).split(" ")[12])[6:]
    print "[ARP]Source IP =", (str(Pcap[pkt - 1:pkt]).split(" ")[13])[5:]
    print "[ARP]Destination MAC =", (str(Pcap[pkt - 1:pkt]).split(" ")[14])[6:]
    print "[ARP]Destination IP =", (str(Pcap[pkt - 1:pkt]).split(" ")[15])[5:]

    try:
        if (str(Pcap[pkt - 1:pkt]).split(" ")[16]) != "|>>]":
            Padding(Pcap, pkt)
    except:
        pass


def Padding(Pcap, pkt):
    print "\n[Padding]Load Raw =", (str(Pcap[pkt - 1:pkt]).split(" ")[18])[5:]
