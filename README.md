# Network Security Assessment Tool

![alt tag](https://s8.postimg.org/ta8dvd76d/NSAT_Team.jpg)

## User Manual
https://github.com/EmreOvunc/Senior-Project-Network-Scanner/blob/master/User-Manual.pdf


![alt tag](https://s30.postimg.org/w797cmd35/NSAT-_GUI.png)

![alt tag](http://emreovunc.com/projects/NSAT-Project.png)

## Requirements

### Ubuntu 16.04.2 LTS|17.02 & Ubuntu Server & Bananian & Raspbian & Kali ARM:
sudo apt-get install python-scapy

sudo apt-get install python-requests

sudo apt install tshark

sudo apt-get install hping3

sudo apt-get install tcpdump

sudo apt-get install python-pyqt5

sudo apt-get install traceroute

sudo apt install nmap

wfuzzer (http://packages.ubuntu.com/tr/yakkety/all/wfuzz/download)
[dpkg -i wfuzz_XXXXX_all.deb]

### Kali 2016v2 & 2017v1:
sudo apt-get install python-pyqt5


# Project

## Project and Problem Description

   Network security is becoming of great importance because of intellectual property that
can be easily acquired through the internet. The security threats and internet protocols should
be analyzed to determine the necessary security technology. A set of tools will be developed
for network threat analysis and attack detection.

   Low-level packet capturing will be performed using tcpdump. The output of tcpdump
processes will be fed into some agent codes (written in C, Python and Java) which will
decode protocols, analyze protocol headers and contents, and filter packets that contain
various types of threats. Some packet generators will also be used to generate adversary
packets and benign packets for the threat identification processes. Following the threat
identification, threat/attack classification will be performed in order to build a dictionary of
threats and attacks for further studies.

![alt tag](https://emreovunc.com/projects/NSAT-UseCase.png)

# Details

## Tools and Systems

### Tcpdump:

   Tcpdump is a common packet analyzer that runs under the command line. It allows
the user to display TCP/IP and other packets being transmitted or received over a network
to which the computer is attached. Distributed under the BSD license, tcpdump is free
software.

### Scapy:

   Scapy is a powerful interactive packet manipulation program. It is able to forge or
decode packets of a wide number of protocols, send them on the wire, capture them,
match requests and replies, and much more. It can easily handle most classical tasks like
scanning, tracerouting, probing, unit tests, attacks or network discovery.

### Hping3:

   Hping is a command-line oriented TCP/IP packet assembler/analyzer. The interface
is inspired to the ping unix command, but hping isn't only able to send ICMP echo
requests. It supports TCP, UDP, ICMP and RAW-IP protocols, has a traceroute mode.

### Libpcap & Python & C#:

   We use packet sniffers in low level programming language using raw sockets.
Libpcap is the packet capture library for linux and has wrappers for most languages. In
python there are multiple libpcap wrappers like pcapy, pypcapy etc.

### Computer Security Lab.:

   We use computer security lab. which is dedicated to performing research in critical
areas of network and systems security in our school to test all steps. There are 12 servers
and 8 desktop computers. Each of them has different operating systems such as Kali Linux,
OpenSUSE, Windows Server 2012 etc. We created an isolated environment from the Internet
to detect real traffics in our networks.
