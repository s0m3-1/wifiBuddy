import os, sys
from scapy.layers.dot11 import Dot11 # Wireless LAN according to IEEE 802.11
from scapy.layers.dot11 import Dot11Beacon # Transmit AP information
from scapy.layers.dot11 import Dot11Elt # Information Element
from scapy.layers.dot11 import Dot11ProbeResp
from scapy.layers.eap import EAPOL
from scapy.all import sniff

from .accessPoint import AccessPoint
from .client import Client
from .utils import Util

specialMACadresses = ["ff:ff:ff:ff:ff:ff", "33:33:00:00:00:0c"]

class WifiAdapter():
    iface = None
    foundAPs = None
    foundClients = {}
    helper = None
    aController = None


    def __init__(self, iface):
        self.iface = iface
        self.setup_monitor()
        self.foundAPs = {}
        self.foundClients = {}



    def setup_monitor (self):
        print("Setting up sniff options...")
        os.system('ifconfig ' + self.iface + ' down')
        try:
            os.system('iwconfig ' + self.iface + ' mode monitor')
        except:
            print ("Failed to setup monitor mode")
            sys.exit(1)
        os.system('ifconfig ' + self.iface + ' up')


    def startSniffingAPs(self, callback, updateFunc):
        print("Sniffing for access points " + str(self.iface) + "...")
        for channel in range(1, 14):
            os.system("iwconfig " + self.iface + " channel " + str(channel))
            print("Sniffing for APs on interface " + str(self.iface) + " channel " + str(channel) + "...")
            sniff(iface=self.iface, prn=updateFunc(callback()), store=0, count=1000, timeout=10)
        print("finished")

    def startSniffingClients(self, callback, updateFunc):
        print("Sniffing for clients " + str(self.iface) + "...")
        for channel in range(1, 14):
            os.system("iwconfig " + self.iface + " channel " + str(channel))
            print("Sniffing for clients on interface " + str(self.iface) + " channel " + str(channel) + "...")
            sniff(iface=self.iface, prn=updateFunc(callback()), store=0, count=10, timeout=5)
        print("finished")

    def startSniffingSpecificAP(self, apMac):
        print(self.foundAPs[apMac])
        print("Sniffing AP " + apMac + " (" + str(self.foundAPs[apMac].ssid) + ") on " + str(self.iface) + "...")

        apChannel = int(self.foundAPs[apMac].channel)
        for channel in range(apChannel, apChannel+1):
            os.system("iwconfig " + self.iface + " channel " + str(channel))
            print("Sniffing for clients on interface " + str(self.iface) + " channel " + str(channel) + "...")
            sniff(iface=self.iface, prn=self.scanForClientsOfMac(apMac), store=0, count=100, timeout=5)
        print("finished")

    def startSniffingForEverything(self, aChecker):
        print("Sniffing for access points and clients on interface " + str(self.iface) + "...")
        for channel in range(1, 14):
            os.system("iwconfig " + self.iface + " channel " + str(channel))
            print("Sniffing for clients and APs on interface " + str(self.iface) + " channel " + str(channel) + "...")
            sniff(iface=self.iface, prn=aChecker.check, store=0, count=10, timeout=5)
        print("finished sniffing")
