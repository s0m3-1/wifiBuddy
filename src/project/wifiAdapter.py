import os
import sys
from scapy.all import sniff

specialMACadresses = ["ff:ff:ff:ff:ff:ff", "33:33:00:00:00:0c"]


class WifiAdapter:
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

    def setup_monitor(self):
        print("Setting up sniff options...")
        os.system('ifconfig ' + self.iface + ' down')
        try:
            os.system('iwconfig ' + self.iface + ' mode monitor')
        except:
            print("Failed to setup monitor mode")
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
            sniff(iface=self.iface, prn=updateFunc(callback()), store=0, count=1000, timeout=5)
        print("finished")

    # todo
    def startSniffingSpecificAP(self, callback, updateFunc, ap, foundClients, foundAPs):
        channel = str(ap.channel)
        print("Sniffing AP " + ap.macAdress + " (" + str(ap.ssid) + ") on " + str(self.iface) + "...")
        os.system("iwconfig " + self.iface + " channel " + channel)
        print("Sniffing for clients on interface " + str(self.iface) + " channel " + channel + "...")
        sniff(iface=self.iface, prn=updateFunc(callback(ap.macAdress, foundClients, foundAPs)), store=0, count=1000,
              timeout=30)

        print("finished")

    # todo maybe both checkers as singleton and add checker with both checkers as attributes
    def startSniffingForEverything(self, callback, updateFunc):
        print("Sniffing for access points and clients on interface " + str(self.iface) + "...")
        for channel in range(1, 14):
            os.system("iwconfig " + self.iface + " channel " + str(channel))
            print("Sniffing for clients and APs on interface " + str(self.iface) + " channel " + str(channel) + "...")
            sniff(iface=self.iface, prn=updateFunc(callback()), store=0, count=10, timeout=5)
        print("finished sniffing")
