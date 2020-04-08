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

class WifiAdapter:
    iface = None
    foundAPs = None
    foundClients = {}
    hiddenSSIDs = None
    helper = None


    def __init__(self, iface):
        self.iface = iface
        self.setup_monitor()
        self.foundAPs = {}
        self.foundClients = {}
        self.helper = Util()
        self.hiddenSSIDs = []

    def setup_monitor (self):
        print("Setting up sniff options...")
        os.system('ifconfig ' + self.iface + ' down')
        try:
            os.system('iwconfig ' + self.iface + ' mode monitor')
        except:
            print ("Failed to setup monitor mode")
            sys.exit(1)
        os.system('ifconfig ' + self.iface + ' up')

    def findEverything(self, pkt):
        accessPoint = self.checkForBeacon(pkt)
        if accessPoint:
            self.updateAPs(accessPoint)

        self.checkHiddenSSID(pkt)

        client = self.checkForClient(pkt)
        if client:
            self.updateClients(client)
        self.findDataFrames(pkt)

        """
        self.checkForBroadcastProbeRequest(pkt)
        self.findSearchingClients(pkt)

        """

    def checkForClient(self, pkt):
        # check for client looking for APs
        if pkt.getlayer(Dot11) != None and pkt.type == 0 and pkt.subtype == 4: # probe request
            if pkt.info != b'': # broadcast probe request
                client = Client(pkt.addr2, savedAps=[pkt.info])
                return client
        else:
            return None

    def findClients(self, pkt):
        # Make sure the packet has the Scapy Dot11 layer present
        if pkt.getlayer(Dot11) != None and pkt.type == 0 and pkt.getlayer(Dot11).addr1.upper() != "FF:FF:FF:FF:FF:FF":
            receiverMAC = pkt.getlayer(Dot11).addr1
            senderMAC = pkt.getlayer(Dot11).addr2
            if receiverMAC in self.foundAPs:

                return Client(senderMAC)
                self.foundAPs[receiverMAC].clients[senderMAC] = Client(senderMAC)
                self.foundClients[senderMAC] = Client(senderMAC)
            elif senderMAC in self.foundAPs:
                self.foundAPs[senderMAC].clients[receiverMAC] = Client(receiverMAC)
                self.foundClients[receiverMAC] = Client(senderMAC)
            elif not senderMAC in self.foundAPs and not receiverMAC in self.foundAPs:
                print("found loose client")

    def showFoundAPs(self):
        for mac, ap in self.foundAPs.items():
            print(ap)


    def findDataFrames(self, pkt):
        if pkt.getlayer(Dot11) != None and pkt.getlayer(Dot11).type == 2 and not pkt.haslayer(EAPOL) \
            and pkt.getlayer(Dot11).addr1 not in specialMACadresses \
            and pkt.getlayer(Dot11).addr2 not in specialMACadresses:
            # This means it's data frame.
            sn = pkt.getlayer(Dot11).addr2
            rc = pkt.getlayer(Dot11).addr1

            # already know the AP
            if sn in self.foundAPs:
                # check if the client is saved in the AP object
                if rc not in self.foundAPs[sn].clients:
                    self.foundAPs[sn].clients.append(rc)
                # check if client is already known
                if rc not in self.foundClients:
                    self.foundClients[rc] = Client(rc, connectedAP=sn, manufacturer = self.helper.get_oui(rc))
                # already in known Clients update information
                else:
                    self.foundClients[rc].connectedAP = sn
            elif rc in self.foundAPs:
                # check if the client is saved in the AP object
                if sn not in self.foundAPs[rc].clients:
                    self.foundAPs[rc].clients.append(sn)
                # check if client is already known
                if sn not in self.foundClients:
                    self.foundClients[sn] = Client(sn, connectedAP=rc, manufacturer = self.helper.get_oui(sn))
                # already in known Clients update information
                else:
                    self.foundClients[sn].connectedAP = rc




    # check if there is an AP sending a Beacon in the packet
    def checkForBeacon(self, pkt):
        # Packettype 0 -> Management type
        # Subtype 8 ->  Beacon
        if pkt.getlayer(Dot11) != None and pkt.type == 0 and pkt.subtype == 8:  ## type beaconframe
            macAdress = pkt.getlayer(Dot11).addr3
            ssid = pkt.getlayer(Dot11Elt).info
            channel, crypto = self.getChannelAndSecurity(pkt)
            if (not pkt.info or pkt.info ==  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')  and macAdress in self.foundAPs and not macAdress in self.hiddenSSIDs:
                if self.foundAPs[macAdress].ssid == b'' or self.foundAPs[macAdress].ssid ==  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                    self.hiddenSSIDs.append(macAdress)
                    print("Found new hidden SSID for: " + macAdress)
            return AccessPoint(ssid, macAdress, False, channel=channel, crypto=crypto, manufacturer=self.helper.get_oui(macAdress))
        else:
            return None

    def getChannelAndSecurity(self, pkt):
        p = pkt[Dot11Elt]
        crypto = set()
        cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
        while isinstance(p, Dot11Elt):
            if p.ID == 0:
                essid = p.info
            elif p.ID == 3:
                channel = ord(p.info)
            elif p.ID == 48:
                crypto.add("WPA2")
            elif p.ID == 221 and p.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                crypto.add("WPA")
            p = p.payload
        if not crypto:
            if 'privacy' in cap:
                crypto.add("WEP")
            else:
                crypto.add("OPN")
        return channel, ' / '.join(crypto)

    def checkHiddenSSID(self, pkt):
        if pkt.haslayer(Dot11ProbeResp) and pkt.addr3 in self.hiddenSSIDs:
            print("Uncovered fcking Hidden SSID!" + str(pkt.addr3) + "->" + str(pkt.info))
            self.foundAPs[pkt.addr3].ssid = pkt.info
            self.foundAPs[pkt.addr3].wasHidden = True
            self.hiddenSSIDs.remove(pkt.addr3)

    # takes possible new Client
    # gets manufacturer
    # checks if already is known
    # adds if not known
    # if known but saved AP for that client is not, saves that
    # updates
    def updateClients(self, possibleNewClient):
        possibleNewClient.manufacturer = self.helper.get_oui(possibleNewClient.macAdress)
        if not possibleNewClient.macAdress in self.foundClients:  # if client not yet known
            print("Found new Client: " + str(possibleNewClient))
            self.foundClients[possibleNewClient.macAdress] = possibleNewClient
        elif len(possibleNewClient.savedAPs) > 0:  # already known, maybe have to update savedAps for that client
            if not possibleNewClient.savedAPs[0] in self.foundClients[possibleNewClient.macAdress].savedAPs:
                self.foundClients[possibleNewClient.macAdress].savedAPs.append(possibleNewClient.savedAPs[0])

        self.updateAPconnectedClient(possibleNewClient)

    # checks if the client is registered as connected client in Access  Point
    def updateAPconnectedClient(self, client):
        if client.connectedAP and client.connectedAP in self.foundAPs:
            if not client.macAdress in self.foundAPs[client.connectedAP].clients:
                self.foundAPs[client.connectedAP].clients.append(client.macAdress)

    def updateAPs(self, accessPoint):
        if not accessPoint.macAdress in self.foundAPs:
            print("Found new Access Point: " + str(accessPoint))
            self.foundAPs[accessPoint.macAdress] = accessPoint

    def startSniffing(self):
        print("Sniffing for access points and clients on interface " + str(self.iface) + "...")

        for channel in range(1, 14):
            os.system("iwconfig " + self.iface + " channel " + str(channel))
            print("Sniffing for clients on interface " + str(self.iface) + " channel " + str(channel) + "...")
            sniff(iface=self.iface, prn=self.findEverything, store=0, count=10, timeout=5)
        print("finished")


    def startSniffingForEverything(self):
        print("Sniffing for access points and clients on interface " + str(self.iface) + "...")
        for channel in range(1, 14):
            os.system("iwconfig " + self.iface + " channel " + str(channel))
            print("Sniffing for clients and APs on interface " + str(self.iface) + " channel " + str(channel) + "...")
            sniff(iface=self.iface, prn=self.findEverything, store=0, count=10, timeout=5)
        print("finished sniffing")