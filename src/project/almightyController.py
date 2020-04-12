from scapy.layers.dot11 import Dot11, Dot11ProbeResp
from scapy.layers.eap import EAPOL

from .packetChecker import PacketChecker
from .wifiAdapter import WifiAdapter
from .clientChecker import ClientChecker

from .client import Client

from .apChecker import ApChecker
from .utils import Util

specialMACadresses = ["ff:ff:ff:ff:ff:ff", "33:33:00:00:00:0c"]


class AlmightyController:

    def __init__(self):
        self.foundClients = {}
        self.aChecker = ApChecker()
        self.foundAPs = {}
        self.wa = WifiAdapter("wlx00c0ca984618")
        self.helper = Util()

    # push this to end
    def startSniffingForEverything(self):
        self.wa.startSniffingForEverything(PacketChecker.check, self.updateClientsAndApsFromSnif)

    def startSniffingAPs(self):
        self.wa.startSniffingAPs(self.aChecker.check, self.updateAPsFromSnif)

    def startSniffingClients(self):
        self.wa.startSniffingClients(ClientChecker.check, self.updateClientsFromSnif)

    def startSniffingSpecificAP(self, ap):
        print("in controller with ap: " + ap)
        self.wa.startSniffingSpecificAP(ClientChecker.check, self.updateClientsFromSnif, self.foundAPs[ap],
                                        self.foundClients, self.foundAPs)

    # looks for clients quickly if ap is known
    def findClientForKnownAp(self, pkt):
        # Make sure the packet has the Scapy Dot11 layer present
        if pkt.getlayer(Dot11) is not None and pkt.type == 0:

            if pkt.getlayer(Dot11).addr1.upper() != "FF:FF:FF:FF:FF:FF":
                receiverMAC = pkt.getlayer(Dot11).addr1
                senderMAC = pkt.getlayer(Dot11).addr2
                if receiverMAC in self.foundAPs:
                    client = Client(senderMAC, savedAps=[receiverMAC], connectedAP=receiverMAC)
                    self.foundAPs[receiverMAC].clients.append(senderMAC)
                    return client
                elif senderMAC in self.foundAPs:
                    client = Client(receiverMAC, savedAps=[senderMAC], connectedAP=senderMAC)
                    self.foundAPs[senderMAC].clients.append(receiverMAC)
                    return client
                elif senderMAC not in self.foundAPs and receiverMAC not in self.foundAPs:
                    print("found loose client")
        else:
            print("no client packet")
        return None

    # looks for data communication
    def checkForDataFrames(self, pkt):
        if pkt.getlayer(Dot11) is not None and pkt.getlayer(Dot11).type == 2 and not pkt.haslayer(EAPOL) \
                and pkt.getlayer(Dot11).addr1 not in specialMACadresses \
                and pkt.getlayer(Dot11).addr2 not in specialMACadresses:

            # This means it's data frame.
            sn = pkt.getlayer(Dot11).addr2
            rc = pkt.getlayer(Dot11).addr1

            # already know the AP
            # sender is an AP
            if sn in self.foundAPs:
                # check if the client is saved in the AP object
                if rc not in self.foundAPs[sn].clients:
                    self.foundAPs[sn].clients.append(rc)
                # check if client is already known
                if rc not in self.foundClients:
                    self.foundClients[rc] = Client(rc, connectedAP=sn, manufacturer=self.helper.get_oui(rc))
                # already in known Clients update information on connected AP
                else:
                    self.foundClients[rc].connectedAP = sn
            # already know the AP
            # receiver is AP
            elif rc in self.foundAPs:
                # check if the client is saved in the AP object
                if sn not in self.foundAPs[rc].clients:
                    self.foundAPs[rc].clients.append(sn)
                # check if client is already known
                if sn not in self.foundClients:
                    self.foundClients[sn] = Client(sn, connectedAP=rc, manufacturer=self.helper.get_oui(sn))
                # already in known Clients update information
                else:
                    self.foundClients[sn].connectedAP = rc
            print("found data")
            return True
        else:
            return False

    def updateClientsAndApsFromSnif(self, callback):
        def packetHandler(pkt):
            possibleNewAp, possibleNewClient = callback(pkt)
            self.updateGivenClient(possibleNewClient)
            self.updateGivenAP(possibleNewAp)
        return packetHandler

    # gets manufacturer, adds to foundClients not known and might update savedAPs for client
    def updateClientsFromSnif(self, callback):

        def packetHandler(pkt):
            possibleNewClient = callback(pkt)
            self.updateGivenClient(possibleNewClient)
            """
            if possibleNewClient:
                possibleNewClient.manufacturer = self.helper.get_oui(possibleNewClient.macAdress)
                if possibleNewClient.macAdress not in self.foundClients:  # if client not yet known
                    print("Found new Client: " + str(possibleNewClient))
                    self.foundClients[possibleNewClient.macAdress] = possibleNewClient
                elif len(
                        possibleNewClient.savedAPs) > 0:  # already known, maybe have to update savedAps for that client
                    if not possibleNewClient.savedAPs[0] in self.foundClients[possibleNewClient.macAdress].savedAPs:
                        self.foundClients[possibleNewClient.macAdress].savedAPs.append(possibleNewClient.savedAPs[0])

                self.updateAPconnectedClient(possibleNewClient)
            """
        return packetHandler

    # checks if the client is registered as connected client in Access  Point
    def updateAPconnectedClient(self, client):
        if client.connectedAP and client.connectedAP in self.foundAPs:
            if client.macAdress not in self.foundAPs[client.connectedAP].clients:
                self.foundAPs[client.connectedAP].clients.append(client.macAdress)

    def updateAPsFromSnif(self, callback):

        def packetHandler(pkt):
            accessPoint = callback(pkt)
            """
            if accessPoint:
                if accessPoint.macAdress not in self.foundAPs:
                    print("Found new Access Point: " + str(accessPoint))
                    self.foundAPs[accessPoint.macAdress] = accessPoint
                manufacturer = self.helper.get_oui(accessPoint.macAdress)
                self.foundAPs[accessPoint.macAdress].manufacturer = manufacturer
            """
            if accessPoint:
                self.updateGivenAP(accessPoint)
            self.checkHiddenSSID(pkt)

        return packetHandler

    def updateGivenClient(self, client):
        if client:
            client.manufacturer = self.helper.get_oui(client.macAdress)
            if client.macAdress not in self.foundClients:  # if client not yet known
                print("Found new Client: " + str(client))
                self.foundClients[client.macAdress] = client
            elif len(
                    client.savedAPs) > 0:  # already known, maybe have to update savedAps for that client
                if not client.savedAPs[0] in self.foundClients[client.macAdress].savedAPs:
                    self.foundClients[client.macAdress].savedAPs.append(client.savedAPs[0])

            self.updateAPconnectedClient(client)

    def updateGivenAP(self, accessPoint):
        if accessPoint:
            if accessPoint.macAdress not in self.foundAPs:
                print("Found new Access Point: " + str(accessPoint))
                self.foundAPs[accessPoint.macAdress] = accessPoint
            manufacturer = self.helper.get_oui(accessPoint.macAdress)
            self.foundAPs[accessPoint.macAdress].manufacturer = manufacturer

    def checkHiddenSSID(self, pkt):
        if pkt.haslayer(Dot11ProbeResp) and pkt.addr3 in self.aChecker.hiddenSSIDs:
            print("Uncovered fcking Hidden SSID!" + str(pkt.addr3) + "->" + str(pkt.info))
            self.foundAPs[pkt.addr3].ssid = pkt.info
            self.foundAPs[pkt.addr3].wasHidden = True
            self.aChecker.hiddenSSIDs.remove(pkt.addr3)

    def showFoundClients(self):
        for mac, client in self.foundClients.items():
            print(client)

    def showFoundAPs(self):
        for mac, ap in self.foundAPs.items():
            print(ap)

    def getAPsAsList(self):
        apList = []
        for mac, item in self.foundAPs.items():
            apList.append(mac)
        return apList
