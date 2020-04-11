from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL
from .client import Client
from .checkerInterface import CheckerInterface


class ClientChecker(CheckerInterface):

    def __init__(self):
        pass

    # ToDo check if client known
    def __contains__(self):
        pass

    def check(self, ap=None):
        def checkPkt(pkt):

            client = None
            if ap:
                client = self.findDataFramesForAP(pkt, ap)
            else:
                client = self.checkForProbingClient(pkt)

                # no probing client found
                # check for Client trying to associate
                if not client:
                    client = self.checkForAssociationClient(pkt)

            if client:
                return client
            else:
                return None

        return checkPkt

    """
    # analyse if there is a client in pkt
    def check(self, pkt, ap=None):
        client = None
        if ap:
            client = self.findDataFramesForAP(pkt, ap)
        else:
            client = self.checkForProbingClient(pkt)

            # no probing client found
            # check for Client trying to associate
            if not client:
                client = self.checkForAssociationClient(pkt)

        if client:
            return client
        else:
            return None
    """

    def checkForAssociationClient(self, pkt):
        # pkt.subtype == 0 -> Association Request
        # pkt.subtype == 2 -> Reassociation Request
        if pkt.getlayer(Dot11) != None and (pkt.subtype == 0 or pkt.subtype == 2):
            client = Client(pkt.addr2)
            return client
        else:
            return None

    def checkForProbingClient(self, pkt):
        # pkt.type == 0 -> Management frame
        # pkt.subtype == 4 -> Probe Request

        if pkt.getlayer(Dot11) != None and pkt.type == 0 and pkt.subtype == 4: # probe request
            if pkt.info != b'': # broadcast probe request
                client = Client(pkt.addr2, savedAps=[pkt.info])
                return client
        else:
            return None

    def scanForClientsOfMac(self, apMac):
        def scanClient(pkt):
            client = self.checkForClient(pkt)
            if client:
                self.updateClients(client)
            self.findDataFrames(pkt)
            self.findDataFramesForAP(pkt, apMac)

        return scanClient

    def findDataFramesForAP(self, pkt,apMac):
        # Make sure the packet has the Scapy Dot11 layer present
        if pkt.getlayer(Dot11) != None and pkt.type == 0 and ( pkt.addr1 == apMac or pkt.addr2 == apMac):
            if pkt.subtype == 4:  # probe request
                if pkt.info != b'':  # broadcast probe request
                    client = Client(pkt.addr2, savedAps=[pkt.info])
                    if pkt.addr2 not in self.foundClients:
                        print(pkt.addr2 + " looking for " + apMac)
                    return client
            elif pkt.getlayer(Dot11).addr1.upper() != "FF:FF:FF:FF:FF:FF":
                receiverMAC = pkt.getlayer(Dot11).addr1
                senderMAC = pkt.getlayer(Dot11).addr2
                if receiverMAC in self.foundAPs:
                    client = Client(senderMAC, savedAps=[receiverMAC], connectedAP=receiverMAC)
                    self.foundAPs[receiverMAC].clients.append(senderMAC)
                    print(senderMAC + " looking for " + apMac)
                    return client
                elif senderMAC in self.foundAPs:
                    client = Client(receiverMAC, savedAps=[senderMAC], connectedAP=senderMAC)
                    self.foundAPs[senderMAC].clients.append(receiverMAC)
                    print(receiverMAC + " looking for " + apMac)
                    return client
                elif not senderMAC in self.foundAPs and not receiverMAC in self.foundAPs:
                    print("found loose client")

        return None
