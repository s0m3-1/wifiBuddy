from scapy.layers.dot11 import Dot11
from .client import Client


class ClientChecker:

    @staticmethod
    def check(ap=None, foundClients=None, foundAPs=None):
        def checkPkt(pkt):
            if ap:
                client = ClientChecker.findDataFramesForAP(pkt, ap, foundClients, foundAPs)
            else:
                client = ClientChecker.checkForProbingClient(pkt)

                # no probing client found
                # check for Client trying to associate
                if not client:
                    client = ClientChecker.checkForAssociationClient(pkt)

            if client:
                return client
            else:
                return None

        return checkPkt

    @staticmethod
    def checkWithPkt(pkt, ap=None, foundClients=None, foundAPs=None):
        if ap:
            client = ClientChecker.findDataFramesForAP(pkt, ap, foundClients, foundAPs)
        else:
            client = ClientChecker.checkForProbingClient(pkt)

            # no probing client found
            # check for Client trying to associate
            if not client:
                client = ClientChecker.checkForAssociationClient(pkt)

        if client:
            return client
        else:
            return None

    @staticmethod
    def checkForAssociationClient(pkt):
        # pkt.subtype == 0 -> Association Request
        # pkt.subtype == 2 -> Reassociation Request
        if pkt.getlayer(Dot11) is not None and (pkt.subtype == 0 or pkt.subtype == 2):
            client = Client(pkt.addr2)
            return client
        else:
            return None

    @staticmethod
    def checkForProbingClient(pkt):
        # pkt.type == 0 -> Management frame
        # pkt.subtype == 4 -> Probe Request

        if pkt.getlayer(Dot11) is not None and pkt.type == 0 and pkt.subtype == 4:  # probe request
            if pkt.info != b'':  # broadcast probe request
                client = Client(pkt.addr2, savedAps=[pkt.info])
                return client
        else:
            return None

    @staticmethod
    def findDataFramesForAP(pkt, apMac, foundClients, foundAPs):

        # Make sure the packet has the Scapy Dot11 layer present
        if pkt.addr1 == apMac or pkt.addr2 == apMac:
            if pkt.subtype == 4:  # probe request
                if pkt.info != b'':  # broadcast probe request
                    client = Client(pkt.addr2, savedAps=[pkt.info])
                    if pkt.addr2 not in foundClients:
                        print(pkt.addr2 + " looking for " + apMac)
                    print("Found: " + str(client))
                    return client
            elif pkt.addr1.upper() != "FF:FF:FF:FF:FF:FF":
                receiverMAC = pkt.addr1
                senderMAC = pkt.addr2
                if receiverMAC in foundAPs:
                    client = Client(senderMAC, savedAps=[receiverMAC], connectedAP=receiverMAC)
                    foundAPs[receiverMAC].clients.append(senderMAC)
                    print(senderMAC + " looking for " + apMac)
                    print("Found: " + str(client))
                    return client
                elif senderMAC in foundAPs:
                    client = Client(receiverMAC, savedAps=[senderMAC], connectedAP=senderMAC)
                    foundAPs[senderMAC].clients.append(receiverMAC)
                    print(receiverMAC + " looking for " + apMac)
                    print("Found: " + str(client))
                    return client
                elif senderMAC not in foundAPs and receiverMAC not in foundAPs:
                    print("found loose client")

        return None
