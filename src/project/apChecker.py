from scapy.layers.dot11 import Dot11, Dot11Elt
from .accessPoint import AccessPoint


class ApChecker:

    def __init__(self):
        self.hiddenSSIDs = []

    def check(self):
        def checkPkt(pkt):
            ap = self.checkForBeaconingAp(pkt)
            return ap

        return checkPkt

    def checkWithPkt(self, pkt):
        ap = self.checkForBeaconingAp(pkt)
        return ap

    # check if there is an AP sending a Beacon in the packet
    def checkForBeaconingAp(self, pkt):
        # Packettype 0 -> Management type
        # Subtype 8 ->  Beacon
        hiddenFlag = False
        if pkt.getlayer(Dot11) is not None and pkt.type == 0 and pkt.subtype == 8:  # type beaconframe
            macAdress = pkt.getlayer(Dot11).addr3
            ssid = pkt.getlayer(Dot11Elt).info
            channel, crypto = self.getChannelAndSecurity(pkt)
            if (not pkt.info or pkt.info == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                                            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00') \
                    and macAdress not in self.hiddenSSIDs:
                self.hiddenSSIDs.append(macAdress)
                print("Found new hidden SSID for: " + macAdress)
                hiddenFlag = True
            return AccessPoint(ssid, macAdress, hiddenFlag, channel=channel, crypto=crypto)
        else:
            return None

    def getChannelAndSecurity(self, pkt):
        p = pkt[Dot11Elt]
        crypto = set()
        cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
        channel = None
        while isinstance(p, Dot11Elt):
            if p.ID == 3:
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
