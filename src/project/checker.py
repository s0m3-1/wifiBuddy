from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11ProbeResp
from scapy.layers.eap import EAPOL
from .client import Client

from .accessPoint import AccessPoint
from .checkerInterface import CheckerInterface


class Checker(CheckerInterface):

    hiddenSSIDs = None

    def __init__(self):
        self.hiddenSSIDs = []

    def check(self):
        def checkPkt(pkt):

            ap = self.checkForBeaconingAp(pkt)
            return ap

        return checkPkt

