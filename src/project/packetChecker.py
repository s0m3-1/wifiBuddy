from .apChecker import ApChecker
from .clientChecker import ClientChecker


# This class is used for checking a pkt for both aps and clients
class PacketChecker:

    @classmethod
    def check(cls):
        def checkPkt(pkt):
            ap = ApChecker.checkWithPkt(pkt)
            client = ClientChecker.checkWithPkt(pkt)
            return ap, client

        return checkPkt
