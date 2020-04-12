from .apChecker import ApChecker
from .clientChecker import ClientChecker


# This class is used for checking a pkt for both aps and clients
class PacketChecker:

    aChecker = ApChecker()

    @classmethod
    def check(cls):
        def checkPkt(pkt):
            ap = cls.aChecker.checkWithPkt(pkt)
            client = ClientChecker.checkWithPkt(pkt)
            return ap, client

        return checkPkt
