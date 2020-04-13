import os
from netaddr import *


class Util:

    @staticmethod
    def check_root():
        if not os.geteuid() == 0:
            print("Run as root.")
            exit(1)

    @staticmethod
    def get_oui(mac):
        maco = EUI(mac)
        try:
            manuf = maco.oui.registration().org
        except NotRegisteredError:
            manuf = "Not available"
        return manuf
