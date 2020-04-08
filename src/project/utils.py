import os
from netaddr.core import NotRegisteredError
from netaddr import *

class Util:
    def check_root(self):
        if not os.geteuid() == 0:
            print("Run as root.")
            exit(1)


    def get_oui(self, mac):
        maco =EUI(mac)
        try:
            manuf = maco.oui.registration().org
        except NotRegisteredError:
            manuf = "Not available"
        return manuf