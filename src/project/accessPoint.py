
class AccessPoint:

    ssid = None
    macAdress = None
    clients = None
    channel = None
    crypto = None
    wasHidden = None
    manufacturer = None

    def __init__(self, ssid, macAdress, wasHidden, channel=-1, crypto="", manufacturer=""):
        self.ssid = ssid
        self.macAdress = macAdress
        self.clients = []
        self.wasHidden = wasHidden
        self.channel = channel
        self.crypto = crypto
        self.manufacturer = manufacturer


    def __str__(self):
        #ssid = self.ssid.decode("utf-8")
        ssid=self.ssid

        if len(ssid) == 0 or ssid ==  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
            ssid = "<Hidden SSID>"
            self.wasHidden = True

        return str(ssid) + " - " + self.macAdress + ", channel " + str(self.channel) + ", " + self.crypto + ", Manu: " + self.manufacturer + " - was Hidden: " + str(self.wasHidden)

    def printAPinformation(self):
        print(self)
        amountClients = (len(self.clients.items()))
        counter = 0
        for key, client in self.clients.items():
            if counter == amountClients - 1:
                print("  └ " + str(client))
            else:
                print("  ├ " + str(client))

            counter = counter + 1

    def listClients(self):
        for key, client in self.clients.items():
            print(client)

