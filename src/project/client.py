class Client:
    macAdress = None
    savedAPs = []
    connectedAP = ""
    manufacturer = None

    def __init__(self, macAdress, savedAps=[], connectedAP="", manufacturer=""):
        self.macAdress = macAdress
        self.savedAPs = []
        self.connectedAP = ""
        self.manufacturer = manufacturer

    def __str__(self):
        return self.macAdress

    def printClientInformation(self):
        print("Clientmac: " + self.macAdress)
        print("  Connected AP: " + self.connectedAP)
        print("  Manufacturer: " + self.manufacturer)
        print("  Saved APs:")


        counter = 0
        for ap in self.savedAPs:
            if counter == len(self.savedAPs) - 1:
                print("    └ " + str(ap))
            else:
                print("    ├ " + str(ap))
            counter = counter + 1