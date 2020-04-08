# WifiBuddy
This Project started with a couple of different intentions:
- practice object orientated programming
- practice a couple of concepts instead of just scripting quick and dirty
- **make life of annoying neighbours a little bit harder, by causing them to have wifi problems**
- build an own almighty RaspberryPi Wifi-Tool
- understand how to manipulate Wifi with Python and Scapy instead of just running scripts like a Skiddie

# Final planned Setup
<img src="https://images-na.ssl-images-amazon.com/images/I/71IOISwSYZL._AC_SX425_.jpg" width="150"><img src="https://us.123rf.com/450wm/siamimages/siamimages1702/siamimages170202606/72762359-plus-symbol-vektor-illustration.jpg?ver=6" width="50"><img src="https://images-na.ssl-images-amazon.com/images/I/61i2x-fn-mL._SX425_.jpg" width="150"><img src="https://us.123rf.com/450wm/siamimages/siamimages1702/siamimages170202606/72762359-plus-symbol-vektor-illustration.jpg?ver=6" width="50"><img src="https://images-eu.ssl-images-amazon.com/images/I/315pfxcyZIL._SL500_AC_SS350_.jpg" width="150"><img src="https://us.123rf.com/450wm/siamimages/siamimages1702/siamimages170202606/72762359-plus-symbol-vektor-illustration.jpg?ver=6" width="50"><img src="https://images-eu.ssl-images-amazon.com/images/I/315pfxcyZIL._SL500_AC_SS350_.jpg" width="150">


So the plan is to connect a RaspberryPi, a little Display (maybe even touch) and 2 wifi antennas. 

Antenna 1:
Will do the sniffing and Scanning

Antenna 2:
Will do the attacks (e.g. Deauthentication)

# Current Features
- List all Access Points (their SSID, MAC, SecurityMode, Channel)
- Uncover Hidden SSID
- List all clients
- List all clients for a specific access point

# Usage
```
sudo python3.7 src/wifiBuddy.py
Setting up sniff options...
Sniffing for clients on interface wlx00c0ca984618...
Sniffing for clients on interface wlx00c0ca984618 channel 1...
Found new hidden SSID for: 12:34:56:78:90:AB
Sniffing for clients on interface wlx00c0ca984618 channel 2...
Sniffing for clients on interface wlx00c0ca984618 channel 3...
Sniffing for clients on interface wlx00c0ca984618 channel 4...
Sniffing for clients on interface wlx00c0ca984618 channel 5...
Sniffing for clients on interface wlx00c0ca984618 channel 6...
Sniffing for clients on interface wlx00c0ca984618 channel 7...
Sniffing for clients on interface wlx00c0ca984618 channel 8...
Sniffing for clients on interface wlx00c0ca984618 channel 9...
Sniffing for clients on interface wlx00c0ca984618 channel 10...
Sniffing for clients on interface wlx00c0ca984618 channel 11...
Sniffing for clients on interface wlx00c0ca984618 channel 12...
Sniffing for clients on interface wlx00c0ca984618 channel 13...
finished
CensoredSSID - 12:34:56:78:90:AB, channel 1, OPN, Manu: Not available - was Hidden: False
<Hidden SSID> - 12:34:56:78:90:AB, channel 1, WPA2, Manu: Not available - was Hidden: True
CensoredSSID - 12:34:56:78:90:AB, channel 1, OPN, Manu: Not available - was Hidden: False
CensoredSSID - 12:34:56:78:90:AB, channel 1, OPN, Manu: Not available - was Hidden: False
CensoredSSID - 12:34:56:78:90:AB, channel 1, WPA2, Manu: Not available - was Hidden: False
CensoredSSID - 12:34:56:78:90:AB, channel 1, WEP, Manu: Compal Broadband Networks, Inc. - was Hidden: False
CensoredSSID - 12:34:56:78:90:AB, channel 1, WPA / WPA2, Manu: AVM GmbH - was Hidden: True
CensoredSSID - 12:34:56:78:90:AB, channel 1, WPA / WPA2, Manu: Compal Broadband Networks, Inc. - was Hidden: False
CensoredSSID - 12:34:56:78:90:AB, channel 1, WEP, Manu: AVM GmbH - was Hidden: False
CensoredSSID - 12:34:56:78:90:AB, channel 9, WPA2, Manu: ZyXEL Communications Corporation - was Hidden: False
```
# Next Steps
- simulate Access Points
- simulate rouge access point the clients are looking for
- Deauth Function for a client
- Deauth Function for an access point
- Deauth all but...
- Update code to work in at least two threads (one for each antenna)
- Play Man in the middle
- Include a GPS receiver for kismet/war driving

