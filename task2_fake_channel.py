# Julien Huguet & Antoine Hunkeler

from scapy.all import *
import pandas as pd
import numpy
import threading
import time
import os

# initialize variables
interface = "wlan0mon"
listSSID = []
availableNetworks = pd.DataFrame()

# change channel on the wlan0mon interface
# the channels go from 1 to 13
# inspired from : https://stackoverflow.com/questions/21229386/packet-sniffing-with-channel-hopping-using-scapy
def changeInterfaceChannel():
	interface = "wlan0mon"
	channel = 0	
	while True:
		if channel == 13:
			channel = 1
		else:
			channel = channel + 1
		os.system("iwconfig %s channel %d" % (interface, channel))
		time.sleep(1)

# every 1 second clear terminal
# and print the data frame
def printSSID():
	while True:
		os.system("clear")
		print(availableNetworks)
		time.sleep(1)

# function calling for every packet captured in sniffing
def scanSSID(packet):
	# set variables as global
	global listSSID	
	global availableNetworks
	
	# if the packet is a beacon frame
	# From : https://en.wikipedia.org/wiki/802.11_Frame_Types#Types_and_SubTypes
	if packet.haslayer(Dot11FCS) and packet.type == 0 and packet.subtype == 8:
		macAddr = packet.addr2 # get the source MAC address
		ssid = packet.info.decode("utf-8") # get the SSID
		stats = packet[Dot11Beacon].network_stats() # get some stats
		channel = stats.get("channel") # get the channel
		#channel = int(ord(packet[Dot11Elt:3].info)) # From : https://www.programcreek.com/python/example/92705/scapy.layers.dot11.Dot11
		#channel = 1
		dBm = packet[RadioTap].dBm_AntSignal # get the signal
		
		# if the MAC address is not on the list
		# Doc for dataframe : https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.html
		if macAddr not in listSSID:
			listSSID.append([macAddr, ssid, dBm, channel]) # add on the list
			availableNetworks = pd.DataFrame(listSSID, columns=["BSSID", "SSID", "dBm_Signal", "Channel"]) # update dataframe
		#print(availableNetworks)

print("Sniffing...")
# launch thread for display dateframe
printer = threading.Thread(target=printSSID)
printer.daemon = True
printer.start()

# launch thread for change channel on interface
interChannel = threading.Thread(target=printSSID)
interChannel.daemon = True
interChannel.start()

# sniffing on explicit interface and calling the function scanSSID
# on every captured packet
# Help from : http://sdz.tdct.org/sdz/manipulez-les-paquets-reseau-avec-scapy.html#Lafonctionsniff
sniff(iface=interface, prn=scanSSID)

#macAddrlist = numpy.empty(len(listSSID), dtype=object)
#channelList = numpy.empty(len(listSSID))

#for i in range (len(listSSID)):
#	macAddrlist[i] = listSSID[i][0]
#	channelList[i] = listSSID[i][3]

#inputSSID = input("Choose the SSID to attack : ")

