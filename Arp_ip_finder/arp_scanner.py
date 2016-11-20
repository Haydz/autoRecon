#! /usr/bin/python

import time
from scapy.all import *

#seconds = int(raw_input("Enter the amount of seconds you wish to scan\n"))

def scan(command):
	launchresults = subprocess.check_output(command, shell=True)
	return launchresults


def BaseLineTest():
	print "++++++++++++++++++++++++++++++++"
	print "+++RUNNING BASELINE CHECKS +++++"
	print "+++ ROOT | Base Directory etc+++++"
	print "++++++++++++++++++++++++++++++++\n "
	# Checking Running as root, for write perms
	try:
		checkPermissions = 'whoami'
		checkPermissionsResults = scan(checkPermissions)
	except Exception as e:
		print e

	if 'root' in checkPermissionsResults:
		print "====You are Root that is good! Continuing===="
	else:
		"You are not root, please run as root!"
		"EXITING"
		exit()

	#finding full full path of script
	checkPath = 'pwd'
	FullPath = scan(checkPath).strip() + '/'
	#print "The Full path to be used for the script is ", FullPath


	baseDir = "ArpHosts"
	# create base sub dir to place all files
	try:
		mkBaseDir = "mkdir %s" % baseDir
		scan(mkBaseDir)
	except Exception as e:
		print e, "\n"

	# check dir was created
	try:
		checkDir = "ls | grep %s" % baseDir
		checkDirDirResults = scan(checkDir)
		if baseDir in checkDirDirResults:
			print "BASE directory found.. continuing"
	except Exception as e:
		print e
	FullPath = ''.join((FullPath, baseDir)) + '/'
	print "Full path and baseDir for script will be ", FullPath
	return FullPath


def packet_callback(packet):

	if (ARP in packet and packet[ARP].op == 2):
		arpIP = packet[ARP].psrc
		print "%s => %s"%(packet[ARP].hwsrc,packet[ARP].psrc)
		IPlist.append(packet[ARP].psrc)
				#packet.show()
# prevents IP address being written twice
		if arpIP not in IPlist:
			IPlist.append(arpIP)


def arpPing(IPRange):
	print " Running Arp Ping"
	arpPingIPList = []
	#arping(IPRange)
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IPRange), timeout=5)
	ans.summary(lambda (s,r):  r.sprintf("%Ether.src% %ARP.psrc%"))
	for snd, rcv in ans:
		print "Ethernet Address and IP Addresses of hosts: "
		print rcv.sprintf(r"%Ether.src% & %ARP.psrc%")
		IP = rcv.sprintf("%ARP.psrc%")
		if IP not in arpPingIPList:
			arpPingIPList.append(IP)
		#print IP

	return arpPingIPList



if __name__ == '__main__':
	"""====START OF MAIN ====="""


	print "++++ This Script will identify IP addresses from ARP PACKETS ++++"
	print "++++ and it will run an ArpPing Scan to be more acive        ++++"
	print "Press Enter to continue, or press CTRL C to quit\n"
	raw_input("> ")

	seconds = int(raw_input("Please enter the amount of seconds to Sniff ARP packerts for"
				  "> "))


	#seconds = 2
	bpf = 'arp'
	outPutFile = 'ArpHosts.txt'
	IPlist = []
	FullPath = BaseLineTest()
	time.sleep(2)

	print "\n\n\n====starting Sniffer====="
	print "Running Sniffer for %s seconds\n\n " % seconds

	sniff(filter=bpf, prn=packet_callback, timeout=seconds)


	#print "Running Arp Ping"
	arpPingResults = arpPing("10.255.252.*")
	print "ARP PING RESULTS "
	print arpPingResults
	print IPlist

	for arpPingIP in arpPingResults:
		if arpPingIP not in IPlist:
			print "Adding IP from Arp Ping scan to list: ", arpPingIP
			IPlist.append(arpPingIP)
	print "IPLIST: ", IPlist

	print "====Sniffer finished====\n"

	FileFullPath = FullPath + outPutFile

	#Creating blank file
	ipFile = open(FileFullPath, 'w').close()


	if IPlist:
		print "====Writing IPs found to file"
		print "[!] Writing contents to %s" % outPutFile
		ipFile = open(FileFullPath, 'w')
		ipFile.write("===Hosts identified via ARP Sniffing==" '\n')
		for IP in IPlist:
			print "Found Host: %s writing to file" % IP
			ipFile.write(IP + '\n')
		ipFile.close()
		print "\n ====== Script has finished ======"
		print "Folder where outputfile is"
		print FullPath
	else:
		print "NO IP ADDRESSES FOUND"
		print "Do you have an interface that is working???"





