#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = 'haydz'
__copyright__ = "GNU General Public License v3"
__credits__ = ["loneferret"]
__license__ = "GPL"
__version__ = "1.0.1"
__email__ = "unknown"
__status__ = "Development"

# to add multi process
from multiprocessing import Process

# importing multi processing to support running multiple nmap comamnds (similar to multiple threads)
import multiprocessing
# import os for allowing OS interfacing, such as listinga  directory if needed
import os, sys, threading

# importing to allow the script to connect to input and out put pipes, such as out put from nmap scans
import subprocess
import time

# import nmap

"""
 this is a major work in progress
 IDEA: Using TCP dump to monitor for Arp Packets, collate IP address from ARP packets, then direct scan hosts.
 TO DO:
 Save files in separate directory using user input
 Add excluding own IP address
 ifconfig
 nmap 192.168.0.* --exclude 192.168.0.100

 further functionality
 https://hackertarget.com/7-nmap-nse-scripts-recon/

 This project is focused on intelligence automation from Nmap scans.
 IT currently does the following:

 1) Fast Nmap Scan to find hosts up
 2) TOP 1000 PORTS TCP scan
 3) Scan for common web ports
 4) Run Eye Witness on common web ports (in progress)
 """

"""
 Yet to do:
 5) Enum4linux *done loneferret*
 6) connect all various NSE scripts up
 7) ftp scan - log in for anonymous, output success anonmyous logins
 8) snmp scans - private, community strings
"""


class constants:
	oVersion = "unknown"


###### FUNCTIONS BELOW #####
# this is the function that will run the multip processing - NEED TO CONFIRM IF THIS IS USED -- need to add this
def multProc(targetin, scanip, port):
	jobs = []
	p = multiprocessing.Process(target=targetin, args=(scanip, port))
	jobs.append(p)
	p.start()
	return


def hostsup_scans(list):  # maybe change to starter scan
	print"[+] Starting -sn scan for hosts up \n"
	# tcpNameScan = 'nmap_%s_' % address\
	# print "File name is: %s" %(list)
	TCPSCAN = 'nmap -vv -sN -iL %s -oA hostsup1_sn' % (list)
	# tcp_results = scan(TCPSCAN)
	# print tcp_results
	# tcp_results = subprocess.check_output(TCPSCAN, shell=True)
	print "[+] Starting -F scan for hosts up \n"
	TCPSCAN2 = 'nmap -vv -F -iL %s -oA hostsup2_fast' % (list)
	tcp_results2 = subprocess.check_output(TCPSCAN2, shell=True)
	print "[+] Starting common ports scan for hosts up \n"
	TCPSCAN3 = 'nmap -iL %s -sn -T4 -PE -PM -PP -PU53,69,123,161,500,514,520,1434 -PA21,22,23,25,53,80,389,443,513,636,8080,8443,3389,1433,3306,10000 -PS21,22,23,25,53,80,443,513,8080,8443,389,636,3389,3306,1433,10000 -n -r -vv -oA hostsup3_ports' % (
		list)
	# tcp_results3 = subprocess.check_output(TCPSCAN3, shell=True)

	# for line in lines:
	#	if ("against" in line) and not ("no-response" in line):
	#		print line
	print "[!] Finished Hostup scans"

	# Parsing all hostup scans for Hosts that are UP
	grepHostsUp = 'cat hostsup*.gnmap | grep Up | cut -d " " -f2 | sort -u'
	grepHostsUpResults = subprocess.check_output(grepHostsUp, shell=True)
	lines = grepHostsUpResults.split("\n")

	# removing any list items that are blank
	lines = [x for x in lines if x]

	# writing all hosts up to a file
	allHostsUp = open('allhostsup.txt', 'a')
	for line in lines:
		line = line.strip()
		allHostsUp.write("%s\n" % line)
	allHostsUp.close()


#need to trouble shoot this
	# if there are web ports we do eyewitness scan
	# if no web ports we do not run

	print "[!] Lauching Webports scan"
	# launching not as multi process so we know when it finishes
	webports('allhostsup.txt')

	# lauching EyeWitness as a seperate process due to how long it takes
	p2 = Process(target=eyewitness, args=('webPorts_common.xml', 'webPorts_common'))
	p2.start()

	print "[-] Testing if running after process ran"
	total = 0
	IPListClean = []


# for IP in lines:
#	 print "IP:", IP
#	 IPListClean.append(IPList[total].strip('\n'))
#	 total = total + 1
# for IP in IPListClean:
#	 p = Process(target=quicknmapScan, args=(IP,))
#	 p.start()

# generic nmap scan top 1000 ports
def quicknmapScan(address):
	# print address
	serv_dict = {}
	# nm = nmap.PortScanner()
	print "[+] Starting top 1000 tcp ports scan for ", address
	tcpNameScan = 'nmap_%s_quick' % address
	# top one thousand ports
	TCPSCAN = 'nmap -vv --top-ports 1000  %s -oA %s_quick' % (address, tcpNameScan)
	tcp_results = subprocess.check_output(TCPSCAN, shell=True)

	# fullName = "%s_quick.xml" % tcpNameScan
	print "[-] Gathering ports and services for %s" % address

	lines = tcp_results.split("\n")

	for line in lines:
		ports = []
		line = line.strip()
		if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
			# print line
			while "  " in line:
				line = line.replace("  ", " ");
			linesplit = line.split(" ")

			service = linesplit[2]  # grabs service
			# print "service is"
			# print service

			port = line.split(" ")[0]
			# print "port is"
			port = line.split("/")[0]  # remove protocol from pEyort: 80/tcp
			# print port
			if service in serv_dict:
				ports = serv_dict[service]
			serv_dict[service] = ports
			# print test_dict['port']
			ports.append(port)

			qhp = open('quick_hosts_ports.txt', 'a')
			qhp.write("%s:%s:%s\n" % (address, port, service))
			qhp.close()


def scan(command):
	launchresults = subprocess.check_output(command, shell=True)
	return launchresults


def portSelection(filename, portsList, outputFile):
	placeholder = []
	print "=====PORT SELECTION Execution running==="
	print "File selected: ", filename
	print "Running Port Selection on ports:", (str(portsList))[1:-1]
	for port in portsList:
		# print x
		# Grep and cutting hosts for respective potrs
		grepHostsUp = 'cat %s  | grep %s/open | cut -d " " -f2 | sort -u' % (filename, port)
		print 'grepHostsUp command being run: %s' % grepHostsUp
		grepHostsUpResults = subprocess.check_output(grepHostsUp, shell=True)
		lines = grepHostsUpResults.split("\n")

		# removing any list items that are blank
		lines = [x for x in lines if x]
		#print lines

		for x in lines:
				#prevents IP address being written twice
			if x not in placeholder:
				placeholder.append(x)
		# writing hosts with correct ports to a file
		print "PLACEHOLDER",placeholder
	if placeholder:
		fileWriting = open(outputFile, 'a')
		for line in placeholder:
			line = line.strip()
			fileWriting.write("%s\n" % line)
			fileWriting.close()
	else:
		print "NO PORTS OPEN ON COMMON WEB PORTS"


def parseScanResults(results, filename, address):
	# parser to find ports open during 1 IP nmap scan
	# results passed from def scan(command) : launchresults
	print "[-] Gathering ports and services for %s" % address
	# split end of lines in results and parse for tcp, open, and no discovered in line
	lines = results.split("\n")
	for line in lines:
		ports = []
		line = line.strip()
		if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
			# print line
			while "  " in line:
				line = line.replace("  ", " ");
			linesplit = line.split(" ")

			service = linesplit[2]  # grabs service
			# print "service is"
			# print service

			port = line.split(" ")[0]
			# print "port is"
			port = line.split("/")[0]  # remove protocol from pEyort: 80/tcp
			# print port
			# if service in serv_dict:
			#	 ports = serv_dict[service]
			# serv_dict[service] = ports
			# print test_dict['port']
			ports.append(port)

			print "[!] Writing contents to %s" % filename
			qhp = open(filename, 'a')
			qhp.write("%s:%s:%s\n" % (address, port, service))
			qhp.close()


def top2000(address):
	serv_dict = {}
	print"[+] Starting top 2000 ports scan", address


# STILL TO DO


def webports(filename):
	print "[-] Starting Common web ports scan -quick Fast One"
	# USING THIS TO TEST PARSING SCAN RESULTS THEN SEND TO EYEWITNESS.
	webScan = 'nmap -p 80,443,8080,8443,981,1311,2480 -iL %s -oA webPorts_common' % filename

	webresults = scan(webScan)

	#if webresults has web ports open, run eyewistness


# print testresults
# parseScanResults(testresults, 'webports.txt',address)

def ftpPort(filename):
	print "[-] Starting FTP scan, checks anonymous"
	ftpScan = 'nmap -sV -Pn -vv -p 21 -iL %s --script=banner,ftp-anon --oA ftpPorts' % filename

	#ftpResults = scan(ftpScan)


""" GREP AND CUTTING FOR FTP ANONYMOUS
 root@traversal-lap:~/PycharmProjects/autoRecon/base# cat ftpPorts.nmap  | grep -B 8 230 | grep "Nmap scan report" | cut -d " " -f 5
192.168.56.102


 """

# need to add parsing the file for anonymous access.

def smbScan(filename):
	print "[-] Starting SMB scan to run enum4Linux and smb checks"

	smbScan = 'nmap -sV -Pn -vv -p 139,445 -iL %s --script=smb-enum-shares, smb-enum-users, smb-os-discovery,smb-brute --oA enum4linux' % filename

	enum4LinuxResults = scan(smbScan)



# to grep correct portscat 	test | grep	22 / open | cut - d 	" " - f2
#  need to add parsing the file for smb results, then add function for ENUM4Linux.

def Enum4Linux(ipToScan):
	if constants.osVersion == 'Debian':
		Enum4LinuxPath = '/pentest/intelligence-gathering/enum4linux'
		command = '%s/enum4linux.pl %s >> enum4_%s.ouput' % (Enum4LinuxPath, ipToScan, ipToScan)
	if constants.osVersion == 'Kali':
		command = 'enum4linux %s >> enum4_%s.output' % (ipToScan, ipToScan)

	print  "[-] Running Enum4Linux on with: %s" % command
	FNULL = open(os.devnull, 'w')  # Suppress enum4linux output
	subprocess.Popen(command, stdout=FNULL, stderr=subprocess.STDOUT, shell=True).wait()
	FNULL.close()


def eyewitness(filename, outputName):  # expecting IP addrees list
	print "[-] Starting Eye Witness scan"
	# this requires editing the Eyewitness.py to use /bin/phantomjs

	if constants.osVersion == 'Debian':
		eyewitnessPath = '/pentest/intelligence-gathering/eyewitness'
		command = '%s/Eyewitness.py --headless--prepend-https --no-prompt  -x %s -d %s' % (
			eyewitnessPath, filename, outputName)
	elif constants.osVersion == 'Kali':
		# filename = webPorts_common.xml
		command = 'eyewitness --web --no-prompt -x ../../../../../root/TestScript/%s' % (filename)
	else:
		command = "**EYE WITNESS WILL NOT RUN*"

	print  "[!] Running EyeWitness with: ", command

	FNULL = open(os.devnull, 'w')  # Suppress eyewitness output
	subprocess.Popen(command, stdout=FNULL, stderr=subprocess.STDOUT, shell=True).wait()
	FNULL.close()

	print "[!] EyeWitness web ports scan finished"
	print "[-] Located in the %s Directory" % outputName


def checkKaliApps():
	# A few of these scripts are not installed by default on Kali Linux
	# Need to check, and install if needed
	print "\t[-] We need to see if Eyewitness is installed..."
	if os.path.isfile("/usr/bin/eyewitness"):
		print "\t[-] Eyewitness is present"
	else:
		print "\t[!] Eyewitness is not installed."
		eyeInstall = raw_input("\t[?] Do you wish to install it [Y/n] ? ") or "Y"
		if eyeInstall == "Y":
			print "\t[+] Installing Eyewitness..."
			subprocess.Popen('apt-get update -y && updatedb', shell=True).wait()
			subprocess.Popen('apt-get install eyewitness -y', shell=True).wait()


def getOsVersion():
	# check to see if debian
	if os.path.isfile("/usr/bin/apt-get"):
		proc = subprocess.Popen(['lsb_release', '-d'], stdout=subprocess.PIPE)
		out = proc.communicate()
		osVer = out[0]
		if "Debian" in (osVer.split("\t"))[1]:
			constants.osVersion = "Debian"
			print "[!] Debian\Ubuntu system detected"
		elif "Kali" in (osVer.split("\t"))[1]:
			constants.osVersion = "Kali"
			print "[!] Kali Linux detected"
		else:
			constants.osVersion = "Debian"
			print "[?] Unknown operating system being used, some tools may not work"
			print "[-] Assuming Debian based"

	return constants.osVersion


# this is the start of the script, taking the IP addresses from a text file called IP.txt
## Not anymore takes a filename as an argument now :)

def BaseLineTest():
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
    print "The Full path to be used for script is ", FullPath


    baseDir = "base"
    # create base sub dir to place all files
    try:
        mkBaseDir = "mkdir %s" % baseDir
        scan(mkBaseDir)
    except Exception as e:
        print e

    # check dir was created
    checkDir = "ls | grep base"
    checkDirDirResults = scan(checkDir)
    if 'base' in checkDirDirResults:
        print "BASE directory found.. continuing"

    FullPath = ''.join((FullPath, baseDir)) + '/'
    print "Full path and baseDir for script will be ", FullPath

    return FullPath
if __name__ == '__main__':

	BaseLineTest()


	# try:
	# 	checkPermissions = 'whoami'
	# 	checkPermissionsResults = scan(checkPermissions)
	# except Exception as e:
	# 	print e
    #
	# if 'root' in checkPermissionsResults:
	# 	print "====You are Root that is good! Continuing===="
	# else:
	# 	"You are not root, please run as root!"
	# 	"EXITING"
	# 	exit()
    #
    #
	# #print checkPermissionsResults
	# #finding full full path of script
	# checkPath = 'pwd'
	# FullPath = scan(checkPath).strip() + '/'
	# print "The Full path to be used for script is ", FullPath
    #
	# baseDir = "base"
	# FullPath = ''.join((FullPath,baseDir)) + '/'
	# print "Full path and baseDir ", FullPath
    #
	# # create base sub dir to place all files
	# try:
	# 	mkBaseDir = "mkdir %s" % baseDir
	# 	scan(mkBaseDir)
	# except Exception as e:
	# 	print e
	# #check dir was created
	# checkDir = "ls | grep base"
	# checkDirDirResults = scan(checkDir)
	# if 'base' in checkDirDirResults:
	# 	print "BASE directory found.. continuing"

	# open file'

	# === Commented out for easy testing ==#
	# if len(sys.argv) == 1:
	#     print "[-] Usage %s <filename>" % sys.argv[0]
	#     print "[-] Example: %s IPlist.text" % sys.argv[0]
	#     print "[!] Quitting..."
	#     print sys.exit()
	# else:
	#     textfile = sys.argv[1]

	# if "Kali" == getOsVersion():
	#   checkKaliApps()

	textfile = "IP.txt"
	f = open(textfile, 'r')
	print"[-] Opening file with IP addresses..."
	#
	# WList = f.read()
	IPList = []
	total = 0
	for IP in f:
		IPList.append(IP)
		total = total + 1

	print"[+] Total Number of IPs: %s" % total
	IPListClean = []
	total = 0

	for IP in IPList:
		IPListClean.append(IPList[total].strip('\n'))
		total = total + 1

	p2 = Process(target=hostsup_scans, args=(textfile,))
	p2.start()

	# p3 = Process(target=scan, args=(launchresults,))


	# p3.start()


	"""Creates blank files ready to write into"""
	# Acts as a blank file, when script is restarted
	open('quick_hosts_ports.txt', 'w').close()
	open('allhostsup.txt', 'w').close()
	open('webports.txt', 'w').close()
	open('testinghosts.txt', 'w').close()

	for IP in IPListClean:
		print"\t[*] IPs ", IP
	# p = Process(target=webports, args=(IP,))
	# p = Process(target=quicknmapScan, args=(IP,))

	# p.start()
	ports = [22, 8888]
	p1 = Process(target=portSelection, args=('testing.gnmap', ports, 'testinghosts.txt'))
	p1.start()
	# eyewitness('webports.txt')
	# p2 = Process(target=nmapScan, args=(IP,))
	# p2.start()

	# Start enum4linux threads
	# enum4linux scans 1 ip at a time, hence the loop
	# lines = open(textfile).read().split("\n")
	# for ip in lines:
	#     enumThread = threading.Thread(target=Enum4Linux, args=(ip.rstrip('\r\n'),))  # Strip out newlines
	#     enumThread.daemon = True
	#     enumThread.start()

	f.close()
