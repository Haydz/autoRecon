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
import baseTest
import argparse
from netaddr import *

# import nmap

"""
 further functionality
 https://hackertarget.com/7-nmap-nse-scripts-recon/

 This project is focused on intelligence automation from Nmap scans.
 IT currently does the following:

 1) Fast Nmap Scan to find hosts up - Done
 2) TOP 1000 PORTS TCP scan - Done changed to 2K
 3) Scan for common web ports - Done
 4) Run Eye Witness on common web ports - Done
 """

"""
 Yet to do:
 5) Enum4linux *done loneferret*
 6) connect all various NSE scripts up
 7) ftp scan - log in for anonymous, output success anonmyous logins - Partly
 8) snmp scans - private, community strings
 9) Nikto -done
 19 )dirbuster



 to mix in:
  discovery scan against a file of subnets
   default nmap with services (-sV) against up hosts, then full port scan with services against all up hosts (yes that will take a long time)
eyewitness stuff is cool. you should pull out what nmap returned as a www and pass those per scan
"""


class constants:
    oVersion = "unknown"

def exhaustive():
    IPFile= BasePath + 'allhostsup.txt'

    for x in open(IPFile, 'r'):
       p4 = Process(target=allPort, args=(x,))
       p4.start()

    print "[!] Lauching Webports scan"
    # launching not as multi process so we know when it finishes
    #CHANGE INTO MULTI PROCESSING
    #webports('%sallhostsup.txt' % BasePath)
    p6 = Process(target=webports, args=(IPFile,))
    p6.start()

    print "[!] Lauching SMBports scan"
    #smbScan ('%sallhostsup.txt' % BasePath)
    p7 = Process(target=smbScan, args=(IPFile,))
    p7.start()

###### FUNCTIONS BELOW #####
# this is the function that will run the multip processing - NEED TO CONFIRM IF THIS IS USED -- need to add this
def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip, port))
    jobs.append(p)
    p.start()
    return


def hostsup_scans(list):  # maybe change to starter scan
    open('%sallhostsup.txt' % BasePath, 'w').close() #creating empty file each time function is run


    print "\n"
    print "++++++++++++++++++++++++++++++++++"
    print "++++ Running Initial Main Scan ++++"
    print "++++++++++++++++++++++++++++++++++"
    print"[+] Starting -sN scan for hosts up - Ping scan"
    # tcpNameScan = 'nmap_%s_' % address\
    # print "File name is: %s" %(list)
    TCPSCAN = 'nmap -vv -sn -iL %s -oA %shostsup1_sn' % (list, BasePath)
    # tcp_results = scan(TCPSCAN)
    # print tcp_results
    # tcp_results = subprocess.check_output(TCPSCAN, shell=True)
    print "[+] Starting -F scan for hosts up - Fast scan "
    TCPSCAN2 = 'nmap -vv -F -iL %s -oA %shostsup2_fast' % (list, BasePath)
    tcp_results2 = subprocess.check_output(TCPSCAN2, shell=True)
    print "[+] Starting common ports scan for hosts up - TCP and UDP"


    print "[!] Finished Hostup scans\n"

    # Parsing all hostup scans for Hosts that are UP
    grepHostsUp = 'cat %shostsup*.gnmap | grep Up | cut -d " " -f2 | sort -u' % BasePath
    grepHostsUpResults = subprocess.check_output(grepHostsUp, shell=True)
    lines = grepHostsUpResults.split(" ")
    # removing any list items that are blank
    lines = [x for x in lines if x]

    # writing all hosts up to a file
    allHostsUp = open('%sallhostsup.txt' % BasePath, 'a')
    for line in lines:
        line = line.strip()
        print "[!] HOST %s Found UP\n" % line
        allHostsUp.write("%s\n" % line)
    allHostsUp.close()


    for x in open('%sallhostsup.txt' % BasePath, 'r'):
        quicknmapScan(x)

    if exhaustive_scan == True:
        exhaustive()


def allPort(address):
    #CHANGE TO top 2000
    open('%sall_ports_allhosts.txt' % BasePath, 'w').close() # creating empty file each time its run
    address = address.strip("\n")
    # print address
    serv_dict = {}
    print "[+] Starting ALL 65K Ports scan for ", address
    tcpNameScan = 'nmap_%s_allports' % address
    # top one thousand ports
    TCPSCAN = 'nmap -vv -p1-65535  %s -oA %s%s' % (address, FullSubDirPath, tcpNameScan)
    print  "[!] Running scan: ",  TCPSCAN
    tcp_results = subprocess.check_output(TCPSCAN, shell=True)

    parseOutputName = '%sall_ports.txt' % BasePath
    parseScanResults(tcp_results,parseOutputName, address)

def quicknmapScan(address):
    #CHANGE TO top 2000
    open('%squick_hosts_ports.txt' % BasePath, 'w').close() # creating empty file each time its run
    address = address.strip("\n")
    # print address
    serv_dict = {}
    print "[+] Starting top 3000 tcp ports scan for ", address
    tcpNameScan = 'nmap_%s_quick' % address
    # top one thousand ports
    TCPSCAN = 'nmap -vv --top-ports 3000  %s -oA %s%s' % (address, FullSubDirPath, tcpNameScan)
    print  "[!] Running scan: ",  TCPSCAN
    tcp_results = subprocess.check_output(TCPSCAN, shell=True)

    parseOutputName = '%squick_hosts_ports.txt' % BasePath
    parseScanResults(tcp_results, parseOutputName, address)

    # fullName = "%s_quick.xml" % tcpNameScan
    # print "[-] Gathering ports and services for %s" % address
    #
    # lines = tcp_results.split("\n")
    #
    # for line in lines:
    #     ports = []
    #     line = line.strip()
    #     if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
    #         # print line
    #         while "  " in line:
    #             line = line.replace("  ", " ");
    #         linesplit = line.split(" ")
    #
    #         service = linesplit[2]  # grabs service
    #         # print "service is"
    #         # print service
    #
    #         port = line.split(" ")[0]
    #         # print "port is"
    #         port = line.split("/")[0]  # remove protocol from pEyort: 80/tcp
    #         print "Found Host %s with %s Port Open" % (address, port)
    #         # print port
    #         if service in serv_dict:
    #             ports = serv_dict[service]
    #         serv_dict[service] = ports
    #         # print test_dict['port']
    #         ports.append(port)
    #
    #         qhp = open('quick_hosts_ports.txt', 'a')
    #
    #         qhp.write("%s:%s:%s\n" % (address, port, service))
    #         qhp.close()


def scan(command):
    launchresults = subprocess.check_output(command, shell=True)
    return launchresults

def portSelection(filename, portsList, outputFile, type):
    #This function receives results from nmap subprocess and i ports
    #it will write ports to a file with the host
    placeholder = []
    print "\n=====PORT SELECTION Execution running==="
    print "File selected: ", filename
    print "Running Port Selection on ports:", (str(portsList))[1:-1]
    for port in portsList:
        # Grep and cutting hosts for respective potrs
        grepPortOpen = 'cat %s  | grep %s/open | cut -d " " -f2 | sort -u' % (filename, port)
        print 'Grep command being run: %s' % grepPortOpen
        grepPortOpenResults = subprocess.check_output(grepPortOpen, shell=True)
        lines = grepPortOpenResults.split("\n")

        # removing any list items that are blank
        lines = [x for x in lines if x] # ip addresses


        #print lines
        #raw_input("PAUSE")
        for x in lines:
                #prevents IP address being written twice
            if x not in placeholder:
                placeholder.append(x+":"+str(port))
        # writing hosts with correct ports to a file
    outputFile = BasePath + outputFile #place to save hosts  with SMB ports open
    print "\n"  # to add space"
    open(outputFile, 'w').close() #creating Empty File
    if placeholder: # if placeholder has IPS
        print "[!] Hosts found with %s ports, writing to file" % type
        fileWriting = open(outputFile, 'a')
        for line in placeholder:
            print "Writing %s to file" % line
            line = line.strip() #writing IP addresses to a file
            fileWriting.write("%s\n" % line)
        fileWriting.close()
        return True # returns true so that we can have another function run (such as EyeWitness)
    else:
        #strPortsList = ""
            #strPortsList.append(x)
        print "NO PORTS OPEN ON %s PORTS" % portsList[1:-1]
        return False

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
            print "Found Host %s with %s Port Open" % (address, port)
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



def webports(filename):
    open('%swebports.txt' % BasePath, 'w').close() # creating empty file to remove duplication
    #filename = BasePath + filename
    print "[-] Starting Common web ports scan -quick Fast One"
    portList = [80, 443, 8080, 8443, 9821, 1311, 2480] #ports list of common web ports
    webScan = 'nmap -p %s -iL %s -oA %swebPorts_common' % (str(portList)[1:-1], filename, BasePath)
    #print webScan
    webresults = scan(webScan)
    OutputFile = 'hosts_webports.txt'
    type = 'common web '
    test = portSelection('%swebPorts_common.gnmap' % BasePath, portList, OutputFile, type)

    if test == True:
        print "[!] Web Ports were identified, running EyeWitness"

        #to add Eye Witness here
        eyewitness('%shosts_webports.txt' % BasePath, 'EW_web_common')
        #Nikto scan - needs to be on port 80 and 443 (any web ports found)
        for x in open('%shosts_webports.txt' % BasePath,):
            #print x.split(':') # No need to split ports as Nikto takes IP with Port in IP:PORT
            x2 = x.split(':')[0]
            x3 = int(x.split(':')[1])
            DirbusterScan(x2,x3)
            #DirbusterScan(x.split(':')[0], int(x.split(':')[1]))
            #
            # print x2
            #
            # print x3
            #NiktoScan(IP.strip('\n'))
    else:
        print "no web ports found"


# print testresults
# parseScanResults(testresults, 'webports.txt',address)

def ftpPort(filename):
    print "[-] Starting FTP scan, checks anonymous login"
    ftpScan = 'nmap -sV -Pn -vv -p 21 -iL %s --script=banner,ftp-anon --oA %sftpPorts' % (filename, BasePath)

    #ftpResults = scan(ftpScan)
    """ GREP AND CUTTING FOR FTP ANONYMOUS
     root@traversal-lap:~/PycharmProjects/autoRecon/base# cat ftpPorts.nmap  | grep -B 8 230 | grep "Nmap scan report" | cut -d " " -f 5
    192.168.56.102
     """




# need to add parsing the file for anonymous access.

def smbScan(filename):
    print "[-] Starting SMB scan to run enum4Linux and smb checks"
    name = 'enum4linux'
    portList = [139,445]
    smbScan = 'nmap -sV -Pn -vv -p %s -iL %s  --oA %s%s' % (str(portList)[1:-1], filename, BasePath, name)
    #--script=smb-enum-shares,smb-enum-users,smb-os-discovery,smb-brute
    scan(smbScan)
    type1 = 'Enum4Linux'
    OutputFile = 'hosts_smbports.txt'
    test = portSelection('%s%s.gnmap' % (BasePath, name), portList, OutputFile, type1)

    smbhostsfile = BasePath + OutputFile
    if test == True:
        print "[!] SMB Ports were identified, running EyeWitness"
        for x in open(smbhostsfile, 'r'):
            Enum4Linux(x.split(":")[0])
    else:
        print "[!]No SMB ports found"
        print "[!] Not running Enum4Linux"

def NiktoScan(ipToScan):
    if constants.osVersion == 'Debian':
        NiktoPath = '/pentest/vulnerability-analysis/nikto'
        command = '%s/nikto.pl -h %s >> %sNikto_%s.txt' % (NiktoPath, ipToScan, FullSubDirPath, ipToScan)
    if constants.osVersion == 'Kali':
        command = 'nikto -h %s >> %senum4_%s.output' % (ipToScan, BasePath, ipToScan)
        FNULL = open(os.devnull, 'w')  # Suppress enum4linux output
        subprocess.Popen(command, stdout=FNULL, stderr=subprocess.STDOUT, shell=True).wait()
        FNULL.close()

    print  "[-] Running Nikto with: %s" % command

    p5 = Process(target=scan, args=(command,))
    p5.start()

def DirbusterScan(ipToScan,port):
    #open('%sDirb_%s.txt' % (FullSubDirPath,ipToScan), 'w').close()
    if port == 80:
        prepend = 'http://'
    elif port == 443:
        prepend = 'https://'
    else:
        prepend = ""
    open('%sDirb_%s_%s.txt' % (FullSubDirPath, ipToScan,str(port)), 'w').close()
    if constants.osVersion == 'Debian':
        DirbPath = '/pentest/intelligence-gathering/dirb'
        command = '%s/dirb %s%s %s/wordlists/common.txt >> %sDirb_%s_%s.txt' % (DirbPath, prepend, ipToScan,DirbPath, FullSubDirPath, ipToScan,str(port))
    elif constants.osVersion == 'Kali':
        command = 'dirb %s%s >> %senum4_%s.output' % (prepend, ipToScan, BasePath, ipToScan)
        FNULL = open(os.devnull, 'w')  # Suppress enum4linux output
        subprocess.Popen(command, stdout=FNULL, stderr=subprocess.STDOUT, shell=True).wait()
        FNULL.close()
    else:
        command = "NOTHING RUNNING"

    print  "[-] Running Dirb with: %s" % command

    p5 = Process(target=scan, args=(command,))
    p5.start()



def Enum4Linux(ipToScan):
    if constants.osVersion == 'Debian':
        Enum4LinuxPath = '/pentest/intelligence-gathering/enum4linux'
        command = '%s/enum4linux.pl %s >> %senum4_%s.output' % (Enum4LinuxPath, ipToScan, FullSubDirPath, ipToScan)
    if constants.osVersion == 'Kali':
        command = 'enum4linux %s >> %senum4_%s.output' % (ipToScan, BasePath, ipToScan)
        FNULL = open(os.devnull, 'w')  # Suppress enum4linux output
        subprocess.Popen(command, stdout=FNULL, stderr=subprocess.STDOUT, shell=True).wait()
        FNULL.close()

    print  "[-] Running Enum4Linux with: %s" % command

    p5 = Process(target=scan, args=(command,))
    p5.start()



def eyewitness(filename, outputName):  # expecting IP addrees list
    print "[-] Starting Eye Witness scan"
    # this requires editing the Eyewitness.py to use /bin/phantomjs
    checkDir = ""
    if constants.osVersion == 'Debian':
        try:
            checkDir = scan('ls %s | grep %s' % (BasePath, outputName))
        except Exception as e:
            print e
            pass
        #this removes the directory if already created. This prevents Eyewitness from not working
        #EyeWitness will not run if the directory is already created * asks for overwrite*
        if checkDir != "":
            if checkDir.strip("\n") == outputName:
                print "[!] Found Directory %s, removing so EyeWitness can create" % outputName
                scan('rm -rf %s%s' % (BasePath, outputName))
                # raw_input("PAUSE")
        else:
            print "%s directory not found, EyeWitness will create it." % outputName
        eyewitnessPath = '/pentest/intelligence-gathering/eyewitness' #using PTF base directory for eyewitness
        command = '%s/EyeWitness.py --headless --prepend-https --prepend-http --no-prompt  -x %s -d %s%s' % (
            eyewitnessPath, filename, BasePath, outputName)
        print  "[!] Running EyeWitness with: ", command
    elif constants.osVersion == 'Kali':
        # filename = webPorts_common.xml
        command = 'eyewitness --web --no-prompt -x ../../../../../root/TestScript/%s%s' % (filename)
        print "[!] Running EyeWitness with: ", command
    else:
        command = "**EYE WITNESS WILL NOT RUN*"
    FNULL = open(os.devnull, 'w')  # Suppress eyewitness output
    subprocess.Popen(command, stdout=FNULL, stderr=subprocess.STDOUT, shell=True).wait()
    FNULL.close()
    print "[!] EyeWitness web ports scan finished"
    print "[-] Located in the %s Directory" % outputName
    print "[-] Full path == %s%s" %(BasePath, outputName)


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
        if ("Debian" in (osVer.split("\t"))[1]) or ("Ubuntu" in (osVer.split("\t"))[1]):
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


    baseDir = "autoReconScans"
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



if __name__ == '__main__':

    # this is the start of the script, taking the IP addresses from a text file called IP.txt
    ## Not anymore takes a filename as an argument now :)
    parser = argparse.ArgumentParser()
    parser.add_argument("--exhaustive", help="Runs all Exhaustive scans", action="store_true")
    parser.add_argument("IPList2", help = "File with IP addresses for scanning")

    args = parser.parse_args()

    print "AUTORECON - **IN DEVELOPMENT**"
    print "by - @haydnjohnson, contributers - @loneferret"
    print "This Tool uses Kali Linux and Pentesters Framework as a Foundation"
    print "for PTF this assumes the base directory is /pentest"
    print "This Version does not include an ability to change default PTF directory yet"
    print "Attribution, additionally based off of @securitysift (Mike Czumak) from : http://www.securitysift.com/offsec-pwb-oscp/ then re-written but idea goes to him for inspriation and port parsing"

    raw_input("<Press ENTER to Continue>")


    BaseFolder = 'autoReconScans'
    SubDir = 'SubDir_indiv_scans'
    BasePath = baseTest.BaseLineTest(BaseFolder, SubDir)
    FullSubDirPath = BasePath + SubDir + '/'
    print "Full Path for Sub Directory will be: ", FullSubDirPath

    textfile = args.IPList2
    #textfile = "IP.txt"
    # === Commented out for easy testing ==#
    # if len(sys.argv) == 1:
    #     print "[-] Usage %s <filename>" % sys.argv[0]
    #     print "[-] Example: %s IPlist.text" % sys.argv[0]
    #     print "[!] Quitting..."
    #     print sys.exit()
    # else:
    #     textfile = sys.argv[1]

    exhaustive_scan = False
    if args.exhaustive:
        print "+++++++++++++++++++++++++++"
        print "Exhaustive Scans will Run"
        print "[-] SMB to5 Enum4Linux"
        print "[-] WebPorts to EyeWitness"
        print "[-] All 65535 port Scan"
        print "+++++++++++++++++++++++++++"
        time.sleep(3)
        exhaustive_scan = True


    print "\n" # adding space

    #checking OS system
    if "Kali" == getOsVersion():
       checkKaliApps()
    f = open(textfile, 'r') #opening file with IP addresses

    IndividualIPs = []
    try:
        lines = open(textfile).read().split("\n")
        for x in lines:
            if '/' in x:
                print 'subnet FOUND'
                subnetIP = IPNetwork(x)
                for x in subnetIP:
                    IndividualIPs.append(x)
        else:
            IndividualIPs.append(x)

    except Exception as e:
        print e

    print len(IndividualIPs)






    """THE BELOW MAY BE REDUNDANT as all scans work off the original file"""
    # print"[-] Opening file with IP addresses..."
    # IPList = [] #blank array to hold IP addresses from file
    # total = 0
    # for IP in f:
    #     IPList.append(IP) # appending IP addresses to list
    #     total = total + 1 #Counting number of IP addresses included
    # print"[+] Total Number of IPs: %s" % total
    # IPListClean = []# array to hold stripped IPs
    # total = 0
    # for IP in IPList:
    #     IPListClean.append(IPList[total].strip('\n')) #stripping end line from IP addresses
    #     total += 1
    # # p3 = Process(target=scan, args=(launchresults,))
    # # p3.start()
    #
    # for IP in IPListClean:
    #     print"\t[*] IPs ", IP

    """====FIRST SCAN TO RUN===="""

    TCPSCAN3 = 'nmap -iL %s -sn -T4 -PE -PM -PP -PU53,69,123,161,500,514,520,1434 -PA21,22,23,25,53,80,389,443,513,636,8080,8443,3389,1433,3306,10000 -PS21,22,23,25,53,80,443,513,8080,8443,389,636,3389,3306,1433,10000 -n -r -vv -oA %shostsup3_ports' % (textfile, BasePath)
    scan(TCPSCAN3)

    for x in range(0,5):
        print "[!]First Hosts up Scan finished, Check %shostsup3_ports.nmap" % BasePath
    try:
        p1 = Process(target=hostsup_scans, args=(textfile,))
        p1.start()
    except Exception as e:
        print e

    webports('IP.txt')


    # tcp_results3 = subprocess.check_output(TCPSCAN3, shell=True)

    # p = Process(target=quicknmapScan, args=(IP,))

    # Start enum4linux threads
    # enum4linux scans 1 ip at a time, hence the loop
    # lines = open(textfile).read().split("\n")
    # for ip in lines:
    #     enumThread = threading.Thread(target=Enum4Linux, args=(ip.rstrip('\r\n'),))  # Strip out newlines
    #     enumThread.daemon = True
    #     enumThread.start()



    #open('%s testinghosts.txt' %BasePath, 'w').close()
    f.close()
