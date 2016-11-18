"""This script is to test portions of scanning so that the whole script does not need to be modified."""


from multiprocessing import Process

# importing multi processing to support running multiple nmap comamnds (similar to multiple threads)
import multiprocessing
# import os for allowing OS interfacing, such as listinga  directory if needed
import os, sys, threading

# importing to allow the script to connect to input and out put pipes, such as out put from nmap scans
import subprocess
import time

def scan(command):
    launchresults = subprocess.check_output(command, shell=True)
    return launchresults


def ftpPort(filename,outputFile):
    placeholder = []
    print "[-] Starting FTP scan, checks anonymous"

    ftpScan = 'nmap -sV -Pn -vv -p 21 -iL %s --script=banner,ftp-anon -oA %sftpPorts' % (filename, FullPath)

    print ftpScan
    ftpResults = scan(ftpScan)

    anonAccess = 'cat %sftpPorts.nmap  | grep -B 8 230 | grep "Nmap scan report" | cut -d " " -f 5' % FullPath
    #print 'Cutting and grepping the hosts with anonymous access. command:'  % anonAccess
    anonAccessResults = subprocess.check_output(anonAccess, shell=True)
    lines = anonAccessResults.split("\n")
    #removing blanks within the list
    lines = [x for x in lines if x]

    #Print hosts to a file
    for x in lines:
        # prevents IP address being written twice
        if x not in placeholder:
            placeholder.append(x)
    # writing hosts with correct ports to a file
    print "PLACEHOLDER", placeholder

    ftpFullFilePath = ''.join((FullPath, outputFile))

    if placeholder:
        fileWriting = open(ftpFullFilePath, 'a')
        for line in placeholder:
            line = line.strip()
            fileWriting.write("%s\n" % line)
            fileWriting.close()
    else:
        print "NO Anonymous access for FTP Identified"

    print lines

if __name__ == '__main__':

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


    #print checkPermissionsResults
    #finding full full path of script
    checkPath = 'pwd'
    FullPath = scan(checkPath).strip() + '/'
    print "The Full path to be used for script is ", FullPath

    baseDir = "base"
    FullPath = ''.join((FullPath,baseDir)) + '/'
    print "Full path and baseDir ", FullPath

    # create base sub dir to place all files
    try:
        mkBaseDir = "mkdir %s" % baseDir
        scan(mkBaseDir)
    except Exception as e:
        print e
    #check dir was created
    checkDir = "ls | grep base"
    checkDirDirResults = scan(checkDir)
    if 'base' in checkDirDirResults:
        print "BASE directory found.. continuing"




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
    print " Opening File Name ", textfile
    print "[-] Opening file with IP addresses..."
    #
    # WList = f.read()
    IPList = []
    total = 0
    for IP in f:
        IPList.append(IP)
        total = total + 1

    anonAccessFile = 'FTPanonAccess.txt'

    ftpFullFilePath = ''.join((FullPath, anonAccessFile))
    ftpAnonAccessFile = open(ftpFullFilePath, 'w')
    ftpAnonAccessFile.write("===HOSTS WITH FTP ANONYMOUS ACCESS======\n")
    ftpAnonAccessFile.close()

    ftpPort(textfile,'FTPanonAccess.txt')
    print"[+] Total Number of IPs: %s" % total
    IPListClean = []
    total = 0

    for IP in IPList:
        IPListClean.append(IPList[total].strip('\n'))
        total = total + 1
