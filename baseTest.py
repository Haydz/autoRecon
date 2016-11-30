import subprocess

def scan(command):
    launchresults = subprocess.check_output(command, shell=True)
    return launchresults

def BaseLineTest(baseDir,secondDir = None):
	print "+++++++++++++++++++++++++++++++++++"
	print "+++++ RUNNING BASELINE CHECKS +++++"
	print "++++ ROOT | Base Directory etc ++++"
	print "+++++++++++++++++++++++++++++++++++\n"
	# Checking Running as root, for write perms
	try:
		checkPermissions = 'whoami'
		checkPermissionsResults = scan(checkPermissions)
	except Exception as e:
		print e

	if checkPermissionsResults:
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


	#baseDir = "ArpHosts"
	# create base sub dir to place all files
	try:
		mkBaseDir = "mkdir %s" % baseDir
		scan(mkBaseDir)
	except Exception as e:
		print e,
		print " Cannot create %s directory\n" % baseDir

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


	if secondDir:
		try:
			mkBaseDir = "mkdir %s/%s" % (baseDir,secondDir)
			scan(mkBaseDir)
		except Exception as e:
			print e,
			print " Cannot create %s directory\n" % secondDir

		# check dir was created
		try:
			checkDir = "ls | grep %s%s" % (baseDir, secondDir)
			checkDirDirResults = scan(checkDir)
			if baseDir in checkDirDirResults:
				print "BASE directory & Sub directory found.. continuing"
		except Exception as e:
			print e
		print "Base Directory: %s" % baseDir
		print "Sub Directory: %s%s" %(baseDir,secondDir)
		#o se FullPath
	else:
		print "No Second Sub Directory Chosen"

	return FullPath