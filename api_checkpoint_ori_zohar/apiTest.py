import CheckPointAPI as CP
import base64
import os
import cPickle as pickle
import time
# -- Api Notes Learned the hard way --
# Must supply body even if no params are needed
VERBOSE  =  False
CACHE = False
IP = "223.144.70.1"
PORT = "4434"
USERNAME  = "api-read"
PASSWORD = "UFJZSGF0cmU="
EXCLUDE_LIST = ['dhcp','interface','loopback','nexus','broadcast','fw','wan','nat','proxy','dns','encryptor','tavas']
DNS_LOG_NAME = 'dns-log.csv'
clear = lambda: os.system('cls')

def print_output(output):
	clear()
	print output

def main():
	print "[x] trying to connect to CMA"
	conn = CP.Connection(IP,PORT,verbose=False)

	if conn.login(USERNAME,base64.b64decode(PASSWORD)):
		print "[x] connected to CMA"
		try:
			ruleset = conn.get_rules(80)
			analyzer = CP.Analyzer(ruleset)
			analyzer.setSource('223.142.78.5')
			analyzer.setDestination('223.144.113.5')
			analyzer.setService('8530',CP.SERVICE_TCP)
			status = analyzer.analyze()
			print "Will Pass ? : {}".format(status)
		finally:
			conn.logout()
	else:
		print "[x] failed to connect to CMA"


main()

