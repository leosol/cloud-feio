import concurrent.futures
import pycurl
from StringIO import StringIO
import ipaddress
import time
from datetime import date
import signal
import sys
import argparse
import os.path

networkList = []
hintStrings = []

REQUESTED_SIGINT = 0
SUCCESS_COUNT = 0
SUCCESS_ITEMS = []
def check_site(scheme, vhost, ipaddr, hintStrings, LOG_FILE):
	global SUCCESS_COUNT
	global SUCCESS_ITEMS
	#print('check_site:\t'+ipaddr+'('+scheme+')')
	sys.stdout.write('.')
	sys.stdout.flush()
	try:
		buffer = StringIO()
		curl = pycurl.Curl()
		curl.setopt(curl.URL, scheme+'://'+vhost+'/')
		curl.setopt(curl.VERBOSE, 0)
		curl.setopt(curl.CONNECTTIMEOUT, 30)
		curl.setopt(curl.TIMEOUT, 30)
		curl.setopt(curl.FOLLOWLOCATION, 1)
		curl.setopt(curl.AUTOREFERER,1)
		curl.setopt(curl.USERAGENT, 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Safari/537.36')
		curl.setopt(curl.RESOLVE, [vhost+':80:'+ipaddr, vhost+':443:'+ipaddr])
		curl.setopt(curl.WRITEDATA, buffer)
		curl.perform()
		status_code = curl.getinfo(curl.HTTP_CODE)
		curl.close()
		
		body = buffer.getvalue()
		score = 0
		for s in hintStrings:
			if s in body:
				score = score + 1
		foundStr = ""
		if score>0:
			foundStr = " (FOUND!) "
			respfile = open('resp_'+scheme+'-'+ipaddr+'.dat', 'w')
			respfile.write(body)
			respfile.flush()
			respfile.close()
			SUCCESS_COUNT = SUCCESS_COUNT+1
			SUCCESS_ITEMS.append('resp_'+scheme+'-'+ipaddr+'.dat')
			

		LOG_FILE.write("IP:\t"+ipaddr+'\n')
		LOG_FILE.write("Scheme:\t"+scheme+'\n')
		LOG_FILE.write("Code:\t"+ str(status_code)+'\n')
		LOG_FILE.write("Score:\t"+str(score)+foundStr+'\n')
	except:
		LOG_FILE.write("IP:\t"+ipaddr+" (failed)\n")
		LOG_FILE.write("Scheme:\t"+scheme+'\n')
		LOG_FILE.write("Code:\t-1\n")
		LOG_FILE.write("Score:\t-1\n")	
	LOG_FILE.flush()	

def check_site2(scheme, vhost, ipaddr, hintStrings, LOG_FILE): 
	global SUCCESS_COUNT
	global SUCCESS_ITEMS
	sys.stdout.write('.')
	sys.stdout.flush()
	try:
		buffer = StringIO()
		curl = pycurl.Curl()
		curl.setopt(curl.HTTPHEADER, ['HOST: '+vhost])
		curl.setopt(curl.URL, scheme+'://'+ipaddr+'/')
		curl.setopt(curl.SSL_VERIFYPEER, False)
		curl.setopt(curl.SSL_VERIFYHOST, False)
		curl.setopt(curl.VERBOSE, 0)
		curl.setopt(curl.CONNECTTIMEOUT, 30)
		curl.setopt(curl.TIMEOUT, 30)
		curl.setopt(curl.FOLLOWLOCATION, 1)
		curl.setopt(curl.AUTOREFERER,1)
		curl.setopt(curl.USERAGENT, 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Safari/537.36')
		curl.setopt(curl.RESOLVE, [vhost+':80:'+ipaddr, vhost+':443:'+ipaddr])
		curl.setopt(curl.WRITEDATA, buffer)
		curl.perform()
		status_code = curl.getinfo(curl.HTTP_CODE)
		curl.close()
		
		body = buffer.getvalue()
		score = 0
		for s in hintStrings:
			if s in body:
				score = score + 1
		foundStr = ""
		if score>0:
			foundStr = " (FOUND!) "
			respfile = open('resp_'+scheme+'-'+ipaddr+'.dat', 'w')
			respfile.write(body)
			respfile.flush()
			respfile.close()
			SUCCESS_COUNT = SUCCESS_COUNT+1
			SUCCESS_ITEMS.append('resp_'+scheme+'-'+ipaddr+'.dat')
			

		LOG_FILE.write("IP:\t"+ipaddr+'\n')
		LOG_FILE.write("Scheme:\t"+scheme+'\n')
		LOG_FILE.write("Code:\t"+ str(status_code)+'\n')
		LOG_FILE.write("Score:\t"+str(score)+foundStr+'\n')
	except:
		LOG_FILE.write("IP:\t"+ipaddr+" (failed)\n")
		LOG_FILE.write("Scheme:\t"+scheme+'\n')
		LOG_FILE.write("Code:\t-1\n")
		LOG_FILE.write("Score:\t-1\n")	
	LOG_FILE.flush()

def spawnNetworks(networkList):
	result = []
        for networkItem in networkList:
		#print("Spawning network "+networkItem)
		network = ipaddress.ip_network(unicode(networkItem))
            	for item in network.hosts():
                	result.append(item)
	return result

def findVhost(ipList, domain, LOG_FILE):
	LOG_FILE.write('Starting FIND-VHOST AT '+str(date.today())+'\n')
	totalitems = len(ipList)
	execution_time = 0
	processedItems = 0
	for ip in ipList:
		start_time = time.time()
		check_site('http', domain, str(ip), LOG_FILE)
		check_site('https', domain, str(ip), LOG_FILE)
		spent_time = (time.time() - start_time)
		execution_time = execution_time+spent_time
		processedItems = processedItems+1
		if processedItems % 1 == 0:
			print("Total:\t"+str(totalitems))
			print("Position:\t"+str(processedItems))
			print("Everage:\t"+str(execution_time/processedItems))

def doFindVhostWithThreadPool(ipaddr, hostname, hintStrings, LOG_FILE):
	#check_site2('http', hostname, str(ipaddr), hintStrings, LOG_FILE)
	check_site2('https', hostname, str(ipaddr), hintStrings, LOG_FILE)

processedItems = 0
def future_callback_error_logger(future):
	global processedItems
	e = future.exception()
	if e is not None:
        	print("Executor Exception", e)
	else:
		processedItems = processedItems+1


def findVhostWithThreadPool(ipList, hostname, hintStrings, LOG_FILE):
	global processedItems
	global SUCCESS_COUNT
	global SUCCESS_ITEMS
	LOG_FILE.write('Starting FIND-VHOST AT '+str(date.today())+'\n')
	totalitems = len(ipList)
	LOG_FILE.write('Total hosts '+str(totalitems)+'\n')
	start_time = time.time()
	executor = concurrent.futures.ThreadPoolExecutor(max_workers=250)
	with executor:
		futures = []
		for item in ipList:
			future = executor.submit(doFindVhostWithThreadPool, ipaddr=item, hostname=hostname, hintStrings=hintStrings, LOG_FILE=LOG_FILE)
			future.add_done_callback(future_callback_error_logger)
                	futures.append(future)
		executor.shutdown(wait=True)
	spent_time = (time.time() - start_time)
	print('\n')
	print("Total:\t"+str(totalitems))
	print("Processed:\t"+str(processedItems))
	print("Seconds: \t"+str(spent_time))
	print("Everage:\t"+str(spent_time/processedItems))
	print("SUCCESS_COUNT:\t"+str(SUCCESS_COUNT))
	print("SUCCESS evidences:\t"+str(SUCCESS_ITEMS))


def signal_handler(sig, frame):
	print('You pressed Ctrl+C!')
	REQUESTED_SIGINT = 1
	sys.exit(0)

def launchChecker(domain, networks, texts, LOG_FILE):
	ipList = spawnNetworks(networks)
	question = 'About to dispatch requests to '+str(len(ipList))+'. are you sure?'
	reply = str(raw_input(question+' (Y/n): ')).lower().strip()
	if reply[0] == 'y':
		findVhostWithThreadPool(ipList, domain, texts, LOG_FILE)
	else:
		print('Okay, maybe later...')

parser = argparse.ArgumentParser(description='Find Vhost')
parser.add_argument('domain', help='Domain name (www.example.com).')
parser.add_argument('networks', help='A file with a list of networks or a single network (192.168.1.0/24)')
parser.add_argument('expected-txt', help='Texts that actually exists in the expected response.')
args = vars(parser.parse_args())
domain = args["domain"]
networks = args["networks"]
expected_txt = args["expected-txt"]

if domain is None:
	print('Domain not set')
	exit()

if networks is None:
	print('networks not set')
	exit()

if expected_txt is None:
	print('expected_txt not set')
	exit()

var_networks = []
if os.path.isfile(networks):
	with open(networks) as my_file:
    		for line in my_file:
        		var_networks.append(line.strip())
else:
	var_networks.append(networks)

var_expected_txt = []
if os.path.isfile(expected_txt):
	with open(expected_txt) as my_file:
    		for line in my_file:
        		var_expected_txt.append(line.strip())
else:
	var_expected_txt.append(expected_txt)

LOG_FILE = open('find-vhost.log', 'w')
launchChecker(domain, var_networks, var_expected_txt, LOG_FILE)
LOG_FILE.close()

