import concurrent.futures
import pycurl
from StringIO import StringIO
import ipaddress
import time
from datetime import date
from datetime import datetime
import signal
import sys
import argparse
import os.path
import socket
import ssl
import OpenSSL
import OpenSSL.crypto as crypto

REQUESTED_SIGINT = 0
SUCCESS_COUNT = 0
SUCCESS_ITEMS = []
FOLLOW_LOCATION = 1
TIMEOUT = 30
URL_RESOURCE = '/'
WORKERS = 250
COLLECT_CERTS = 0

WORKDIR =  datetime.now().strftime("SCAN %Y-%m-%d at %H-%M-%S")

def request_page_http(vhost, ipaddr):
	global FOLLOW_LOCATION
	global TIMEOUT
	global URL_RESOURCE
	buffer = StringIO()
	curl = pycurl.Curl()
	curl.setopt(curl.URL, 'http://'+vhost+URL_RESOURCE)
	curl.setopt(curl.VERBOSE, 0)
	curl.setopt(curl.CONNECTTIMEOUT, TIMEOUT)
	curl.setopt(curl.TIMEOUT, TIMEOUT)
	curl.setopt(curl.FOLLOWLOCATION, FOLLOW_LOCATION)
	curl.setopt(curl.AUTOREFERER,1)
	curl.setopt(curl.USERAGENT, 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Safari/537.36')
	curl.setopt(curl.RESOLVE, [vhost+':80:'+ipaddr, vhost+':443:'+ipaddr])
	curl.setopt(curl.WRITEDATA, buffer)
	curl.perform()
	status_code = curl.getinfo(curl.HTTP_CODE)
	curl.close()
	return {'status_code': status_code, 'body': buffer.getvalue()}

def request_page_https_sni(vhost, ipaddr):
	global FOLLOW_LOCATION
	global TIMEOUT
	global URL_RESOURCE
	buffer = StringIO()
	curl = pycurl.Curl()
	curl.setopt(curl.URL, 'https://'+vhost+URL_RESOURCE)
	curl.setopt(curl.VERBOSE, 0)
	curl.setopt(curl.SSL_VERIFYPEER, False)
	curl.setopt(curl.SSL_VERIFYHOST, False)
	curl.setopt(curl.CONNECTTIMEOUT, TIMEOUT)
	curl.setopt(curl.TIMEOUT, TIMEOUT)
	curl.setopt(curl.FOLLOWLOCATION, FOLLOW_LOCATION)
	curl.setopt(curl.AUTOREFERER,1)
	curl.setopt(curl.USERAGENT, 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Safari/537.36')
	curl.setopt(curl.RESOLVE, [vhost+':80:'+ipaddr, vhost+':443:'+ipaddr])
	curl.setopt(curl.WRITEDATA, buffer)
	curl.perform()
	status_code = curl.getinfo(curl.HTTP_CODE)
	curl.close()
	return {'status_code': status_code, 'body': buffer.getvalue()}

def request_page_https_nosni(vhost, ipaddr):
	global FOLLOW_LOCATION
	global TIMEOUT
	global URL_RESOURCE
	buffer = StringIO()
	curl = pycurl.Curl()
	curl.setopt(curl.HTTPHEADER, ['Host: '+vhost])
	curl.setopt(curl.URL, 'https://'+ipaddr+URL_RESOURCE)
	curl.setopt(curl.SSL_VERIFYPEER, False)
	curl.setopt(curl.SSL_VERIFYHOST, False)
	curl.setopt(curl.VERBOSE, 0)
	curl.setopt(curl.CONNECTTIMEOUT, TIMEOUT)
	curl.setopt(curl.TIMEOUT, TIMEOUT)
	curl.setopt(curl.FOLLOWLOCATION, FOLLOW_LOCATION)
	curl.setopt(curl.AUTOREFERER,1)
	curl.setopt(curl.USERAGENT, 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Safari/537.36')
	curl.setopt(curl.RESOLVE, [vhost+':80:'+ipaddr, vhost+':443:'+ipaddr])
	curl.setopt(curl.WRITEDATA, buffer)
	curl.perform()
	status_code = curl.getinfo(curl.HTTP_CODE)
	curl.close()
	return {'status_code': status_code, 'body': buffer.getvalue()}	

def collect_cert(ipaddr, port, LOG_FILE):
	if port < 0:
		LOG_FILE.write("IP "+str(ipaddr)+" port "+str(port)+" CN= Not Configured \n")
	try:
		#context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
		#s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#ssl_sock = context.wrap_socket(s, server_hostname=hostname)
		#ssl_sock.connect((ipaddr, port))
		#ssl_sock.close()
		cert = ssl.get_server_certificate((str(ipaddr), 443))
		x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
		der = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509)
		with open('./'+WORKDIR+'/certs/cert-'+str(ipaddr)+' port '+str(port), 'wb') as f: f.write(der)
		LOG_FILE.write("IP "+str(ipaddr)+" port "+str(port)+" CN=" + x509.get_subject().CN+'\n')
	except:
		LOG_FILE.write("IP "+str(ipaddr)+" port "+str(port)+" CN= FAILED \n")

def check_site(scheme, vhost, ipaddr, hintStrings, LOG_FILE): 
	global SUCCESS_COUNT
	global SUCCESS_ITEMS
	sys.stdout.write('.')
	sys.stdout.flush()
	LOG_FILE.write("_________________________\n")
	try:
		response = {}
		body = ''
		if scheme == 'http':
			response = request_page_http(vhost, ipaddr)
		elif scheme == 'https':
			response = request_page_https_nosni(vhost, ipaddr)
		elif scheme == 'https (SNI)':
			response = request_page_https_sni(vhost, ipaddr)

		body = response['body']
		status_code = response['status_code']
		score = 0
		for s in hintStrings:
			if s in body:
				score = score + 1
		foundStr = ""
		if score>0:
			foundStr = " (FOUND!) "
			respfile = open('./'+WORKDIR+'/resp_'+scheme+'-'+ipaddr+'.dat', 'w')
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
		check_site('https', domain, str(ip), LOG_FILE)
		spent_time = (time.time() - start_time)
		execution_time = execution_time+spent_time
		processedItems = processedItems+1
		if processedItems % 1 == 0:
			print("Total:\t"+str(totalitems))
			print("Position:\t"+str(processedItems))
			print("Everage:\t"+str(execution_time/processedItems))

def doFindVhostWithThreadPool(ipaddr, hostname, hintStrings, LOG_FILE):
	check_site('http', hostname, str(ipaddr), hintStrings, LOG_FILE)
	check_site('https', hostname, str(ipaddr), hintStrings, LOG_FILE)
	check_site('https (SNI)', hostname, str(ipaddr), hintStrings, LOG_FILE)
	if COLLECT_CERTS > 0:
		collect_cert(ipaddr, 443, LOG_FILE)

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
	global WORKERS
	LOG_FILE.write('Starting FIND-VHOST AT '+str(date.today())+'\n')
	totalitems = len(ipList)
	LOG_FILE.write('Total hosts '+str(totalitems)+'\n')
	start_time = time.time()
	executor = concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS)
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

#parser.add_argument('chars', type=str, nargs=2, metavar='c',help='starting and ending character')
parser = argparse.ArgumentParser(description='Find Vhost in many lans')
parser.add_argument('domain', type=str, help='Domain name (www.example.com).')
parser.add_argument('networks', type=str, help='A file with a list of networks or a single network (192.168.1.0/24)')
parser.add_argument('expected-txt', type=str, help='Texts that actually exists in the expected response.')
parser.add_argument('follow-redir', type=int, nargs='?', help='{0,1} Follow redirects (defaults to 1 - yes)')
parser.add_argument('timeout', type=int, nargs='?', help='Timeout (defaults to 30s)')
parser.add_argument('url-resource',type=str, nargs='?', help='Extra part of the URL - defaults to / (slash)')
parser.add_argument('workers', type=int, nargs='?', help='Max open requests at a single time (defaults to 250)')
parser.add_argument('collect-certs', type=int, nargs='?', help='{0,1} Collect certs (defaults to 0 - no)')

args = vars(parser.parse_args())
domain = args["domain"]
networks = args["networks"]
expected_txt = args["expected-txt"]
follow_redir = args['follow-redir']
timeout = args['timeout']
url_resource = args['url-resource']
workers = args['workers']
collect_certs = args['collect-certs']

if domain is None:
	print('Domain not set')
	exit()
if networks is None:
	print('networks not set')
	exit()
if expected_txt is None:
	print('expected_txt not set')
	exit()
if follow_redir is None:
	print('Follow location enabled (default option)')
	FOLLOW_LOCATION = 1
else:
	FOLLOW_LOCATION = int(follow_redir)
if timeout is None:
	TIMEOUT = 30
	print('Using default timeout of 30s')
else:
	TIMEOUT = int(timeout)
if url_resource is None:
	URL_RESOURCE = '/'
	print('No URL Resource was set')
else:
	if not url_resource.startswith('/'):
		print('URL RESOURCE SHOULD START WITH /')
		exit()
	else:
		URL_RESOURCE = url_resource
if workers is None:
	WORKERS = 250
	print('Using 250 as the number of Workers')
else:
	WORKERS = int(workers)

if collect_certs is None:
	COLLECT_CERTS = 0;
	print('Using No for collect certs')
else:
	COLLECT_CERTS = int(collect_certs)

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


if not os.path.exists(os.path.dirname('./'+WORKDIR+'/find-vhost.log')):
    try:
        os.makedirs(os.path.dirname('./'+WORKDIR+'/find-vhost.log'))
    except OSError as exc: 
        if exc.errno != errno.EEXIST:
            raise

if not os.path.exists(os.path.dirname('./'+WORKDIR+'/certs/')):
    try:
        os.makedirs(os.path.dirname('./'+WORKDIR+'/certs/'))
    except OSError as exc: 
        if exc.errno != errno.EEXIST:
            raise

LOG_FILE = open('./'+WORKDIR+'/find-vhost.log', 'w')
launchChecker(domain, var_networks, var_expected_txt, LOG_FILE)
LOG_FILE.close()

