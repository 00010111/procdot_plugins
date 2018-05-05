#!/usr/bin/env python

# python code to get report about a url from virustotal
# print statments will not be shown as plugin runs with more hidden.
# change vt_url.pdp 'RunHidden' to '0' in order to get the print output

# Author = @b00010111
#

import requests
from time import sleep
import configparser
import os

try:
	#print (os.environ['PROCDOTPLUGIN_VerificationRun'])
	if os.environ['PROCDOTPLUGIN_VerificationRun'] == '1':
		# if we get an exception here, verificaiton failed, otherwise exit with 1
		os.environ['PROCDOTPLUGIN_CurrentNode_Details_Domain']
		exit(1)
except Exception as e:
	# we do not have a Domain in the CurrentNote Details, so we do not what to show this plugin
	# if anything else fails above.. we do not want to show this plugin either
	print ("we could either not run the verification or the current node does not have a domain")
	print ("if set CanBeVerified to 0, this exception will always be triggered")	
	exit(0)


# get procdot plugins path from environment var
p = os.environ['PROCDOTPLUGIN_PluginsPath']
out = os.environ['PROCDOTPLUGIN_ResultTXT']
f = open(out,'w')
#f.write('{{{style-id:default;color:black;style-id:one;color:red;style-id:two;color:white;background-color:black}}}')
print (out)

apipath = os.path.join(p, 'api_keys.txt')
#get api key for virustotal from config file
try:
	config = configparser.ConfigParser()
	# prefix string with r to get raw sting, getting around unicode errors
	#config.readfp(open(r'C:\Users\REM\procdot_dev\vt_plugin\api_keys.txt'))
	config.readfp(open(apipath))
	apikey = config['virustotal']['apikey']
	if apikey == "INSERT-VIRUSTOTAL-API-KEY-HERE":
		f.write('You did not change the API key. Enter you API-key into file: ' + apipath)
		exit(0)
	verbose = config['virustotal']['verbose']
	#print (apikey)
except Exception as e:
	f.write("ERROR while parsing file containing api keys/config")

print (apikey)
print (verbose)

url = os.environ['PROCDOTPLUGIN_CurrentNode_Details_Domain']

# set up headers we use to access virustotal
headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "procdot_vt_plugin_url"
  }

# define virustotal urls
vt_url_scan = 'https://www.virustotal.com/vtapi/v2/url/scan'
vt_url_report = 'https://www.virustotal.com/vtapi/v2/url/report' 
  
# setup parameters for scanning to URL
params = {'url': url, 'apikey': apikey }
try:
	response = requests.post(vt_url_scan, params=params, headers=headers)
	json_response = response.json()
except Exception as e:
	f.write("ERROR while trying to access virustotal\n")
	f.write(str(e))

#DEBUG print
print (json_response)
print (json_response['scan_id'])
print (json_response['scan_date'])
#DEBUG print

# scan_id we use to get report later on
res = json_response['scan_id']

# scan submitted and retrieved scan_id to get report 
# sleep 5 seconds before sending next request
sleep(5)

# setup parameters for retrieving the report 
params = {'resource': res, 'apikey': apikey, 'scan': '1'}
try:
	response = requests.post(vt_url_report, params=params, headers=headers)
	json_response = response.json()
except Exception as e:
	f.write("ERROR while trying to access virustotal\n")
	f.write(str(e))
try:	
	#DEBUG print
	print (json_response)
	print (json_response['scan_id'])
	print (json_response['scan_date'])
	#DEBUG print

	f.write('Scan Date: ' + str(json_response['scan_date']) + '\n')
	f.write('Submitted URL: ' + str(url) + '\n')
	f.write('VT verbose response: ' + str(json_response['verbose_msg']) + '\n')
	f.write('Total scanned: ' + str(json_response['total']) + '\n')
	f.write('Total positives: ' + str(json_response['positives']) + '\n')
	f.write('Direct link to report: ' + str(json_response['permalink']) + '\n')

	if verbose :
		#print ("TRUE")
		b = json_response['scans']
		for key, value in b.items():
			f.write(str(key) + ' detected: ' + str(value['detected']) + ' result: ' + str(value['result']) + '\n')
except Exception as e:
	f.write("ERROR while writing to txt file.\n")
	f.write(str(e))
	
print ("ENDE")

