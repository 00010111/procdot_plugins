#!/usr/bin/env python

# python code to get report about a url from virustotal
# print statments will not be shown as plugin runs with more hidden.
# change vt_ip.pdp 'RunHidden' to '0' in order to get the print output

# Author = @b00010111
#

import requests
from time import sleep
import configparser
import os


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
	verbose = config['virustotal']['verbose']
	res_count = int(config['virustotal_IP']['res_count'])
	dec_count = int(config['virustotal_IP']['dec_count'])
	decdow_count = int(config['virustotal_IP']['decdow_count'])
	deccom_count = int(config['virustotal_IP']['deccom_count'])
	#print (apikey)
except Exception as e:
	f.write("ERROR while parsing file containing api keys/config")

print (apikey)
print (verbose)

#print (os.environ)
#sleep(500)

ip = os.environ['PROCDOTPLUGIN_CurrentNode_Details_IP_Address']

print (ip)

# set up headers we use to access virustotal
headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "procdot_vt_plugin_ip"
  }

# define virustotal urls
vt_url_report = 'http://www.virustotal.com/vtapi/v2/ip-address/report'
  

# setup parameters for retrieving the report 
params = {'ip': ip, 'apikey': apikey, 'scan': '1'}
try:
	response = requests.get(vt_url_report, params=params, headers=headers)
	json_response = response.json()
except Exception as e:
	f.write("ERROR while trying to access virustotal\n")
	f.write(str(e))
try:	
	#DEBUG print	
	#DEBUG print
	f.write(str(json_response['verbose_msg']) + '\n')
	f.write('ASN: ' + str(json_response['asn']) + '\n')
	f.write(str('ASN Owner: ' + json_response['as_owner']) + '\n')
	f.write(str('Country: ' + json_response['country']) + '\n')

	if 'resolutions' in json_response:
		b = json_response['resolutions']
		if res_count > 0:
			if res_count > len(b):
				res_count = len(b)
			f.write('\nLast Domains resovling to given IP (passive DNS data):\n')
			for s in range(res_count):
				f.write('Hostname: ' + b[s]['hostname'] + ' last resolved: ' + b[s]['last_resolved'] + '\n' )
	else:
		if res_count > 0:
			f.write('\nResult did not contain last Domains resovling to given IP (passive DNS data)\n')

	if 'detected_urls' in json_response:
		d = json_response['detected_urls']
		if dec_count > 0:
			if dec_count > len(d):
				dec_count = len(d)
			f.write('\nURLs resolving to this IP address that have at least 1 detection on a URL scan:\n')
			for s in range(dec_count):
				f.write('Detected URL: ' + d[s]['url'] + ' positives: ' + str(d[s]['positives']) + ' Scan Date: ' + str(d[s]['scan_date']) + '\n' )
	else:
		if dec_count > 0:
			f.write('\nResult did not contain URLs resolving to this IP address that have at least 1 detection on a URL scan\n')

	if 'detected_downloaded_samples' in json_response:
		dds = json_response['detected_downloaded_samples']
		if decdow_count > 0:
			if decdow_count > len(dds):
				decdow_count = len(dds)
			f.write('\nFiles that have been downloaded from this IP address with at least one AV detection:\n')
			for s in range(decdow_count):
				f.write('positives: ' + str(dds[s]['positives']) + ' Scan Date: ' + str(dds[s]['date']) + ' Filehash sha256: ' + str(dds[s]['sha256']) + '\n' )			
	else:
		if decdow_count > 0:
			f.write('\nResult did not contain files that have been downloaded from this IP address with at least one AV detection\n')
			
	if 'detected_communicating_samples' in json_response: 			
		dcs = json_response['detected_communicating_samples']
		if deccom_count > 0:
			if deccom_count > len(dcs):
				deccom_count = len(dcs)
			f.write('\nFiles that have been communicating to this IP address with at least one AV detection:\n')
			for s in range(deccom_count):
				f.write('positives: ' + str(dds[s]['positives']) + ' Scan Date: ' + str(dds[s]['date']) + ' Filehash sha256: ' + str(dds[s]['sha256']) + '\n' )			
	else:
		if deccom_count > 0:
			f.write('\nResult did not contain files that have been communicating to this IP address with at least one AV detection\n')
				
except Exception as e:
	f.write("ERROR while writing to txt file.\n")
	f.write(str(e))

sleep(10)	
print ("ENDE")

