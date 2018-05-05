# procdot_plugins
Plugins for the ProcDot.<br/>
Credis:
* @ProcDOT for actually writing ProcDOT
* @bmmaloney97 for his tutorial on writing Plugins for ProcDOT

How to check if the used python modules are installed:
* windows: python.exe -c "help('INSERT-MODULE-NAME-HERE')"
* linux:  python3 -c "help('INSERT-MODULE-NAME-HERE')"
* expect something like "No Python documentation found for ..." in case of missing module

## VirusTotal URL plugin
Credits: <br/>
&nbsp;@Didelphodon for the plugin idea<br/>
Use Case:<br/>
&nbsp;Submit a URL to VirusTotal via a contextmenue item. Receive report will be shown within ProcDOT.<br/>
Name:<br/>
&nbsp;vt_url<br/>
Requirements:
* VirusTotal API key (see VirusTotal how to get a free or paid one)
* python 3
* python modules
  * requests
  * configparser
* python modules used, but should be included in default install
  * os
  * time

Setup:
* place plugin (Linux: vt_url.py; Windows:vt_url.bat), vt_url.pdp and api_config.txt in ProcDot plugins folder
* open api_config.txt and fill in your VirusTotal API key 
* Linux: make vt_url.py executable
* if you use more than one of the virustotal plugins, you just need one api_config.txt file containing all neccesary parameters

## VirusTotal IP plugin
Credits: <br/>
&nbsp;@Didelphodon for the plugin idea<br/>
Use Case:<br/>
&nbsp;Submit a IP to VirusTotal via a contextmenue item. Receive report will be shown within ProcDOT.<br/>
Name:<br/>
&nbsp;vt_url<br/>
Requirements:
* VirusTotal API key (see VirusTotal how to get a free or paid one)
* python 3
* python modules
  * requests
  * configparser
* python modules used, but should be included in default install
  * os
  * time

Setup:
* place plugin (Linux: vt_url.py; Windows:vt_url.bat), vt_url.pdp and api_config.txt in ProcDot plugins folder
* open api_config.txt and fill in your VirusTotal API key 
* Linux: make vt_url.py executable
* if you use more than one of the virustotal plugins, you just need one api_config.txt file containing all neccesary parameters