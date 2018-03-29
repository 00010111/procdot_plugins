# procdot_plug-ins
Plug-ins for [ProcDot](http://procdot.com/) .<br/>
Credits:
* @ProcDOT for actually writing ProcDOT
* @bmmaloney97 for his tutorial on writing plug-ins for ProcDOT

How to check if the used python modules are installed:
* windows: python.exe -c "help('INSERT-MODULE-NAME-HERE')"
* linux:  python3 -c "help('INSERT-MODULE-NAME-HERE')"
* expect something like "No Python documentation found for ..." in case of missing module
## VirusTotal URL plug-in
Credits: <br/>
&nbsp;@Didelphodon for the plug-in idea<br/>
Use Case:<br/>
&nbsp;Submit a URL to VirusTotal via a context menu item. Receive report will be shown within ProcDOT.<br/>
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
* place plug-in (Linux: vt_url.py; Windows:vt_url.bat), vt_url.pdp and api_config.txt in ProcDot plug-ins folder
* open api_config.txt and fill in your VirusTotal API key 
* Linux: make vt_url.py executable
