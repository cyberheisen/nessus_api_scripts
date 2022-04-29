# nessus_api_scripts

This repo contains scripts written to interact with a Nessus scanner through the Nessus API.  

ssh_login_check.py - When the Debugging Log Report plugin is enabled, ssh login results are saved in the ssh_logins.log attachment contained in the plugin results.  This script extracts the attachment data and provides a csv file output of the login results for each host.
