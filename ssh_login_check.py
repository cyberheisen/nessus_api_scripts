# ssh_login_check
# 1.0 
# Joel Quevedo
#04.26.2022

import csv
import getpass
import requests
import os
import tqdm
import urllib3

#disable ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# initialize global variables
token = None
headers = {}
plugin_id = '84239'
filename = './ssh_status.csv'
results = []
test = False

# All api http get requests are processed by this function
def get(url,format):
    try:
        r = requests.get(url=url, headers=headers, verify=False)
        if format == "json":
            response = r.json()
        else:
            response = r.text
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)
    return response 

# All api http post requests are processed by this function.
def post(url,data,format):
    try:
        r = requests.post(url, data=data, headers=headers, verify=False)
        if format == "json":
            response = r.json()
        else:
            response = r.text
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)
        end_session()
    return response

# this function authenticates our Nessus user and provides a security token
def login(username,password):
    data = {"username":username,"password":password}
    login_url = base_url+"/session"
    token = post(login_url,data,"json")
    return(token)

# This function extracts the token from the authentication response
def parse_token(data):
    error = data.get("error")
    if not error:
        token = data.get("token")
        return token
    else:
        print(error)
        print("Logoff existing sessions or try again later\n")
        exit(1)

# This function ends our Nessus session
def end_session():
    print("\n[+] Logging off")
    try:
        url = base_url + "/session"
        r = requests.delete(url=url, headers=headers, verify=False)
        if r.status_code == 200:
            print("[-] Logged off")
            exit(0)
        else:
            print("[!] Not Logged in")
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)
        exit(1)
    return 

# This function will export the final results to a csv file.
def writeCSV(data,filename):
    print ("\n[+] Writing Results")
    header = ['hostname','status']
    try:
        with open(filename, 'a') as f:
            writer = csv.writer(f)
            writer.writerow(header)
            for row in data:
                writer.writerow(row) 
    except IOError as e:
        end_session()
        print(e)
        exit()
    print("[-] Wrote %s bytes to %s" % (os.stat(filename).st_size,filename))

# this function requests the Nessus Scan results
def get_scan(scan_id):
    url = base_url + "/scans/" + scan_id
    print("[+] Retrieving scan and plugin information\n")
    data = get(url,"json")
    hosts = data.get("hosts")
    return hosts

# This function validate that the Debugging Log Report plugin exists in the scan.
def test_for_plugin(hostname,host_id,plugin_id,scan_id):
    url = base_url+"/scans/" + scan_id + "/hosts/" + str(host_id) + "/plugins/" + plugin_id
    data = get(url,"json")
    outputs_dict = data.get("outputs")
    if outputs_dict == None:
        print ("[!] The Debugging Log Report plugin was not enabled for this scan.  Ensure plugin 84239 is enabled\n")
        end_session() 
    else:
        return

# This function extracts the plugin information for a given scan result
def get_plugin_info(hostname,host_id,plugin_id,scan_id):
    # this list will contain one record containing hostname and status.
    # it will be added to the global "results" list containing all records
    result = []
    url = base_url+"/scans/" + scan_id + "/hosts/" + host_id + "/plugins/" + plugin_id
    data = get(url,"json")
    outputs_dict = data.get("outputs")
    
    for output in outputs_dict:
        ports_dict = output.get("ports")
        for port in ports_dict:
            plugin_info = ports_dict.get(port)
            attachments = plugin_info[0].get("attachments")
            for attachment in attachments:
                # we are only interested in the ssh_get_info.log file which contains
                # the ssh login debug information
                if (attachment.get("name") == 'ssh_get_info.log'):
                    # the attachment id and key is needed to request the file
                    attachment_id = str(attachment.get("id"))
                    attachment_key = str(attachment.get("key"))
                    result.append(hostname)
                    # we pass the relevant information to obtain a parsed status for our host
                    status = get_attachment(scan_id,attachment_id,attachment_key)
                    result.append(status)
    return result

# This function obtains the specific attachment and processes the information 
def get_attachment(scan_id,attachment_id,attachment_key):
    url = base_url + "/scans/" +scan_id + "/attachments/" + attachment_id + "?key=" + attachment_key
    # the attachment request results must be parsed as "text" rather than "json"
    data = get(url,"text")
    # Once we have the results, we want to do some simple parsing to get the 
    # relevant information
    if "Failed to authenticate" in data:
        return "Failed to authenticate"
    elif "Failed to open a socket" in data:
        return "System did not respond"
    elif "Authentication success" in data:
        return "Authentication was successful"
    else:
        return (data)

# Start here
if __name__ == "__main__":
    
    #Nessus API documentation is available at http://<nessusserver>:8834/api
    print("This program provides a listing of hosts and their ssh login status during a scan. In order to operate, the Debugging log report plugin (84239) must have been enabled for the scan.\n")
    #Obtain the credentials for the Nessus Server
    username = input("Username: ")
    password = getpass.getpass(prompt="Password: ",stream=None)

    #The nessus server url and scan id information will be extracted from the full url
    # of the nessus scan results
    scan_url = input("Enter the full url for the Nessus scan results: ")
    scan_url_list = scan_url.split("/")
    base_url = scan_url_list[0] + "//" + scan_url_list[1] + scan_url_list[2]
    scan_id = scan_url_list[6]

    #With the Nessus url in hand now, we can authenticate and obtain a token.
    #The token is used to authorize each API request.
    raw_token = login(username,password)
    token = parse_token(raw_token) 
 
    # if we have a valid token... 
    if token:
        # add the token value to our headers going forward
        headers = {"X-Cookie":"token=" + token}
        print("\n[+] Logged in as %s" % username)
        
        # and let's dive into the scan results
        hosts = get_scan(scan_id)
 

        #we need to validate the debugging log report plugin was enabled
        #we'll do a quick check on the first host.
        test_for_plugin(hosts[0].get("hostname"),hosts[0].get("host_id"),plugin_id,scan_id)

        # How many hosts are in the scan?
        total_hosts = len(hosts)
        #Now we cycle through the lists of hosts
        #tqdm gives us the nice progress bar
        for i in tqdm.tqdm(range(total_hosts)):
            # we need the hostname for our final output
            hostname = hosts[i].get("hostname")
            # we need the host_id in order to retrieve plugin information
            host_id = str(hosts[i].get("host_id"))
            # get the plugin information for each host
            result = get_plugin_info(hostname,host_id,plugin_id,scan_id)
            results.append(result)           

        # Once all attachment information is retrieved and parsed, write the results
        # to a csv file.
        writeCSV(results,filename)
    else:
        print("Error logging in")
    # we're done, so let's end the session and program.
    end_session()
