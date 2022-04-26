import csv
import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


username = ''
password = ''
token = ''
scan_id = '4025'
plugin_id = '84239'
headers = {"X-Cookie":"token=" + token}
filename = 'ssh_status.csv'
results = []
url = 'https://CHANGEME:8834'
count = 1

def login(username,password):
    data = {"username":username,"password":password}
    r = requests.post(url=url+"/session", data = data, verify=False)
    token = r.text
    print(token)

def get_scan(token):
    
    headers = {"X-Cookie":"token=" + token}
    r = requests.get(url=url+"/scans/"+scan_id,headers=headers,verify=False)
    data = r.json()
    hosts = data.get("hosts")
    for host in hosts:
        hostname = host.get("hostname")
        host_id = str(host.get("host_id"))
        get_plugin_info(token,hostname,host_id,plugin_id,scan_id)

    return

def get_plugin_info(token,hostname,host_id,plugin_id,scan_id):
    global count
    result = []
    r = requests.get(url=url+"/scans/"+scan_id + "/hosts/" + host_id + "/plugins/" + plugin_id,headers=headers,verify=False)
    data = r.json()
    outputs = data.get("outputs")
    for o in outputs:
        ports = o.get("ports")
        for key in ports:
            port = ports.get(key)
            attachments = port[0].get("attachments")
            for attachment in attachments:
                if (attachment.get("name") == 'ssh_get_info.log'):
                    attachment_id = str(attachment.get("id"))
                    attachment_key = str(attachment.get("key"))
                    result.append(hostname)
                    status = get_attachment(scan_id,attachment_id,attachment_key)
                    result.append(status)
                    print(count)
                    print(hostname + "," + status)
        count = count + 1
        results.append(result)
    return results
    

def get_attachment(scan_id,attachment_id,attachment_key):
    r = requests.get(url=url+"/scans/"+scan_id + "/attachments/" + attachment_id + "?key=" + attachment_key,headers=headers,verify=False)
    data = r.text
    if "Failed to authenticate" in data:
        return "failed to authenticate"
    elif "Failed to open a socket" in data:
        return "System did not respond"
    elif "Authentication success" in data:
        return "Authentication was successful"
    else:
        return (data)

def writeCSV(data,filename):
    header = ['hostname','status']
    

    with open(filename, 'a') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for row in data:
            writer.writerow(row) 
              
if __name__ == '__main__':
    #login(username,password)
    get_scan(token)
    writeCSV(results,filename)
