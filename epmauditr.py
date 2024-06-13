#!/usr/bin/python3
# author: Tengku Zahasman

import sys
import json
import requests
import os.path
import getpass
from datetime import date
import urllib3
urllib3.disable_warnings()

class bcolors:
    RED = '\033[31m'
    ORANGE = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    LIGHT_GRAY = '\033[37m'
    GRAY = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    WHITE = '\033[97m'
    GREEN = '\033[92m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Constants
DISPATCHER_URL = 'https://XXXX.epm.cyberark.com'
MANAGER_URL = 'https://XXXX.epm.cyberark.com'
LOLBAS_URL = 'https://lolbas-project.github.io'
GTFOBINS_URL = 'https://gtfobins.github.io'
VALIDATE_SSL = False # set to True if local certificate store is correctly configured

plus = f"{bcolors.GREEN}+{bcolors.ENDC}"
high = f"{bcolors.RED}HIGH{bcolors.ENDC}"
medium = f"{bcolors.ORANGE}MEDIUM{bcolors.ENDC}"
low = f"{bcolors.YELLOW}LOW{bcolors.ENDC}"
info = f"{bcolors.GRAY}INFO{bcolors.ENDC}"

policyAction = {1:"Allow",2:"Block",3:"Elevate",4:"Elevate if necessary"}

# load lolbas
if not os.path.isfile('./lolbas.json'):
    print('lolbas repo not found. Downloading ...')
    open('lolbas.json', 'wb').write(requests.get(LOLBAS_URL+"/api/lolbas.json", verify=VALIDATE_SSL).content)
    print('lolbas repo saved at ./lolbas.json')
lolbas_file = open('lolbas.json')
lolbas_data = json.load(lolbas_file)
lolbas = []

for i in lolbas_data:
    lolbas.append(i['Name'].lower())
lolbas_file.close()

# load gtfobins
if not os.path.isfile('./gtfobins.json'):
    print('gtfobins repo not found. Downloading ...')
    open('gtfobins.json', 'wb').write(requests.get(GTFOBINS_URL+"/gtfobins.json", verify=VALIDATE_SSL).content)
    print('gtfobins repo saved at ./gtfobins.json')
gtfobins_file = open('gtfobins.json')
gtfobins = json.load(gtfobins_file)
gtfobins_file.close()

# audit policies from file
def audit_file(data):

    for policy in data['Policies']:
        
        computers = ""
        if policy['IsAppliedToAllComputers']:
            computers = "All"
        else:
            for computer in policy['Executors']:
                computers = computers + computer['Name'] + " "
                
        print(f"{bcolors.YELLOW}----------------------------")
        print('Policy: '+policy['Name'])
        print('Policy action: '+policyAction[policy['Action']])
        print('Applies to: '+computers)
        print('Active: '+str(policy['IsActive']))
        print(f"----------------------------{bcolors.ENDC}")
        #print(policy)
        if policy['Action'] == 3 or policy['Action'] == 4:
            for apps in policy['Applications']:
                audit_elevation_policy(apps)
        elif policy['Action'] == 2:
            for apps in policy['Applications']:
                audit_block_policy(apps)
        elif policy['Action'] == 1:
            for apps in appgroup['Applications']:
                audit_allow_policy(apps)
        
    for appgroup in data['AppGroups']:
        print(f"{bcolors.YELLOW}----------------------------")
        print('==> Application Group: '+appgroup['Name'])
        print(f"----------------------------{bcolors.ENDC}")
        #print(policy)
        if policy['Action'] == 3 or policy['Action'] == 4:
            for apps in appgroup['Applications']:
                audit_elevation_policy(apps)
        elif policy['Action'] == 2:
            for apps in appgroup['Applications']:
                audit_block_policy(apps)
        elif policy['Action'] == 1:
            for apps in appgroup['Applications']:
                audit_allow_policy(apps)

                        

# audit policies from api
def audit_api(authToken, setId, data):

    policy = data['Policy']
    banner = 1
    
    computers = ""
    if policy['IsAppliedToAllComputers']:
        computers = "All"
    else:
        for computer in policy['Executors']:
            computers = computers + computer['Name'] + " "   
    
    for apps in policy['Applications']:
    
        if banner == 1:
            print(f"{bcolors.YELLOW}----------------------------")
            print('Policy: '+policy['Name'])
            print('Policy action: '+policyAction[policy['Action']])
            print('Applies to: '+computers)
            print('Active: '+str(policy['IsActive']))
            print(f"----------------------------{bcolors.ENDC}")
            banner = 0
        if policy['Action'] == 3 or policy['Action'] == 4:
            audit_elevation_policy(apps)
        elif policy['Action'] == 2:
            audit_block_policy(apps)
        elif policy['Action'] == 1:
            audit_allow_policy(apps)
            
        if apps['applicationType'] == 2:        
            appgroup = getAppGroupDetails(authToken, setId, apps['id'])
            print(f"{bcolors.YELLOW}----------------------------")
            print('==> Application Group: '+appgroup['Policy']['Name'])
            print(f"----------------------------{bcolors.ENDC}")
            for apps in appgroup['Policy']['Applications']:                
                if policy['Action'] == 3 or policy['Action'] == 4:
                    audit_elevation_policy(apps)
                elif policy['Action'] == 2:
                    audit_block_policy(apps)
                elif policy['Action'] == 1:
                    audit_allow_policy(apps)  
    
    print("\nWhat would you like to do?")
    print("1. Check another policy in the same set")
    print("2. Choose another set")
    print("3. Exit")
    choice = int(input("Choice>> "))
    if choice == 1:
        policyid = choosePolicy(authToken, setId)
        policy = getPolicyDetails(authToken, setId, policyid)
        audit_api(authToken, setId, policy)
    elif choice == 2:
        epmsetid = chooseEPMSet(authToken)
        policyid = choosePolicy(authToken, epmsetid)
        policy = getPolicyDetails(authToken, epmsetid, policyid)
        audit_api(authToken, epmsetid, policy)
    else:
        exit("Goodbye!")
                        
# audit elevation policy
def audit_elevation_policy(j):
    
    if (j['applicationType'] == 3 or j['applicationType'] == 5 or j['applicationType'] == 15 or j['applicationType'] == 21 or j['applicationType'] == 22 or j['applicationType'] == 28):
        appname = ""
        arguments = ""
        command = ""
        location = ""
        publisher = ""
        linux = 0
        issues = []
        
        # check if linux
        if 'LinuxChildProcess' in j:
            linux = 1
        else:
            linux = 0
        
        # determine filename if available
        for key, value in j['patterns'].items():
            if key == 'ORIGINAL_FILE_NAME':
                for a, b in value.items():
                    if a == 'content' and b != '' and appname == '':
                        appname = b
            if key == 'FILE_NAME':
                for a, b in value.items():
                    if a == 'content' and b != '':
                        appname = b
            if key == 'ARGUMENTS':
                for a, b in value.items():
                    if a == 'content' and b != '':                            
                        arguments = b
        if arguments != "" and appname != "":
            command = appname+" "+arguments
        elif appname == "":
            appname = j['id']
        
        # detect command shells
        if issue := check_commandshells(appname):
            issues.append(issue)
        
        # check child process
        if 'childProcess' in j and (j['applicationType'] != 5 and "setup" not in appname.lower() and "install" not in appname.lower()) and (issue := check_childprocess(j['childProcess'])):
            issues.append(issue)
        
        # check Linux child command
        if 'LinuxChildProcess' in j and (issue := check_childprocess(j['LinuxChildProcess'])):
            issues.append(issue)
        
        # check elevation for open save dialog
        if 'restrictOpenSaveFileDialog' in j and (issue := check_opensavedialog(j['restrictOpenSaveFileDialog'])) and j['applicationType'] == 3: 
            issues.append(issue)
        
        # check if password required to run sudo commands
        if 'linuxSudoNoPassword' in j and (issue := check_linuxsudonopassword(j['linuxSudoNoPassword'])): 
            issues.append(issue)
        
        # check if file is a known lolbas
        if linux == 0 and (issue := check_lolbas(appname)):
            issues.append(issue)
        
        # check if file is a known gtfobins
        if linux == 1 and (issue := check_gtfobins(appname)):
            issues.append(issue)
        
        # check if temporary installation files are protected
        if 'protectInstalledFiles' in j and (j['applicationType'] == 3 and (".msi" in appname.lower() or "setup" in appname.lower() or "install" in appname.lower())) and (issue := check_protectinstalledfiles(j['protectInstalledFiles'])) and linux == 0: 
            issues.append(issue)
        
        # check number of patterns
        if 'patterns' in j and (issue := check_pattern_numbers(j['patterns'], False)): 
            issues.append(issue)
            
        for key, value in j['patterns'].items():
            if key == 'LOCATION':
                for a, b in value.items():
                    if a == 'content' and b != '':
                        location = b
                        if issue := check_file_location_wildcard(location): # check if file location contains wildcard
                            issues.append(issue)
                        if (issue := check_file_location_writable(location)) and linux == 0: # check if file is potentially in writable path
                            issues.append(issue)
                    if a == 'withSubfolders':
                        if (issue := check_file_withsubfolders(b,location)) and location != '': # check with subfolders
                            issues.append(issue)
            if key == 'PUBLISHER':
                for a, b in value.items():
                    if a == 'content' and b != '':
                        publisher = b                            
        
        # check wildcard in filename
        if issue := check_filename_wildcard(appname):
            issues.append(issue)
        
        # check if description is set
        if 'description' in j and (issue := check_description(j['description'])): 
            issues.append(issue)
        
        # check if publisher set
        if (issue := check_publisher(publisher)) and linux == 0: 
            issues.append(issue)
        
        # check if location set
        if issue := check_location(location, False): 
            issues.append(issue)
        
        # check if both location and publisher is not set
        if (linux == 0 and (issue := check_loc_pub(publisher, location))):
            issues.append(issue)
                            
        # print results if there are issues
        if len(issues) > 0:
            if command != "":
                results(command, issues)
            else:
                results(appname, issues)

#audit block policy
def audit_block_policy(j):
    if (j['applicationType'] == 3 or j['applicationType'] == 5 or j['applicationType'] == 15 or j['applicationType'] == 21 or j['applicationType'] == 22 or j['applicationType'] == 28):
        appname = ""
        arguments = ""
        command = ""
        location = ""
        publisher = ""
        runas = ""
        linux = 0
        issues = []
        
        # check if linux
        if 'LinuxChildProcess' in j:
            linux = 1
        else:
            linux = 0
        
        # determine filename, arguments and runas user if available
        for key, value in j['patterns'].items():
            if key == 'ORIGINAL_FILE_NAME':
                for a, b in value.items():
                    if a == 'content' and b != '' and appname == '':
                        appname = b
            if key == 'FILE_NAME':
                for a, b in value.items():
                    if a == 'content' and b != '':
                        appname = b
            if key == 'ARGUMENTS':
                for a, b in value.items():
                    if a == 'content' and b != '':                            
                        arguments = b
            if key == 'LINUX_RUN_AS_USER':
                for a, b in value.items():
                    if a == 'users' and b != '':                            
                        runas = b
        if arguments != "" and appname != "":
            command = appname+" "+arguments
        elif appname == "":
            appname = j['id']
        
        # determine location if set
        for key, value in j['patterns'].items():
            if key == 'LOCATION':
                for a, b in value.items():
                    if a == 'content' and b != '':
                        location = b
        
        # check if location set
        if runas != ['root'] and (issue := check_location(location, True)):
            issues.append(issue)
            
        # check if description is set
        if 'description' in j and (issue := check_description(j['description'])): 
            issues.append(issue)
        
        # check number of patterns if more than 3
        if 'patterns' in j and (issue := check_pattern_numbers(j['patterns'], True)): 
            issues.append(issue)
        
        # print results if there are issues
        if len(issues) > 0:
            if command != "":
                results(command, issues)
            else:
                results(appname, issues)

#audit allow policy
def audit_allow_policy(j):

    appname = ""
    arguments = ""
    command = ""
    location = ""
    publisher = ""
    runas = ""
    linux = 0
    issues = []
    
    if (j['applicationType'] == 3 or j['applicationType'] == 4 or j['applicationType'] == 5 or j['applicationType'] == 15 or j['applicationType'] == 21 or j['applicationType'] == 22 or j['applicationType'] == 28):
            appname = ""
            arguments = ""
            command = ""
            issues = []
            
            # determine filename, arguments and runas user if available
            for key, value in j['patterns'].items():
                if key == 'ORIGINAL_FILE_NAME':
                    for a, b in value.items():
                        if a == 'content' and b != '' and appname == '':
                            appname = b
                if key == 'FILE_NAME':
                    for a, b in value.items():
                        if a == 'content' and b != '':
                            appname = b
                if key == 'ARGUMENTS':
                    for a, b in value.items():
                        if a == 'content' and b != '':                            
                            arguments = b
            if arguments != "" and appname != "":
                command = appname+" "+arguments
            elif appname == "":
                appname = j['id']

            # check if description is set
            if 'description' in j and (issue := check_description(j['description'])): 
                issues.append(issue)

            # print results if there are issues
            if len(issues) > 0:
                if command != "":
                    results(command, issues)
                else:
                    results(appname, issues)

# retrieve admin audit log by date
def audit_adminlogs(authToken, dateFrom):
    url = MANAGER_URL + "/EPM/API/Account/AdminAudit?limit=500&DateFrom=" + dateFrom
    headers = {'Authorization': 'basic '+authToken, 'Content-type': 'application/json'}
    r = requests.get(url=url, headers=headers, verify=VALIDATE_SSL)
    print(f"{bcolors.BOLD}\nShowing admin audit logs from:{bcolors.ENDC} " + dateFrom + "\n")
    for i in r.json()['AdminAudits']:
        print(f'{bcolors.YELLOW}'+i['Administrator'] + f"{bcolors.ENDC} | " + i['Description'] + " | " + i['EventTime'])

def audit_setadminlogs(authToken, setId, dateFrom):
    url = MANAGER_URL + "/EPM/API/Sets/"+ setId +"/AdminAudit?limit=500&DateFrom=" + dateFrom
    headers = {'Authorization': 'basic '+authToken, 'Content-type': 'application/json'}
    r = requests.get(url=url, headers=headers, verify=VALIDATE_SSL)
    print(f"{bcolors.BOLD}\nShowing set admin audit logs from:{bcolors.ENDC} " + dateFrom + "\n")
    for i in r.json()['AdminAudits']:
        alert = ''
        if 'Generated token' in i['Description'] and ('for all computers' in i['Description'] or 'valid till 31/12/9999' in i['Description']):
            alert = f'{bcolors.RED}[WARNING]{bcolors.ENDC} '
        print(f'{bcolors.YELLOW}'+i['Administrator'] + f"{bcolors.ENDC} | " + alert + i['Description'] + " | " + i['EventTime'])
    
    epmsetid = chooseEPMSet(authToken)
    print("\nPlease enter date for the log to be retrieved from: ")
    newDateFrom = input('Date (eg: ' +str(date.today())+'): ')
    if not newDateFrom:
        newDateFrom = str(date.today())    
    audit_setadminlogs(authToken, epmsetid, newDateFrom)


# audit rules #

# check that minimum patterns are at least 3
def check_pattern_numbers(patterns, block):
    # count patterns with values
    count = 0
    for key, value in patterns.items():
        for a, b in value.items():
            if a == 'isEmpty' and b == False:
                count = count+1
    #if len(patterns) < 3:
    if count < 3 and not block:
        return {"p":2,"i":f'[{plus}] [{medium}] Less than 3 property definitions specified'}
    elif count > 3 and block:
        return {"p":2,"i":f'[{plus}] [{medium}] More than 3 property definitions specified'}
        

# check if description is empty
def check_description(description):
    if not description:
        return {"p":3,"i":f'[{plus}] [{low}] Policy description is missing'}

# check child process
def check_childprocess(value):
    if value:
        return {"p":1,"i":f'[{plus}] [{high}] Child process is allowed to elevate'}

# detect command shells
def check_commandshells(value):
    value = value.lower()
    if value == "cmd.exe" or value == "powershell.exe" or value == "powershell_ise.exe" or value == "pwsh.exe" or value == "windowsterminal.exe" or value == "wt.exe" or value == "bash" or value == "sh" or value == "zsh":
        return {"p":1,"i":f'[{plus}] [{high}] Command shell is elevated'}

# check elevation for open save dialog
def check_opensavedialog(value):
    if not value:
        return {"p":1,"i":f'[{plus}] [{high}] Open Save Dialog is allowed to elevate'}

# check if publisher not specified AND location either not specified or writable
def check_loc_pub(publisher, location):
    if publisher == "" and location == "":
        return {"p":1,"i":f'[{plus}] [{high}] Both Publisher AND Location not specified'}
    elif publisher == "" and check_file_location_writable(location):
        return {"p":1,"i":f'[{plus}] [{high}] Publisher not specified AND Location is user writable'}

# check if file is a known lolbas
def check_lolbas(filename):
    result = False
    if "|" in filename:        
        for i in filename.split("|"):
            if i.lower() in lolbas:
                result = True
    if filename.lower() in lolbas:
        result = True
    
    if result:    
        return {"p":1,"i":f'[{plus}] [{high}] File is a known LOLBAS: '+filename}

# check if file is a known gtfobins
def check_gtfobins(filename):
    result = False
    if "|" in filename:        
        for i in filename.split("|"):
            if i in gtfobins:
                result = True
    if filename in gtfobins:
        result = True
    
    if result:
        return {"p":1,"i":f'[{plus}] [{high}] File is a known GTFOBin: '+filename}
        
# check if filepath contains wildcard
def check_file_location_wildcard(filepath):
    if "*" in filepath:
        return {"p":2,"i":f'[{plus}] [{medium}] File path contains wildcard: '+filepath}

# check if is potentially in writable location
def check_file_location_writable(filepath):
    if not ("c:\windows" in filepath.lower() or "c:\program files" in filepath.lower() or "%systemroot%" in filepath.lower() or "%windir%" in filepath.lower() or "%programfiles%" in filepath.lower() or "%programfiles(x86)%" in filepath.lower()):
        return {"p":2,"i":f'[{plus}] [{medium}] File potentially in user writable path: '+filepath}
        
# check if file location include subfolders
def check_file_withsubfolders(value, filepath):
    if value:
        return {"p":2,"i":f'[{plus}] [{medium}] File location include subfolders: '+filepath+'\*'}

# check if temporary installation files are protected
def check_protectinstalledfiles(value):
    if not value:
        return {"p":2,"i":f'[{plus}] [{medium}] Temporary installation files are not protected'}

# check if temporary installation files are protected
def check_linuxsudonopassword(value):
    if value:
        return {"p":1,"i":f'[{plus}] [{high}] Sudo command does not require password'}

# check if filename contains wildcard
def check_filename_wildcard(filename):
    if "*" in filename:
        return {"p":3,"i":f'[{plus}] [{low}] Filename contains wildcard: '+filename}
        
# check if publisher is set
def check_publisher(publisher):
    if not publisher or publisher == '':
        return {"p":4,"i":f'[{plus}] [{info}] Publisher not specified'}

# check if location is specified
def check_location(location, block):
    if (not location or location == '') and not block:
        return {"p":4,"i":f'[{plus}] [{info}] Location not specified'}
    elif (location or location != '') and block:
        return {"p":1,"i":f'[{plus}] [{high}] Location specified for blocked command: '+location}
        
# output results
def results(appname, issues):
    
    print(f"Application: {bcolors.BOLD}"+appname+f"{bcolors.ENDC}")
    
    # sort issues by priority order
    issues = sorted(issues, key=lambda x: x['p'])
    
    for issue in issues:
        print(issue['i'])
    print()

# log into the API and retrieve auth token
def getAuthToken():
    url = DISPATCHER_URL + "/EPM/API/Auth/EPM/Logon"
    json = {'Username': input('Username: '),'Password': getpass.getpass(),'ApplicationID': 'epmauditor'}
    headers = {'Content-type': 'application/json'}
    r = requests.post(url=url, json=json, headers=headers, verify=VALIDATE_SSL)
    token = r.json()
    return token['EPMAuthenticationResult']

# list and choose EPM set to audit
def chooseEPMSet(authToken):
    sets = []
    url = MANAGER_URL + "/EPM/API/Sets"
    headers = {'Authorization': 'basic '+authToken}
    r = requests.get(url=url, headers=headers, verify=VALIDATE_SSL)
    #print(r.content)
    if len(r.json()['Sets']) < 1:
        print("There are no sets available to audit. Exiting...")
        exit("Goodbye!")
    count = 1
    print('\nThese are the available sets:')
    for i in r.json()['Sets']:
        print(f'{count}. ' + i['Name'])
        sets.append(i['Id'])
        count=count+1
    print('\nWhich set would you like to audit?')
    choice = int(input('Choice>> '))
    return sets[choice-1]

# list and choose EPM policy to audit
def choosePolicy(authToken, setId):
    policies = []
    url = MANAGER_URL + "/EPM/API/Sets/"+setId+"/Policies/Server/Search"
    headers = {'Authorization': 'basic '+authToken, 'Content-type': 'application/json'}
    json = {'filter' : 'PolicyType IN ADV_WIN,ADV_MAC,ADV_LINUX'}
    r = requests.post(url=url, json=json, headers=headers, verify=VALIDATE_SSL)
    #print(r.content)
    if len(r.json()['Policies']) < 1:
        print("There are no policies in this set available to audit. Please choose another set.")
        epmsetid = chooseEPMSet(authToken)
        policyid = choosePolicy(authToken, epmsetid)
        policy = getPolicyDetails(authToken, epmsetid, policyid)
        audit_api(authToken, epmsetid, policy)
    count = 1
    print('\nThese are the available policies to audit:')
    for i in r.json()['Policies']:
        if i['IsActive']:
            print(f'{count}. ' + i['PolicyName'])
        else:
            print(f'{bcolors.GRAY}{count}. ' + i['PolicyName'] + f' (disabled){bcolors.ENDC}')
        policies.append(i['PolicyId'])
        count=count+1
    print('\nWhich policy would you like to audit?')
    choice = int(input('Choice>> '))
    return policies[choice-1]

# obtain policy details
def getPolicyDetails(authToken, setId, policyId):
    url = MANAGER_URL + "/EPM/API/Sets/"+setId+"/Policies/Server/"+policyId
    headers = {'Authorization': 'basic '+authToken, 'Content-type': 'application/json'}
    r = requests.get(url=url, headers=headers, verify=VALIDATE_SSL)
    #print(json.dumps(r.json()))    
    return r.json()

# obtain application group details
def getAppGroupDetails(authToken, setId, appGroupId):
    url = MANAGER_URL + "/EPM/API/Sets/"+setId+"/Policies/ApplicationGroups/"+appGroupId 
    headers = {'Authorization': 'basic '+authToken, 'Content-type': 'application/json'}
    r = requests.get(url=url, headers=headers, verify=VALIDATE_SSL)
    return r.json()


        
    

print(f"""{bcolors.CYAN}
  _____ ____  __  __      _             _ _ _        
 | ____|  _ \|  \/  |    / \  _   _  __| (_) |_ _ __ 
 |  _| | |_) | |\/| |   / _ \| | | |/ _` | | __| '__|
 | |___|  __/| |  | |  / ___ \ |_| | (_| | | |_| |   
 |_____|_|   |_|  |_| /_/   \_\__,_|\__,_|_|\__|_| v0.1beta  
                                                     
{bcolors.ENDC}""")

if len(sys.argv) > 1 and sys.argv[1] == "--file":
    print("Auditing policy from file: "+sys.argv[2])
    f = open(sys.argv[2])
    filedata = json.load(f)
    audit_file(filedata)
    f.close()
elif len(sys.argv) > 1 and sys.argv[1] == "--api":
    print("Auditing policy from API: "+MANAGER_URL)
    print("Please enter EPM API credentials.\n")
    authToken = getAuthToken()
    epmsetid = chooseEPMSet(authToken)
    policyid = choosePolicy(authToken, epmsetid)
    policy = getPolicyDetails(authToken, epmsetid, policyid)
    audit_api(authToken, epmsetid, policy)
elif len(sys.argv) > 1 and sys.argv[1] == "--logs":
    print("Retrieving audit logs from API: "+MANAGER_URL)
    print("Please enter EPM API credentials.\n")
    authToken = getAuthToken()
        
    if sys.argv[2] == 'admin':  
        print("\nPlease enter date for the log to be retrieved from: ")
        dateFrom = input('Date (eg: ' +str(date.today())+'): ')
        if not dateFrom:
            dateFrom = str(date.today())        
        audit_adminlogs(authToken, dateFrom)
    elif sys.argv[2] == 'sets':
        epmsetid = chooseEPMSet(authToken)
        print("\nPlease enter date for the log to be retrieved from: ")
        dateFrom = input('Date (eg: ' +str(date.today())+'): ')
        if not dateFrom:
            dateFrom = str(date.today())        
        audit_setadminlogs(authToken, epmsetid, dateFrom)
        
else:
    print("""Usage: 
    ./epmaudit.py --file <filename.epmp>
    ./epmaudit.py --api
    ./epmaudit.py --logs [admin|sets]
    """)



# [ References ]
#
# Application Type
#        2 = "Group"
#        3 = "EXE"
#        4 = "Script"
#        5 = "MSI"
#        6 = "MSU"
#        7 = "WebApp"
#        8 = "WinAdminTask"
#        9 = "ActiveX"
#        13 = "FileSystemNode"
#        14 = "Registry Key"
#        15 = "COM"
#        17 = "WinService"
#        18 = "USB Device"
#        19 = "Optical Disc2"
#        20 = "WinApp"
#        21 = "DLL"
#        22 = "PKG"
#        28 = "Linux command"
#
# CompareAs type        
#        0 = "exact"
#        1 = "prefix"
#        2 = "contains"
#        3 = "wildcards"
#        4 = "regExp"
#
#
# Policy Action Type
#        1 = "Allow"
#        2 = "Block"
#        3 = "Elevate"        
#        4 = "Elevate if necessary"
#        5 = "CollectUAC"
#        6 = "ElevateRequest"
#        9 = "ExecSript"
#        10 = "AgentConfiguration"
#        11 = "SetSecurityPermissions"
#        13 = "DefineUpdater"
#        17 = "Loosely connected devices"
#       18 = "DefineDeveloperTool"
#        20 = "AdHocElevate"
#
# Policy Type
#        1 = "Privilege Management Detect"
#        2 = "Application Control Detect"
#        3 = "Application Control Restrict"
#        11 = "Advanced Windows"
#        12 = "Advanced Linux"
#        13 = "Advanced Mac"
#        18 = "Predefined App Groups Win"
#        20 = "Developer Applications"
