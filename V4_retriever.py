import os
import csv
import requests
import socket
import time
from pyhunter import PyHunter
import json

# you will need an API key for hunter.io (Free)
_hunting_api = 'fe98dad379493a7198f54984e92af9df86721f25'

# You will need an API key for have I Been Pwned (Not Free, as of now. But they are planning to go open source)
_hibp_key = '4d17b82954d24c1e874e6997d3ed3b28'

# Get a free signal API key, its free (get an API key at: https://auth0.com/signals/ip)
_signals_key = "f0293f3c-4b9f-4427-a940-62b7efcffab5"



def usage2():
    print("________________________________________________________")
    print("| You seem to have entered something other than '1' or |")
    print("| or '2'. By entering '1' you will be prompted with an |")
    print("| input section for the domain you want to search. If  |")
    print("| you enter '2' then you will need to prompted to enter|")
    print("| the path to the .txt file containing the list of     |")
    print("| domains to be searched. Sooooooo try again and do it |")
    print("| right this time.                                     |")
    print("|                                                      |")
    print("|______________________________________________________|\n")
    _response = input("Would you like to try again [Y/N]: ")
    if _response == 'yes' or 'Yes' or 'YES' or 'Y' or 'y':
        _main_()
    else:
        print("\n\nHave a nice day!")
        exit()



def hunt_emails(domain):
    # Your hunter API key will end up here
    hunter = PyHunter(_hunting_api)
    # Initialize the domain search and the emails found online
    test = hunter.domain_search(domain)
    # Use the following for loop to figure out the keys for the dictionary
    for key in test:
        # print(key, '->', test[key])
        pass
    # this can shows the pattern the emails are created with ##
    # print('Pattern',' -> ', test['pattern'])
    # this pulls out the inner dictionary and shows all the values for an email
    emails = []
    emails_ = test['emails']
    for xdict in emails_:
        # temp_conf = xdict['confidence']
        temp_email = xdict['value']
        temp_conf_email = [temp_email]
        emails.append(temp_conf_email)
    return emails



# Run emails against known breaches
def check_breach(eml):
    headers = {}
    headers['content-type'] = 'application/json'
    headers['api-version'] = '3'
    headers['User-Agent'] = 'the-monkey-playground-script'
    # Your HIBP key will go here
    headers['hibp-api-key'] = _hibp_key

    url = 'https://haveibeenpwned.com/api/v3/breachedaccount/'+eml+'?truncateResponse=false'
    r = requests.get(url, headers=headers)
    _split = eml.split('@')
    file_end = _split[1][:-4]
    file_end = file_end + '_emails'

    if r.status_code == 404:
        pass
    elif r.status_code == 200:
        data = r.json()
        #print('Breach Check for: %s'%eml)
        for d in data:
            #   Simple info
            breach = d['Name']
            domain = d['Domain']
            breachDate = d['BreachDate']
            sensitive = d['IsSensitive']

            # Write the pwned emails to a CSV
            temp_info = [eml, breach, sensitive, domain, breachDate]
            breach_info = "data/final/emails/%s" % file_end +'.csv'
            if os.path.isfile(breach_info):
                with open(breach_info, 'a') as f:
                    f.write(str(temp_info))
                    f.write('\n')
            else:
                # have to create the file if it doesnt exist
                with open(breach_info, 'w') as f:
                    f.write(str(temp_info))
                    f.write('\n')
    else:
        data = r.json()
        print('Error: <%s>  %s'%(str(r.status_code),data['message']))
        exit()



def hibp_emails():
    # show_banner()
    print("[+] Checking if emails have been pwned!! [+]\n")
    # clear the temp file
    breach_info = "temp_emails.txt"
    blank = ''
    with open(breach_info, 'w') as f:
        f.write(blank)

    headers = {}
    headers['content-type'] = 'application/json'
    headers['api-version'] = '3'
    headers['User-Agent'] = 'the-monkey-playground-script'
    #   Place your HIBP API key below
    headers['hibp-api-key'] = '4d17b82954d24c1e874e6997d3ed3b28'

    # Pete, you set these next three variables so the .py automatically looks for the
    # temp email file
    chkType = 'file'
    hibpCheck='breachaccount'
    chkIt = 'temp_emails'

    if headers['hibp-api-key']=='https://haveibeenpwned.com/API/Key':
        print("ERROR: Setup still required.\nPlease register an API key to start using this script.\nRegister @ %s"
              % headers['hibp-api-key'])
        exit()

    if not os.path.isfile(chkIt):
        print('\n\nWe can\'t find/open %s.  Please check that it\'s a valid file.\n\n'%chkIt)
    elif chkType == 'file':
        get_emails = open(chkIt, 'r')
        for line in get_emails:
            cleanEmail = line.strip()
            if hibpCheck == 'breachaccount':
                check_breach(cleanEmail)
                time.sleep(2)
            else:
                check_paste(cleanEmail)
                time.sleep(2)
        get_emails.close()
    # Something really interesting happened
    else:
        print('We in trouble.  We should not be here.')



def DNSTwist(domain_input):
    domain1 = domain_input
    domain2 = domain_input[:-4]

    # Get emails to run thru HIBP
    print("\n[+] Find emails associated with %s [+]\n" % domain1)
    emails = hunt_emails(domain1)

    temp_emails = 'temp_emails'
    with open(temp_emails, 'w') as out_file:
        for sublist in emails:
            # print(sublist)
            out_file.write(sublist[0])
            out_file.write('\n')

    # check if emails have been pwned
    hibp_emails()

    # Using '--registered' will only show domain variations that have been registered
    print("[+] looking for registered domains spoofing %s ... [+]\n" % domain1)
    os.system('cmd /c "dnstwist --registered --format csv %s > data/temp/temp_registered.csv"'% (domain1))

    print("[+] Running --ssdeep scan... [+]\n")
    print("_______________________________________")
    print("| ssdeep is grabbing hashed values of  |")
    print("| the registered domains to see if any |")
    print("| sites are posing as phishing sites...|")
    print("| some of the domains are purchased by |")
    print("| the company in question to redirect  |")
    print("| to their site, showing 100% match, so|")
    print("| so the results need to be manually   |")
    print("| explored.                            |")
    print("----------------------------------------")

    # Run the same OG domain through --ssdeep
    os.system('cmd /c "dnstwist --ssdeep --format csv %s > data/temp/temp_ssdeepfile.csv"' % (domain1))

    # store the info hear until ready to write to final csv
    spoof_domain_hash_type = [["IP", "Domain", "Percent Match", "Type", "score", "blacklist_last_7_days",
                               "blacklist_last_year"]]

    print("[+] Combining the results and finding IPs [+]\n")
    print("\n[+] Check if domain has IP associated [+]")
    print("___________________________________________")
    print("| IP is not something provided from       |")
    print("| DNStwist, and therefore has to be       |")
    print("| individually searched to find.          |")
    print("-------------------------------------------")
    # read back the legit domains and compare the hashes
    # The goal here is to find the domains that are live and a permutation of target
    _registered_domains = 'data/temp/' 'temp_registered.csv'
    _ssdeepfile_temp = 'data/temp/' + 'temp_ssdeepfile.csv'
    with open(_registered_domains, newline='') as csv_file:
        csv_reader = csv.reader(csv_file)
        for row in csv_reader:

            # open the ssdeep temp file and compare domains to find registered and similar
            with open(_ssdeepfile_temp, newline='') as csv_file:
                csv_reader2 = csv.reader(csv_file)
                x = 0
                for ssdeep_row in csv_reader2:
                    # compare rows to temp_ssdeep to find hash value comparisons
                    if row[1] == ssdeep_row[1]:
                        # This is to avoid the OG domain from being checked
                        if x != 0:
                            try:
                                # Check to see if sites are reachable
                                ip = socket.gethostbyname(ssdeep_row[1])

                                #ip_domain_hash = [ip, ssdeep_row[1], ssdeep_row[9], ssdeep_row[0]]

                                # Check if IP has been blacklisted (auth API)
                                os.system('cmd /c "curl https://signals.api.auth0.com/v2.0/ip/%s '
                                                 '-H x-auth-token:%s > temp_ip_info.txt"' % (ip, _signals_key))

                                _score = ''
                                _7days = ''
                                _1year = ''
                                ip_info = []
                                with open("temp_ip_info.txt", "r") as f:
                                    for line in f:
                                        ip_info.append(line)

                                for d in ip_info:
                                    test_string = d
                                    res = json.loads(test_string)

                                    _score = res['fullip']['score']
                                    _7days = res['fullip']['history']['score_7days']
                                    _1year = res['fullip']['history']['score_1year']
                                    #print(res['fullip']['score'])
                                    #print(res['fullip']['history']['score_7days'])
                                    #print(res['fullip']['history']['score_1year'])


                                ip_domain_hash = [ip, ssdeep_row[1], ssdeep_row[9], ssdeep_row[0], _score, _7days,_1year]


                                spoof_domain_hash_type.append(ip_domain_hash)

                            except:
                                # When there is no reachable IP
                                domain_hash = ['N/A', ssdeep_row[1], ssdeep_row[9], ssdeep_row[0]]
                                spoof_domain_hash_type.append(domain_hash)
                    x += 1


    # Save IP, domain, hash, type to Final file
    _final_file = 'data/final/domain-info/' + str(domain2) + "_final.csv"
    with open(_final_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(spoof_domain_hash_type)

    print("\n[+] Finished! May take a moment to appear in data/final/%s [+]" % domain2)



def _main_():
    # Created needed directories
    _cwd = os.getcwd()
    try:
        os.chdir('data/')
        os.chdir(_cwd)
    except:
        directory = 'data/'
        os.mkdir(directory)

    try:
        os.chdir('data/final/')
        os.chdir(_cwd)
    except:
        directory = 'data/final/'
        os.mkdir(directory)

    try:
        os.chdir('data/final/domain-info/')
        os.chdir(_cwd)
    except:
        directory = 'data/final/domain-info/'
        os.mkdir(directory)

    try:
        os.chdir('data/final/emails/')
        os.chdir(_cwd)
    except:
        directory = 'data/final/emails/'
        os.mkdir(directory)

    try:
        os.chdir('data/temp/')
        os.chdir(_cwd)
        print("It", os.getcwd())
    except:
        directory = 'data/temp/'
        os.mkdir(directory)

    # determine what user wants
    fileOrNot = input("Enter '1' or '2'\nSingle domain search......(1) \nlist of domain's in .txt..(2)\nChoice =  ")

    if fileOrNot == '1':
        domain_name = input("Domain Name: ")
        DNSTwist(domain_name)

    elif fileOrNot == '2':
        file_name = input("path to file: ")
        try:
            print(file_name)
            with open(file_name, newline='\n') as csv_file:
                csv_reader = csv.reader(csv_file)
                for domain_name in csv_reader:
                    for dm in domain_name:
                        print("Doing the stuff to %s" % dm)
                        print(dm)
                        DNSTwist(dm)
        except:
            print("\n\nit appears the file doesn't exist ... try again.\n\n")
            _main_()

    elif fileOrNot == '3':
        exit()

    else:
        usage2()

_main_()
