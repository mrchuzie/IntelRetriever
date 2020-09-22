# IntelRetriever
This is a python script that uses DNStwist and HIBP to find possible malicious domain names trying to emulate the original domain. It also looks for any emails associated with the domain and checks them with the HIBP database.


THe following need to be installed:
- pip install dnstwist
- pip install requests
- pip install pyhunter
- pip install os-sys
- pip install dnspython
- pip install DNSPython
- pip install ssdeep**
- pip install Requests


GeoIP>=1.3.2
dnspython>=1.14.0
requests>=2.20.0
#ssdeep>=3.1
ppdeep>=20200505
whois>=0.7
tld>=0.9.1

**Debian/Ubuntu/Kali Linux**

If running Debian-based distribution, you can install all external libraries
with just single command for DNSTwist:

```
$ sudo apt install python3-dnspython python3-tld python3-geoip python3-whois \
python3-requests python3-ssdeep
