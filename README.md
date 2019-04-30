# Traft - Ethical Hacking Automation Tool

Traft is an automated vulnerability detection tool which will scan the given target IP or subnet for hosts, search the hosts for running services and version numbers, and then query the CVE database to locate all known vulnerabilites associated with that service.  The user will then be able to determine the severity and necessity of upgrading their service to a patched version.


## Running traft:
1. Using python3     <br />
2. pip3 install -r requirements.txt     <br />
3. python3 main.py -t $TARGET_IP       # to scan a single address ex. 10.0.0.2       <br />
4. python3 main.py -s $TARGET_SUBNET   # to scan an address block ex. 10.0.0.2/24     <br />

