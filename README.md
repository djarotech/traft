# Traft - Ethical Hacking Automation Tool

Traft is an automated vulnerability detection tool which will scan the given target IP or subnet for hosts, search the hosts for running services and version numbers, and then query the CVE database to locate all known vulnerabilites associated with that service.  The user will then be able to determine the severity and necessity of upgrading their service to a patched version.


## Installation (kali linux recommended as pre-requisite)
1. Install nmap if not already installed 
        - sudo apt-get install nmap
2. Clone vulscandb into /usr/share/nmap/scripts/vulscan/
        - cd /usr/share/nmap/scripts
        - git clone https://github.com/scipag/vulscan scipag_vulscan
3. Clone nmap-vulners into /usr/share/nmap/scripts/nmap-vulners/
        - cd /usr/share/nmap/scripts
        - git clone https://github.com/vulnersCom/nmap-vulners.git

## Running traft:
1. Using python3
2. pip3 install -r requirements.txt
3. python3 main.py -t $TARGET_IP       # to scan a single address ex. 10.0.0.2
4. python3 main.py -s $TARGET_SUBNET   # to scan an address block ex. 10.0.0.2/24

