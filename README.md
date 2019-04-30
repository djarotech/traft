# Traft - Ethical Hacking Automation Tool

Traft is an automated vulnerability detection tool which will scan the given target IP or subnet for hosts, search the hosts for running services and version numbers, and then query the CVE database to locate all known vulnerabilites associated with that service.  The user will then be able to determine the severity and necessity of upgrading their service to a patched version.


## Installation (assuming installation is on kali linux base)
1. Install nmap if not already installed    <br />
        - sudo apt-get install nmap        <br />
2. Clone vulscandb into /usr/share/nmap/scripts/vulscan/    <br />
        - cd /usr/share/nmap/scripts     <br />
        - git clone https[]()://github.com/scipag/vulscan scipag_vulscan   <br />
3. Copy vulners.nse to /usr/share/nmap/scripts/nmap-vulners/vulners.nse   <br />
        - mkdir -p /usr/share/nmap/scripts/nmap-vulners    <br />
        - cp vulners.nse /usr/share/nmap/scripts/nmap-vuners/vulners.nse    <br />

## Running traft:
1. Using python3     <br />
2. pip3 install -r requirements.txt     <br />
3. python3 main.py -t $TARGET_IP       # to scan a single address ex. 10.0.0.2       <br />
4. python3 main.py -s $TARGET_SUBNET   # to scan an address block ex. 10.0.0.2/24     <br />

