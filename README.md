# Traft - Ethical Hacking Automation Tool

Traft is an automated vulnerability detection tool which will scan the given target IP or subnet for hosts, search the hosts for running services and version numbers, and then query the CVE database to locate all known vulnerabilites associated with that service.  The user will then be able to determine the severity and necessity of upgrading their service to a patched version.


## Installation and Dependencies
1. metasploit framework is required (already included with kali linux) 
    <code> [metasploit](https://metasploit.help.rapid7.com/v1/docs/installing-the-metasploit-framework) </code>
2. run ./msfconsole to complete metasploit setup
3. postgresql will greatly increase the speed of searches (already included with kali linux)
    <code> [postgres][(https://www.postgresql.org/docs/11/tutorial-install.html) </code>
4. <code> pip3 install -r requirements.txt    
5. <code> msfdb init </code>
6. <code> msfconsole </code>
7. msf>> <code> db_rebuild_cache </code>

![Traft Setup Video](https://github.com/somi3k/traft/blob/master/setup.gif)


## Running traft:
1. open a terminal and run the following 3 commands:
    1. <code> msfconsole </code>
    2. msf> <code> load msgrpc [Pass=password] </code>
    3. msf> <code> msfrpcd -P password -S </code>
2. open a new terminal window
3. To scan a single IP address, ex. 10.0.2.4:
    <code> python3 main.py -t <TARGET_IP> </code>
4. To scan an IP address block, ex. 10.0.2.0/24:
    <code> python3 main.py -s <TARGET SUBNET> </code>
        

![Traft Setup Video](https://github.com/somi3k/traft/blob/master/target.gif)
