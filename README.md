# Traft - Ethical Hacking Automation Tool

Traft is an automated vulnerability detection tool which will scan the given target IP or subnet for hosts, search the hosts for running services and version numbers, and then query the CVE database to locate all known vulnerabilites associated with that service.  The user will then be able to determine the severity and necessity of upgrading their service to a patched version.

<br>

## Installation and Dependencies
1. metasploit framework and postgresql are required (already included with kali linux) 
    1. <code> (https://metasploit.help.rapid7.com/v1/docs/installing-the-metasploit-framework) </code>
    2. <code> (https://www.postgresql.org/docs/11/tutorial-install.html) </code>
    3. run <code> ./msfconsole </code> to complete metasploit initial setup </code>
4. <code> pip3 install -r requirements.txt </code>
5. <code> systemctl start postgresql </code>
6. <code> msfdb init </code>
7. <code> msfconsole </code>
8. *msf >* <code> db_rebuild_cache </code>

<br>


## Running traft:
1. open a terminal and run the following 3 commands:
    1. <code> msfconsole </code>
    2. *msf >* <code> load msgrpc [Pass=password] </code>
    3. *msf >* <code> msfrpcd -P password -S </code>
2. open a new terminal window
3. To scan a single IP address, ex. 10.0.2.4:
    1. <code> python3 traft.py -t <TARGET_IP> </code>
4. To scan an IP address block, ex. 10.0.2.0/24:
    1. <code> python3 traft.py -s <TARGET_SUBNET> </code>
    
<br>

![Traft Setup Video](https://github.com/somi3k/traft/blob/master/target.gif)
