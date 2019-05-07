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

## AWS S3 support - this is where you can send off your recon report so that it is off of a sensitive computer

1. To run using s3, please set ACCESS_KEY_ID and ACCESS_SECRET_KEY environmental variables
    to whatever credentials you generated on AWS
```
export ACCESS_KEY_ID=AWEUFDADSJHDGJAS <- replace this
export ACCESS_SECRET_KEY=FARUEWRJEWHRJEQFIQEWJFWJQE@#$@#! <- replace this
```
If you are running on someone else's network or computer, make sure to unset these variables after you are done or else you could get found out.

2. install aws-cli
3. now run `aws configure`
4. enter your access keys

5. make a bucket
`aws s3 mb s3://ethical_hacking471`

6. run `python3 traft.py -t 172.28.128.3 --s3_bucket ethical_hacking471`

7. cleanup bucket
`aws s3 rb s3://ethical_hacking471 --force`

<br>

## Team (github usernames)
somi3k
smehta1215
Double-N
