import argparse
import os
import sys
import nmap
import json
import xmltodict
import xml.etree.ElementTree as ET
from pymetasploit3.msfrpc import MsfRpcClient

def target_nmap_scan(target):
    results = []
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV --open --host-timeout 2m --script=vulners.nse')
    nmap_output = nm.get_nmap_last_output()

    root = ET.fromstring(nmap_output)
    for item in root.findall(".//script"):
        if item[0].attrib:
            temp = []
            temp.append(item[0].attrib['key'])
            temp = temp + (item[0].text).split() 
            ####print(temp)
            ####print()
            if any('CVE' in string for string in temp):
                results.append(temp)

           # results.append(temp)
    ####print(results)
    return results

def subnet_nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sn')
    nmap_output = nm.get_nmap_last_output()
    nmap_dict = xmltodict.parse(nmap_output)
    subnet_hosts = []
    for result in nmap_dict['nmaprun']['host']:
        if isinstance(result['address'], list):
            subnet_hosts.append(result['address'][0]['@addr'])
        else:
            subnet_hosts.append(result['address']['@addr'])
    return subnet_hosts

def main():
    print("""
             ______   ______     ______     ______   ______  
	    /\__  _\ /\  == \   /\  __ \   /\  ___\ /\__  _\ 
	    \/_/\ \/ \ \  __<   \ \  __ \  \ \  __\ \/_/\ \/ 
	       \ \_\  \ \_\ \_\  \ \_\ \_\  \ \_\      \ \_\ 
	        \/_/   \/_/ /_/   \/_/\/_/   \/_/       \/_/ 
         """)                                        

    parser = argparse.ArgumentParser(description='Tool for host discovery and vulnerability scanning.')
    parser.add_argument("-s", "--subnet", action="store", dest='subnet', help="range of IP addresses")
    parser.add_argument("-t", "--target", action="store", dest='target', help="target IP address")
    args = parser.parse_args()

    if args.subnet == None and args.target == None:
        print('No inputs provided, please use -h for usage information.')
    elif args.subnet != None and args.target != None:
        print('Too many inputs provided, please use -h for usage information.')
    elif args.subnet != None:
        print('Running Subnet Scan...\n')
        hosts = subnet_nmap_scan(args.subnet)
        print('Found the following hosts: ' + str(hosts) + '\n')
        for host in hosts:
            print('Running Target Scan on host ' + str(host) + '...')
            scan_result = target_nmap_scan(host)
            if not scan_result:
                print('No vulnerabilities found.\n')
            else:
                print(scan_result)
                print()
    elif args.target != None:
        print('Running Target Scan...\n')
        scan_result = target_nmap_scan(args.target)
        if not scan_result:
            print('No vulnerabilities found.\n')
        else:
            print(scan_result)

if __name__ == '__main__':
    # Ensures program runs with Python 3
    if sys.version_info[0] < 3:
        raise Exception('Must be using Python 3')

    # TODO: Maybe implement a check for python-nmap

    main()
