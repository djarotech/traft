import argparse
import os
import sys
from pymetasploit3.msfrpc import MsfRpcClient
import nmap
import json
import xmltodict

def target_nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV --open --script=nmap-vulners,vulscan --script-args vulscandb=cve.csv')
    nmap_output = nm.get_nmap_last_output()
    nmap_dict = xmltodict.parse(nmap_output)
    
    result = []
    try:
      for item in nmap_dict['nmaprun']['host']['ports']['port']:
        name = ""
        cves = []
  
        if isinstance(item['service']['cpe'], list):
          name = item['service']['cpe'][0]
          ####print(item['service']['cpe'][0])
        else:
          name = item['service']['cpe']
          ####print(item['service']['cpe'])
  
        if isinstance(item['script'], list):
          if isinstance(item['script'][0]['elem'], str):
            cves = item['script'][1]['@output'].split('*')
            ####print(item['script'][1]['@output'].split('*'))
          else:
            cves = item['script'][0]['elem']['#text'].split('*')
            ####print(item['script'][0]['elem']['#text'].split('*'))
        cves = [name] + cves[1:]
        ####print(cves)
        ####print()
        result.append(cves)
      return(result)
    except Exception as e:
      return None



   # print(nm.scaninfo())

    # # Checks if host is down
    # if nm[target].state() != 'up':
    #     print('The target is down: ', target)

    # all_protocols = nm[target].all_protocols()

    # port_information = []

    # for protocol in all_protocols:
    #     keys = nm[target][protocol].keys()
    #     for key in keys:
    #         info = nm[target][protocol][key]
    #         port_information.append((key, info))

    # return port_information

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
        print("Found the following hosts: " + str(hosts))
    elif args.target != None:
        print('Running Target Scan...\n')
        target_nmap_scan(args.target)

if __name__ == '__main__':
    # Ensures program runs with Python 3
    if sys.version_info[0] < 3:
        raise Exception('Must be using Python 3')

    # TODO: Maybe implement a check for python-nmap

    main()
