import argparse
import os
import sys
from pymetasploit3.msfrpc import MsfRpcClient
import nmap

def target_nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV --script=nmap-vulners,vulscan --script-args vulscandb=cve.csv')

    print(nm.scaninfo())

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

def main():
    parser = argparse.ArgumentParser(description='Tool for host discovery and vulnerability scanning.')
    parser.add_argument("-s", "--subnet", action="store", dest='subnet', help="range of IP addresses")
    parser.add_argument("-t", "--target", action="store", dest='target', help="target IP address")
    args = parser.parse_args()

    # No inputs or flags provided
    if args.subnet == None and args.target == None:
        print('No inputs provided, please use -h for usage information.')
    # Too many inputs
    elif args.subnet != None and args.target != None:
        print('Too many inputs provided, please use -h for usage information.')
    # Start Nmap host discovery
    elif args.subnet != None:
        print('subnet process')
    # Start port scanning target host
    elif args.target != None:
        print('target process')
        target_nmap_scan(args.target)

if __name__ == '__main__':
    # Ensures program runs with Python 3
    if sys.version_info[0] < 3:
        raise Exception('Must be using Python 3')

    # TODO: Maybe implement a check for python-nmap

    main()
