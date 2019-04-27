import argparse
import os
from pymetasploit3.msfrpc import MsfRpcClient
import nmap

def main(args):
    ip = args.ip_address

    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-sV -sC -p80')

    if not nm.has_host(ip):
        print("Could not find host")
        exit(1)
    print(nm[ip])
    print(nm.all_hosts())
    print(nm.scaninfo())
if __name__ == '__main__':

    parser = argparse.ArgumentParser(
                                    description = "Nmap and metasploit exploitation tool",
                                )
    parser.add_argument("-i", "--ip_address", default="",
                      help = "The ip address of the target")

    args = parser.parse_args()
    main(args)
