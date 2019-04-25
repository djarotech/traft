import argparse
import os
from metasploit.msfrpc import MsfRpcClient
from metasploit.msfconsole import MsfRpcConsole
import nmap

def main(args):
    ip = args.ip_address

    nm = nmap.PortScanner()
    nm.scan('127.0.0.1', '22-443')
    print(nm['127.0.0.1'])

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
                                    description = "Nmap and metasploit exploitation tool",
                                )
    parser.add_argument("-i", "--ip_address", default="",
                      help = "The ip address of the target")

    args = parser.parse_args()
    main(args)
