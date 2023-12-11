import argparse
import sys
import scapy.all as scapy

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', '-t', dest='ip_address', help="Target IP address or IP range")
    options = parser.parse_args()
    if not options.ip_address:
        parser.error("[-] Please specify a target IP address or IP range. Use --help for more information.")
    return options

def request_arp(ip_address):
    arp_request = scapy.ARP(pdst=ip_address)
    broadcast_mac = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast_mac = broadcast_mac/arp_request
    response_list, noresponse_list = scapy.srp(arp_request_broadcast_mac, timeout=2, verbose=False)
    targets_list = []
    for element in response_list:
        targets_dict = {'IP': element[1].psrc, 'MAC': element[1].hwsrc}
        targets_list.append(targets_dict)
    return targets_list

def list_ARP_Responses(target_list):
    print('  IP-ADDRESS\t\tAt MAC-ADDRESS')
    print(' -------------------------------------------')
    for element in target_list:
        print(' ' + element['IP'] + '\t\t' + element['MAC'])

options = get_arguments()
targets_list = request_arp(options.ip_address)
list_ARP_Responses(targets_list)
