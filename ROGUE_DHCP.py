from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether

# Define the DHCP server configuration
server_ip = '192.168.1.1'
subnet_mask = '255.255.255.0'
lease_time = 600  # Lease time in seconds
ip_pool = ['192.168.1.10', '192.168.1.20']  # Example IP pool
offered_ips = {}

def handle_dhcp_packet(packet):
    if packet[DHCP] and packet[DHCP].options[0][1] == 1:  # DHCP Discover
        print("DHCP Discover received")
        offer_ip = ip_pool.pop(0)
        offered_ips[packet[Ether].src] = offer_ip
        send_dhcp_offer(packet, offer_ip)
    elif packet[DHCP] and packet[DHCP].options[0][1] == 3:  # DHCP Request
        print("DHCP Request received")
        client_mac = packet[Ether].src
        if client_mac in offered_ips:
            send_dhcp_ack(packet, offered_ips[client_mac])

def send_dhcp_offer(discover_packet, offer_ip):
    offer_packet = Ether(src=get_if_hwaddr(conf.iface), dst=discover_packet[Ether].src) / \
                   IP(src=server_ip, dst='255.255.255.255') / \
                   UDP(sport=67, dport=68) / \
                   BOOTP(op=2, yiaddr=offer_ip, siaddr=server_ip, chaddr=discover_packet[Ether].chaddr) / \
                   DHCP(options=[('message-type', 'offer'),
                                 ('server_id', server_ip),
                                 ('subnet_mask', subnet_mask),
                                 ('lease_time', lease_time),
                                 ('end')])
    sendp(offer_packet, iface=conf.iface)

def send_dhcp_ack(request_packet, assigned_ip):
    ack_packet = Ether(src=get_if_hwaddr(conf.iface), dst=request_packet[Ether].src) / \
                 IP(src=server_ip, dst='255.255.255.255') / \
                 UDP(sport=67, dport=68) / \
                 BOOTP(op=2, yiaddr=assigned_ip, siaddr=server_ip, chaddr=request_packet[Ether].chaddr) / \
                 DHCP(options=[('message-type', 'ack'),
                               ('server_id', server_ip),
                               ('subnet_mask', subnet_mask),
                               ('lease_time', lease_time),
                               ('end')])
    sendp(ack_packet, iface=conf.iface)

print("DHCP Server is running...")
sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp_packet, iface=conf.iface)
