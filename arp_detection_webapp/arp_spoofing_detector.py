import scapy.all as scapy
import logging

logging.basicConfig(filename='arp_spoofing_alerts.log', level=logging.INFO)

def packet_callback(packet):
    if scapy.ARP in packet and packet[scapy.ARP].op == 2:  # ARP Reply
        try:
            # ARP packet details
            arp_src_ip = packet[scapy.ARP].psrc
            arp_src_mac = packet[scapy.ARP].hwsrc
            arp_dst_ip = packet[scapy.ARP].pdst
            arp_dst_mac = packet[scapy.ARP].hwdst
            
            logging.info(f"ARP Packet: {arp_src_ip} is at {arp_src_mac}, {arp_dst_ip} is at {arp_dst_mac}")
            print(f"Possible ARP Spoofing detected: IP {arp_src_ip} is at MAC {arp_src_mac}")

        except Exception as e:
            logging.error(f"Error processing packet: {e}")

def start_arp_detection():
    scapy.sniff(prn=packet_callback, filter="arp", store=0)

if __name__ == "__main__":
    start_arp_detection()
