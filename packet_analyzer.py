from scapy.all import sniff, IP

# Function to process each packet
def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        length = len(packet)
        # Protocol mapping
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        proto_name = proto_map.get(proto, str(proto))
        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {proto_name} | Length: {length}")

if __name__ == "__main__":
    interface = input("Enter the network interface to sniff (e.g., eth0, wlan0): ")
    print(f"Sniffing on interface: {interface}. Press Ctrl+C to stop.")
    sniff(iface=interface, prn=process_packet, store=0)