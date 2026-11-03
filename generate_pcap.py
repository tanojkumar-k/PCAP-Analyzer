from scapy.all import IP, TCP, UDP, ICMP, wrpcap

# Dummy packets create chestunnam
packets = [
    IP(src="192.168.1.10", dst="8.8.8.8")/TCP(dport=80),
    IP(src="192.168.1.10", dst="8.8.8.8")/TCP(dport=443),
    IP(src="192.168.1.10", dst="1.1.1.1")/UDP(dport=53),
    IP(src="192.168.1.25", dst="8.8.4.4")/ICMP(),
    IP(src="10.0.0.5", dst="192.168.1.1")/UDP(dport=67),
    IP(src="192.168.1.10", dst="8.8.8.8")/TCP(dport=8080),
    IP(src="192.168.1.50", dst="8.8.8.8")/ICMP()
]

# Daanni .pcap file ga save chestunnam
wrpcap("test_traffic.pcap", packets)
print("Success! test_traffic.pcap file create ayyindi.")