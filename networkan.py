from scapy.all import *
import time


ip_count = {}


time_frame = 10 

# DDos/Dos detection and blocking
def analyze_packet(packet):
    global ip_count 
    
    if packet.haslayer(TCP) and packet.haslayer(IP):
       
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        
        
        if src_ip in ip_count:
            ip_count[src_ip]["count"] += 1
            ip_count[src_ip]["time"] = time.time() 
        else:
            ip_count[src_ip] = {"count": 1, "time": time.time()}
        
      
        if ip_count[src_ip]["count"] > 500:
            print("\033[31m" + f"DDOS attack detected from {src_ip}:{src_port} to {dst_ip}:{dst_port}" + "\033[0m")

            os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
            
        current_time = time.time()
        ip_count = {ip: count for ip, count in ip_count.items() if current_time - count["time"] <= time_frame}
    
    # Injection attack detection and blocking
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', 'ignore')
        if "SELECT" in payload.upper() or "DROP" in payload.upper():
            print("\033[31m" + f"Potential SQL injection attack from {src_ip}:{src_port} to {dst_ip}:{dst_port}" + "\033[0m")

            os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        if "<script>" in payload.lower():
            print("\033[31m" + f"Potential XSS attack from {src_ip}:{src_port} to {dst_ip}:{dst_port}" + "\033[0m")
        
    # brute force detection and blocking
    if flags == "PA":
        payload = packet[TCP].payload.load.decode('utf-8', 'ignore')
        if len(payload) > 10 and len(set(payload)) == 1:
            print("\033[31m" + f"Potential brute forcing from {src_ip}:{src_port} to {dst_ip}:{dst_port}" + "\033[0m")
            # Block the attacker's IP address
            os.system(f"iptables -A INPUT -s {src_ip} -j DROP")

# Sniffing packets on the network interface
sniff(filter="tcp", prn=analyze_packet)

