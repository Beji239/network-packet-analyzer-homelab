# all of it is only written for the purpose of education and one has to install Npcap on windows for the purpose of live sniffing
#pip install scapy in the terminal here should not be forgotten too
#Quick triage tool: Sniff 100 packets when something feels weird, 
#dump to Wireshark, get a fast visual summary. 
#Donut chart instantly says "all clear" or "oh crap".

from scapy.all import sniff, TCP, UDP, ICMP, Raw#Raw=It's a protocol layer for unparsed data.packet[raw].load =payload/data of packet!
from scapy.utils import wrpcap#wrpcap=writes packets in a .pcap file. wrpcap(filename, packets, append=False)
from scapy.layers.inet import IP
from scapy.layers.http import HTTP # Changed: HTTPRequest -> HTTP in scapy >=2.5.new scapy version has got http request/response in it. 
import numpy as np#has to be there for our calculations. without it np.(whatever attribute) is meaningless 
import seaborn as sns# library for graphs 
import pandas as pd#library for graphs,loading,cleaning messy data,filtering and querying,grouping and aggregation, adding and calculating columns like exel.joining and merging dataset.  
import matplotlib.pyplot as plt#used mostly for linear graphs. seaborn need matplotlib always! pandas too if we use it for graphs.
from plotly.subplots import make_subplots#plotly creates our interactive graphs 
import plotly.graph_objects as go
import webbrowser# we import the webbrowser to show our graphs 
import os#importing Operating system into python to create the path we need for the seconde option. the second line I post here below
# plotly_fig.write_html("security_dashboard.html")
#webbrowser.open('file://' + os.path.realpath("security_dashboard.html")) this one needs os or operating system 
import plotly.io as pio
pio.renderers.default = "browser"# how plotly should display our graph (and the line above it ). thats why we imported Browser 

from collections import defaultdict
syn_scan_tracker = defaultdict(list)#defaultdict(list) auto-creates an empty list the first time you touch a new key.
#from collections import defaultdict
#d = defaultdict(list)
#d['192.168.1.5'].append(80) # Works! Creates d['192.168.1.5'] = [] first
#d['192.168.1.5'].append(443) # Now it's [80, 443]




Nmap_THRESHOLD = 15#we later use this in the comments I mention below
#if len(set(syn_scan_tracker[p[IP].src])) > Nmap_THRESHOLD
#    status = "Nmap Scan Detected"


METASPLOIT_SIGNATURES = [
    b"\x90\x90\x90\x90",
    b"meterpreter",
    b"powershell -nop -w hidden",
    b"/bin/sh",
    b"cmd.exe",
]

mode = input("Choose Mode: (1) live sniffing or (2) read PCAP file: ")

if mode == "1":
    print("Monitoring live packets, you can go surf a little...")
    # Note: live sniff needs sudo/admin privileges
    packets = sniff(count=100, store=True)
    wrpcap('live_capture.pcap', packets) # Use relative path.Scapy’s wrpcap writes all the packets you just sniffed to a .pcap file.type:ignore. since I installed scapy and import wrpcap, but still underlined 
    print("Saved to live_capture.pcap - you can open this in Wireshark")
else:
    file_path = input("Enter the path to your PCAP file: ")
    packets = sniff(offline=file_path)

packet_list = []
critical_ports = [21, 23, 80]

for p in packets:
    if p.haslayer(IP):
        proto_name = "other"
        status = "standard"

        if p.haslayer(TCP):
            print(f"Source Port: {p[TCP].sport} -> Dest Port: {p[TCP].dport}")
            proto_name = "TCP"

            if p[TCP].flags == "S":
                syn_scan_tracker[p[IP].src].append(p[TCP].dport)
                if len(set(syn_scan_tracker[p[IP].src])) > Nmap_THRESHOLD:
                    status = "Nmap Scan Detected"
                    proto_name = "Nmap_SCAN"

            if p[TCP].dport in critical_ports or p[TCP].sport in critical_ports:
                status = "critical Risk"
                if (p[TCP].dport == 80 or p[TCP].sport == 80):
                    status = "Warning: Unencrypted HTTP"
                    proto_name = "HTTP"

                    if p.haslayer(HTTP): # Changed from HTTPRequest
                        try:
                            http_layer = p[HTTP]
                            http_path = http_layer.Path.decode(errors='ignore')
                            if any(x in http_path.lower() for x in ["'", "union", "select", "<script>", "javascript:"]):
                                status = "Possible SQLi/XSS Attempt"
                                proto_name = "WEB_ATTACK"
                        except:
                            pass

                if (p[TCP].dport == 21 or p[TCP].sport == 21):
                    proto_name = "FTP"
                elif (p[TCP].dport == 23 or p[TCP].sport == 23):
                    proto_name = "Telnet"

        elif p.haslayer(UDP):
            proto_name = "UDP"

        packet_size = len(p)
        if packet_size > 1200:
            if status == "standard":
                status = "Bulk Data Transfer"
        elif p.haslayer(ICMP):
            proto_name = "ICMP"
            status = "High Risk"

        if p.haslayer(TCP) and p.haslayer(Raw):
            try:
                payload = p[Raw].load
                for sig in METASPLOIT_SIGNATURES:
                    if sig in payload:
                        status = "Metasploit Exploit Detected"
                        proto_name = "EXPLOIT"
                        break
            except:
                pass

        details = {
            'source': p[IP].src,
            'destination': p[IP].dst,
            'size': len(p),
            'protocol': proto_name,
            'safety': status,
            'port': p[TCP].dport if p.haslayer(TCP) else (p[UDP].dport if p.haslayer(UDP) else 0),
            'timestamp': p.time,
            'is_nmap_scan': status == "Nmap Scan Detected",
            'is_web_attack': status == "Possible SQLi/XSS Attempt",
            'is_exploit': status == "Metasploit Exploit Detected"
        }
        packet_list.append(details)

df = pd.DataFrame(packet_list)
df['time_dt'] = pd.to_datetime(df['timestamp'], unit='s')
print(df.head())
df.to_csv('network_log.csv', index=False) # Relative path

if df.empty:
    print("No IP packets captured. Exiting.")
    exit()

most_frequent_IP = df['source'].value_counts().idxmax()
counts = df['source'].value_counts().max()
counts5 = df['source'].value_counts().head(5)

nmap_scanners = df[df['is_nmap_scan'] == True]['source'].unique()
web_attackers = df[df['is_web_attack'] == True]['source'].unique()
exploit_sources = df[df['is_exploit'] == True]['source'].unique()

if len(nmap_scanners) > 0:
    print(f"\n[!] ALERT: Nmap Scan Detected from: {', '.join(nmap_scanners)}")
if len(web_attackers) > 0:
    print(f"\n[!] ALERT: Web Attack Detected from: {', '.join(web_attackers)}")
if len(exploit_sources) > 0:
    print(f"\n[!] CRITICAL: Metasploit Exploit Detected from: {', '.join(exploit_sources)}")

with open('most_active_ip.txt', 'w') as f:
    f.write(f"Most active IP: {most_frequent_IP}\n")
    f.write(f"Packet count: {counts}\n")
    f.write(f"Top 5: \n{counts5}\n")
    if len(nmap_scanners) > 0:
        f.write(f"\nNmap Scanners: {', '.join(nmap_scanners)}\n")
    if len(web_attackers) > 0:
        f.write(f"Web Attackers: {', '.join(web_attackers)}\n")
    if len(exploit_sources) > 0:
        f.write(f"Exploit Sources: {', '.join(exploit_sources)}\n")

# Matplotlib + Seaborn dashboard
mpl_fig, axes = plt.subplots(1, 2, figsize=(14, 6)) # Renamed fig -> mpl_fig
sns.barplot(x=counts5.index, y=counts5.values, ax=axes[0], palette='Greens_r')
axes[0].set_facecolor('black')
axes[0].set_title("Top 5 Loudest Talkers")
axes[0].set_xlabel("IP Address")
axes[0].set_ylabel("Packet Count")
mpl_fig.patch.set_facecolor('#f0f0f0')

risk_counts = df['safety'].value_counts()
color_map = {
    'standard': 'green',
    'High Risk': 'red',
    'critical Risk': 'purple',
    'Bulk Data Transfer': '#FFD700',
    'Warning: Unencrypted HTTP': 'orange',
    'Nmap Scan Detected': '#FF8C00',
    'Possible SQLi/XSS Attempt': '#DC143C',
    'Metasploit Exploit Detected': '#8B0000'
}
current_colors = [color_map.get(x, 'grey') for x in risk_counts.index]
axes[1].pie(risk_counts.values, labels=risk_counts.index, autopct='%1.1f%%',
            startangle=90, colors=current_colors,
            wedgeprops={'width': 0.5, 'edgecolor': 'white'})
axes[1].set_title("Network Risk Assessment")
plt.tight_layout()

# Plotly 3D dashboard
plotly_fig = make_subplots(
    rows=1, cols=2,
    specs=[[{"type": "scene"}, {"type": "domain"}]],
    subplot_titles=("Packet Feature Distribution (3D)", "Risk Assessment (Donut)")
)
plotly_fig.add_trace(
    go.Scatter3d(
        x=df['time_dt'], y=df['size'], z=df['port'],
        mode='markers',
        text=df.apply(lambda r: f"IP: {r['source']}<br>Proto: {r['protocol']}<br>Risk: {r['safety']}<br>Port: {r['port']}", axis=1),
        hoverinfo="text",
        marker=dict(size=5, color=df['size'], colorscale='Viridis', opacity=0.8)
    ), row=1, col=1
)
current_colors_plotly = [color_map.get(label, 'grey') for label in risk_counts.index]
plotly_fig.add_trace(
    go.Pie(labels=risk_counts.index.tolist(), values=risk_counts.values.tolist(),
           hole=0.4, marker=dict(colors=current_colors_plotly)),
    row=1, col=2
)

plotly_fig.write_html("security_dashboard.html")
webbrowser.open('file://' + os.path.realpath("security_dashboard.html"))

plt.show(block=True) # Show matplotlib window
print(f"\nSummary: Captured {len(df)} packets. Check security_dashboard.html for visual analysis.")