# NetworkTrafficAnalyser_Byscapy
### Introduction to the Network Traffic Analyzer Project  

The **Network Traffic Analyzer** is a comprehensive tool designed to monitor, analyze, and log network activity in real-time. This project provides insights into network behavior by capturing and categorizing packets, measuring network latency, and tracking jitter for enhanced visibility and performance evaluation. Built with Python, the analyzer leverages libraries such as **Tkinter** for a graphical user interface (GUI), **Scapy** for packet analysis, and **Matplotlib** for visual representation of network data.  

#### Purpose and Objectives  
In today's digital world, maintaining secure and efficient network communication is crucial. The Network Traffic Analyzer aims to:  
1. **Monitor Network Traffic:** Capture live packets from a specified network interface and classify them by protocol (e.g., TCP, UDP, ICMP).  
2. **Provide Real-time Insights:** Track total packet count, byte size, latency, and jitter, offering a clear understanding of network performance.  
3. **Customizable Filters:** Allow users to focus on specific traffic patterns by filtering based on protocol, source IP, and destination IP.  
4. **Log Traffic Data:** Save network activity details to a log file for further analysis or auditing.  
5. **Visualize Metrics:** Display interactive graphs for protocol distribution, latency trends, and jitter variations for quick interpretation of data.  

 Key Features  
1. **Real-time Packet Sniffing:** Utilizes Scapy’s powerful sniffing capabilities to capture packets with low latency.  
2. **Graphical Interface:** Simplifies usability with a Tkinter-based GUI for selecting interfaces, setting filters, and starting/stopping analysis.  
3. **Performance Metrics:** Includes latency and jitter measurements using ICMP echo requests (ping).  
4. **Data Visualization:** Employs Matplotlib to plot latency, jitter, and protocol distribution trends dynamically.  
5. **Thread-safe Operations:** Ensures reliable data handling even in concurrent operations through multi-threading and thread-safe locking.  

#### Applications  
This project serves as an educational and practical tool for network administrators, cybersecurity professionals, and students to:  
- Diagnose network issues and monitor performance.  
- Analyze suspicious or unauthorized traffic patterns.  
- Gain hands-on experience in network packet analysis.  

By combining robust functionalities with a user-friendly design, the Network Traffic Analyzer enables a deeper understanding of network dynamics and fosters proactive network management.
