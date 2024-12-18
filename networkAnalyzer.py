import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, sr1
from collections import Counter
import threading
import time
import csv
# import random
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Global counters and stats
traffic_stats = Counter()
latency_stats = []
jitter_stats = []
stop_sniffing_flag= False

# Lock for thread-safe operations
stats_lock = threading.Lock()

# Protocol mapping for easy identification
protocol_map = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
    0: "Unknown"
}

# User filters
user_filters = {
    "protocol": None,
    "source_ip": None,
    "destination_ip": None
}

# Logging file
log_file = "traffic_log1.csv"

# Initialize log file
def initialize_log():
    with open(log_file, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Time", "Protocol", "Source", "Destination", "Size (bytes)"])

# Log packet details
def log_packet(time_str, protocol, src, dst, size):
    with open(log_file, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([time_str, protocol, src, dst, size])

# Analyze each packet
def analyze_packet(packet):
    with stats_lock:
        if IP in packet:
            ip_layer = packet[IP]
            protocol = protocol_map.get(ip_layer.proto, "Other")

            # Apply filters
            if user_filters["protocol"] and protocol != user_filters["protocol"]:
                return
            if user_filters["source_ip"] and ip_layer.src != user_filters["source_ip"]:
                return
            if user_filters["destination_ip"] and ip_layer.dst != user_filters["destination_ip"]:
                return

            # Update traffic stats
            traffic_stats["total_packets"] += 1
            traffic_stats[protocol] += 1
            traffic_stats["total_bytes"] += len(packet)

            # Log packet details
            time_str = time.strftime('%H:%M:%S')
            log_packet(time_str, protocol, ip_layer.src, ip_layer.dst, len(packet))

    # Function to start sniffing packets
def start_sniffing(interface):
        global stop_sniffing_flag
        initialize_log()
        sniffer = AsyncSniffer(iface=interface, prn=analyze_packet, store=False)
        sniffer.start()
        try:
          while not stop_sniffing_flag:
            time.sleep(0.5)  # Keep the thread alive while sniffing
        finally:
           sniffer.stop()


# Measure latency and jitter using ICMP (ping)
def measure_latency_jitter(target="8.8.8.8"):
    global latency_stats, jitter_stats
    previous_latency = None

    while True:
        try:
            start_time = time.time()
            packet = IP(dst=target) / ICMP()
            reply = sr1(packet, timeout=1, verbose=0)
            if reply:
                latency = (time.time() - start_time) * 1000  # Latency in milliseconds
                latency_stats.append(latency)

                # Calculate jitter (absolute difference between consecutive latencies)
                if previous_latency is not None:
                    jitter = abs(latency - previous_latency)
                    jitter_stats.append(jitter)
                previous_latency = latency
            else:
                latency_stats.append(None)
        except Exception as e:
            latency_stats.append(None)

        time.sleep(2)  # Send ping every second

# Matplotlib plots
def update_graph():
    with stats_lock:
        protocols = ["TCP", "UDP", "ICMP", "ARP"]
        counts = [traffic_stats[proto] for proto in protocols]
        latency_plot.clear()
        jitter_plot.clear()
        traffic_plot.clear()

        # Latency and jitter plots
        if latency_stats:
            latency_plot.plot(latency_stats[-50:], label="Latency (ms)", color="blue")
        if jitter_stats:
            jitter_plot.plot(jitter_stats[-50:], label="Jitter (ms)", color="red")

             
        latency_plot.set_title("Latency Over Time")
        latency_plot.set_ylabel("Latency (ms)")
        latency_plot.set_xlabel("Time (s)")


        jitter_plot.set_title("Jitter Over Time")
        jitter_plot.set_ylabel("Jitter (ms)")
        jitter_plot.set_xlabel("Time (s)")
        if latency_stats:  
             latency_plot.legend()   
        
        if jitter_stats:
            jitter_plot.legend()

        traffic_plot.bar(protocols, counts, color='blue')
        traffic_plot.set_title("Traffic Protocol Distribution")
        traffic_plot.set_ylabel("Packet Count")
        traffic_plot.set_xlabel("Protocol")

         
        
        canvas.draw()

# Periodic update for the graph
def periodic_update():
    while True:
        time.sleep(2)
        update_graph()

# Start sniffing function with filters
def start_sniffer():
    interface = interface_var.get()
    protocol = protocol_var.get()
    source_ip = source_ip_var.get()
    destination_ip = destination_ip_var.get()

    user_filters["protocol"] = protocol if protocol != "All" else None
    user_filters["source_ip"] = source_ip if source_ip else None
    user_filters["destination_ip"] = destination_ip if destination_ip else None

    if not interface:
        messagebox.showerror("Error", "Please select a network interface.")
        return
    

    threading.Thread(target=start_sniffing, args=(interface,), daemon=True).start()
    messagebox.showinfo("Info", f"Started sniffing on {interface}")

    # Start threads for latency/jitter and packet sniffing
    threading.Thread(target=measure_latency_jitter, daemon=True).start()

#     # Function to start sniffing packets
# def start_sniffing(interface):
#         global stop_sniffing_flag
#         initialize_log()
#         sniffer = AsyncSniffer(iface=interface, prn=analyze_packet, store=False)
#         sniffer.start()
#         try:
#           while not stop_sniffing_flag:
#             time.sleep(0.5)  # Keep the thread alive while sniffing
#         finally:
#            sniffer.stop()
  


#  messagebox.showinfo("Info", f"Started sniffing on {interface}")


# Function to stop sniffing
def stop_sniffer():
    global stop_sniffing_flag
    stop_sniffing_flag = True
    messagebox.showinfo("Info", "Stopped sniffing. Exiting...")
    root.destroy()  # Close the GUI window

root = tk.Tk()
root.title("Network Traffic Analyzer")
root.protocol("WM_DELETE_WINDOW", stop_sniffer)

# GUI Elements
tk.Label(root, text="Select Interface:").grid(row=0, column=0, padx=5, pady=5)
interface_var = tk.StringVar()
interface_entry = ttk.Combobox(root, textvariable=interface_var, values=["Wi-Fi","Ethernet"])
interface_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(root, text="Filter by Protocol:").grid(row=1, column=0, padx=5, pady=5)
protocol_var = tk.StringVar(value="All")
protocol_dropdown = ttk.Combobox(root, textvariable=protocol_var, values=["All", "TCP", "UDP", "ICMP", "ARP"])
protocol_dropdown.grid(row=1, column=1, padx=5, pady=5)

tk.Label(root, text="Source IP:").grid(row=0, column=2, padx=5, pady=5)
source_ip_var = tk.StringVar()
source_ip_entry = ttk.Entry(root, textvariable=source_ip_var)
source_ip_entry.grid(row=0, column=3, padx=5, pady=5)

tk.Label(root, text="Destination IP:").grid(row=1, column=2, padx=5, pady=5)
destination_ip_var = tk.StringVar()
destination_ip_entry = ttk.Entry(root, textvariable=destination_ip_var)
destination_ip_entry.grid(row=1, column=3, padx=5, pady=5)

start_button = ttk.Button(root, text="Start Sniffing", command=start_sniffer)
start_button.grid(row=2, column=0, padx=5, pady=10)

stop_button = ttk.Button(root, text="Stop Sniffing", command=stop_sniffer)
stop_button.grid(row=2, column=3, padx=5, pady=10)

# Matplotlib Figure
fig = Figure(figsize=(10, 5), dpi=100, layout='constrained')
traffic_plot = fig.add_subplot(311)
latency_plot = fig.add_subplot(312)
jitter_plot = fig.add_subplot(313)

canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().grid(row=5, column=0, columnspan=2)

# Start update thread
threading.Thread(target=periodic_update, daemon=True).start()

root.mainloop()


