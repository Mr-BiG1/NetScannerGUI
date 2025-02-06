from scapy.all import *
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
from collections import defaultdict

class NetworkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Monitor")
        self.root.geometry("1000x700")
        
        # Monitoring control
        self.monitoring = False
        self.ssh_threshold = 5
        self.portscan_threshold = 5
        
        # Create GUI elements
        self.create_widgets()
        
        # Initialize statistics
        self.traffic_stats = defaultdict(int)
        self.alerts = []
        self.update_interval = 2  # Seconds
        
        # Start periodic UI updates
        self.update_stats()

    def create_widgets(self):
        # Control Panel
        control_frame = ttk.LabelFrame(self.root, text="Controls")
        control_frame.pack(pady=10, padx=10, fill="x")
        
        self.start_btn = ttk.Button(control_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.start_btn.pack(side="left", padx=5)
        
        ttk.Label(control_frame, text="SSH Threshold:").pack(side="left", padx=5)
        self.ssh_thresh_entry = ttk.Entry(control_frame, width=5)
        self.ssh_thresh_entry.insert(0, "5")
        self.ssh_thresh_entry.pack(side="left", padx=5)
        
        ttk.Label(control_frame, text="Port Scan Threshold:").pack(side="left", padx=5)
        self.portscan_thresh_entry = ttk.Entry(control_frame, width=5)
        self.portscan_thresh_entry.insert(0, "5")
        self.portscan_thresh_entry.pack(side="left", padx=5)
        
        # Statistics Display
        stats_frame = ttk.LabelFrame(self.root, text="Real-time Statistics")
        stats_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        self.stats_tree = ttk.Treeview(stats_frame, columns=("Value"), show="headings")
        self.stats_tree.heading("#0", text="Protocol")
        self.stats_tree.heading("Value", text="Count")
        self.stats_tree.pack(fill="both", expand=True)
        
        # Alert Log
        alert_frame = ttk.LabelFrame(self.root, text="Security Alerts")
        alert_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        self.alert_text = scrolledtext.ScrolledText(alert_frame, height=10)
        self.alert_text.pack(fill="both", expand=True)
        self.alert_text.configure(state='disabled')
        
    def toggle_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.start_btn.config(text="Stop Monitoring")
            self.ssh_threshold = int(self.ssh_thresh_entry.get())
            self.portscan_threshold = int(self.portscan_thresh_entry.get())
            
            # Start sniffing in background thread
            self.sniff_thread = threading.Thread(target=self.start_sniffing, daemon=True)
            self.sniff_thread.start()
        else:
            self.monitoring = False
            self.start_btn.config(text="Start Monitoring")

    def start_sniffing(self):
        sniff(prn=self.packet_handler, store=0, stop_filter=lambda x: not self.monitoring)

    def packet_handler(self, packet):
        try:
            if IP in packet:
                src_ip = packet[IP].src
                
                # Update protocol statistics
                if TCP in packet:
                    self.traffic_stats["TCP"] += 1
                    if packet[TCP].dport == 80:
                        self.traffic_stats["HTTP"] += 1
                    elif packet[TCP].dport == 443:
                        self.traffic_stats["HTTPS"] += 1
                    elif packet[TCP].dport == 22:
                        self.traffic_stats["SSH"] += 1
                        self.check_ssh_bruteforce(src_ip)
                        
                elif UDP in packet:
                    self.traffic_stats["UDP"] += 1
                    if packet[UDP].dport == 53:
                        self.traffic_stats["DNS"] += 1
                        
        except Exception as e:
            self.log_alert(f"Error processing packet: {str(e)}")

    def check_ssh_bruteforce(self, src_ip):
        ssh_count = self.traffic_stats.get(f"SSH_{src_ip}", 0) + 1
        self.traffic_stats[f"SSH_{src_ip}"] = ssh_count
        
        if ssh_count > self.ssh_threshold:
            alert = f"SSH brute-force attempt detected from {src_ip} ({ssh_count} attempts)"
            self.log_alert(alert)
            self.traffic_stats[f"SSH_{src_ip}"] = 0  # Reset counter

    def log_alert(self, message):
        self.alerts.append(message)
        self.alert_text.configure(state='normal')
        self.alert_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}\n")
        self.alert_text.configure(state='disabled')
        self.alert_text.see(tk.END)

    def update_stats(self):
        if self.monitoring:
            # Update statistics treeview
            self.stats_tree.delete(*self.stats_tree.get_children())
            
            for proto in ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "SSH"]:
                count = self.traffic_stats.get(proto, 0)
                self.stats_tree.insert("", "end", text=proto, values=(count,))
                
        self.root.after(1000 * self.update_interval, self.update_stats)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.mainloop() 