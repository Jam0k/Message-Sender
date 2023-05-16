import socket
import ipaddress
import json
import threading
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog

class MessageSenderApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Message Sender")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Variables
        self.subnet = tk.StringVar(value='192.168.1.0/24')
        self.start_ip = tk.StringVar(value='192.168.1.1')
        self.end_ip = tk.StringVar(value='192.168.1.255')
        self.port = tk.IntVar(value=2221)
        self.timeout = tk.IntVar(value=3)
        self.message = tk.StringVar(value='Test')
        self.protocol = tk.StringVar(value='UDP')
        self.is_sending = False

        # Widgets
        ttk.Label(self, text="Subnet:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(self, textvariable=self.subnet).grid(row=0, column=1)

        ttk.Label(self, text="Start IP:").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(self, textvariable=self.start_ip).grid(row=1, column=1)

        ttk.Label(self, text="End IP:").grid(row=2, column=0, sticky=tk.W)
        ttk.Entry(self, textvariable=self.end_ip).grid(row=2, column=1)

        ttk.Label(self, text="Port:").grid(row=3, column=0, sticky=tk.W)
        ttk.Entry(self, textvariable=self.port).grid(row=3, column=1)

        ttk.Label(self, text="Timeout (TCP):").grid(row=4, column=0, sticky=tk.W)
        ttk.Entry(self, textvariable=self.timeout).grid(row=4, column=1)

        ttk.Label(self, text="Message:").grid(row=5, column=0, sticky=tk.W)
        ttk.Entry(self, textvariable=self.message).grid(row=5, column=1)

        ttk.Label(self, text="Protocol:").grid(row=6, column=0, sticky=tk.W)
        protocol_combobox = ttk.Combobox(self, textvariable=self.protocol, values=["UDP", "TCP"], state="readonly")
        protocol_combobox.grid(row=6, column=1, sticky=tk.W)
        protocol_combobox.current(0)

        self.send_button = ttk.Button(self, text="Send", command=self.send_message)
        self.send_button.grid(row=7, column=0)

        self.stop_button = ttk.Button(self, text="Stop", command=self.stop_sending, state=tk.DISABLED)
        self.stop_button.grid(row=7, column=1)

        self.progress = ttk.Progressbar(self, mode='determinate', maximum=100)
        self.progress.grid(row=8, columnspan=2, sticky=(tk.W, tk.E))

        self.log_view = tk.Text(self, width=50, height=10)
        self.log_view.grid(row=9, columnspan=2)

        self.clear_button = ttk.Button(self, text="Clear", command=self.clear_log)
        self.clear_button.grid(row=10, column=0)

        self.export_button = ttk.Button(self, text="Export", command=self.export_results)
        self.export_button.grid(row=10, column=1)


        self.config(menu=self.create_menu())

    def clear_log(self):
        self.log_view.delete(1.0, tk.END)

    def export_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])

        if file_path:
            with open(file_path, "w") as results_file:
                results_file.write(self.log_view.get(1.0, tk.END))

    def create_menu(self):
        menu = tk.Menu(self)

        file_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load Configuration", command=self.load_config)
        file_menu.add_command(label="Save Configuration", command=self.save_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)

        return menu

    def on_close(self):
        if not self.is_sending:
            self.destroy()

    def load_config(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")])

        if file_path:
            with open(file_path, "r") as config_file:
                config = json.load(config_file)

            self.subnet.set(config.get("subnet", "192.168.1.0/24"))
            self.start_ip.set(config.get("start_ip", "192.168.1.1"))
            self.end_ip.set(config.get("end_ip", "192.168.1.255"))
            self.port.set(config.get("port", 2221))
            self.timeout.set(config.get("timeout", 3))
            self.message.set(config.get("message", "Test"))
            self.protocol.set(config.get("protocol", "UDP"))

    def save_config(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")])

        if file_path:
            config = {
                "subnet": self.subnet.get(),
                "start_ip": self.start_ip.get(),
                "end_ip": self.end_ip.get(),
                "port": self.port.get(),
                "timeout": self.timeout.get(),
                "message": self.message.get(),
                "protocol": self.protocol.get()
            }

            with open(file_path, "w") as config_file:
                json.dump(config, config_file, indent=4)

    def send_message(self):
        if not self.is_sending:
            self.is_sending = True
            self.send_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

            send_thread = threading.Thread(target=self.send_messages_thread, daemon=True)
            send_thread.start()

    def send_messages_thread(self):
        subnet = self.subnet.get()
        start_ip = self.start_ip.get()
        end_ip = self.end_ip.get()
        port = self.port.get()
        timeout = self.timeout.get()
        message = self.message.get()
        protocol = self.protocol.get()

        network = ipaddress.IPv4Network(subnet, strict=False)
        start_ip = ipaddress.IPv4Address(start_ip)
        end_ip = ipaddress.IPv4Address(end_ip)

        if start_ip not in network or end_ip not in network:
            messagebox.showerror("Error", "Start or end IP is not in the subnet")
            return

        if protocol == "UDP":
            send_udp_message_to_range(start_ip, end_ip, port, message, self.log_view, self.progress, self)
        else:
            send_tcp_message_to_range(start_ip, end_ip, port, timeout, message, self.log_view, self.progress, self)

        self.is_sending = False
        self.send_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def stop_sending(self):
        self.is_sending = False

def send_udp_message_to_range(start_ip, end_ip, port, message, log_view, progress, app):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)  # Set a short timeout for receiving a response
    ip_count = int(end_ip) - int(start_ip) + 1

    for index, ip_int in enumerate(range(int(start_ip), int(end_ip) + 1)):
        if not app.is_sending:
            break

        addr = ipaddress.IPv4Address(ip_int)
        try:
            sock.sendto(message.encode('utf-8'), (str(addr), port))

            # Try to receive a response
            data, server = sock.recvfrom(1024)
            log_view.insert(tk.END, f'Sent message to {addr} - Response\n')
        except socket.timeout:
            log_view.insert(tk.END, f'Sent message to {addr} - No response\n')
        except Exception as e:
            log_view.insert(tk.END, f'Error sending message to {addr}: {e}\n')

        progress['value'] = (index + 1) * 100 / ip_count

    sock.close()

def send_tcp_message_to_range(start_ip, end_ip, port, timeout, message, log_view, progress, app):
    ip_count = int(end_ip) - int(start_ip) + 1

    for index, ip_int in enumerate(range(int(start_ip), int(end_ip) + 1)):
        if not app.is_sending:
            break

        addr = ipaddress.IPv4Address(ip_int)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((str(addr), port))
            sock.sendall(message.encode('utf-8'))
            response = sock.recv(1024)  # Try to receive a response
            log_view.insert(tk.END, f'Sent message to {addr} - Response: {response}\n')
        except socket.timeout:
            log_view.insert(tk.END, f'Sent message to {addr} - No response\n')
        except Exception as e:
            log_view.insert(tk.END, f'Error sending message to {addr}: {e}\n')
        finally:
            sock.close()

        progress['value'] = (index + 1) * 100 / ip_count

if __name__ == '__main__':
    app = MessageSenderApp()
    app.mainloop()
