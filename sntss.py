import tkinter as tk
from tkinter import ttk, messagebox
import ipaddress
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class SNTSS:
    def __init__(self, root):
        self.root = root
        self.root.title("SoupNet Technologies Subnet Surgeon")
        self.root.geometry("600x500")

        self.main_frame = ttk.Frame(self.root)
        self.main_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER, relwidth=0.9, relheight=0.9)

        self.create_main_menu()

    def create_main_menu(self):
        self.clear_frame()

        tk.Label(self.main_frame, text="Welcome to SNT-SS", font=('Helvetica', 16)).place(relx=0.5, rely=0.05, anchor=tk.CENTER)

        functions = [
            ("Calculate Subnet ID", self.show_find_subnet_id),
            ("Calculate Subnet Mask", self.show_find_mask),
            ("Calculate Subnet Address (Subnets)", self.show_subnets_required),
            ("Calculate Subnet Address (Hosts)", self.show_hosts_required),
            ("Calculate Subnet Address (Host Bits)", self.show_subnets_with_host_bits),
            ("Calculate Broadcast Address", self.show_find_broadcast_id),
            ("Calculate IP Range", self.show_find_ip_range),
            ("Calculate Number of Usable Hosts", self.show_find_number_of_hosts),
            ("Convert CIDR to Subnet Mask", self.show_cidr_to_mask),
            ("Convert Subnet Mask to CIDR", self.show_mask_to_cidr),
            ("Check if IP is in Subnet", self.show_check_ip_in_subnet),
        ]

        for i, (text, command) in enumerate(functions):
            ttk.Button(self.main_frame, text=text, command=command).place(relx=0.5, rely=0.1 + (i+1)*0.07, anchor=tk.CENTER, relwidth=0.6)

    def clear_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def back_to_menu(self):
        self.create_main_menu()

    def show_find_subnet_id(self):
        self.clear_frame()
        tk.Label(self.main_frame, text="IP Address:").place(relx=0.3, rely=0.1, anchor=tk.E)
        self.ip_entry1 = tk.Entry(self.main_frame)
        self.ip_entry1.place(relx=0.3, rely=0.1, anchor=tk.W, relwidth=0.5)
        self.create_tooltip(self.ip_entry1, "e.g., 192.168.1.1")

        tk.Label(self.main_frame, text="Subnet Mask:").place(relx=0.3, rely=0.2, anchor=tk.E)
        self.mask_entry1 = tk.Entry(self.main_frame)
        self.mask_entry1.place(relx=0.3, rely=0.2, anchor=tk.W, relwidth=0.5)
        self.create_tooltip(self.mask_entry1, "e.g., 255.255.255.0")

        self.result_label1 = tk.Label(self.main_frame, text="", justify="left")
        self.result_label1.place(relx=0.5, rely=0.4, anchor=tk.CENTER)

        tk.Button(self.main_frame, text="Calculate Subnet ID", command=self.calculate_subnet_id).place(relx=0.5, rely=0.3, anchor=tk.CENTER, relwidth=0.4)
        ttk.Button(self.main_frame, text="Back", command=self.back_to_menu).place(relx=0.5, rely=0.5, anchor=tk.CENTER, relwidth=0.4)

    def show_find_mask(self):
        self.clear_frame()
        tk.Label(self.main_frame, text="Subnet ID (CIDR):").place(relx=0.3, rely=0.1, anchor=tk.E)
        self.subnet_id_entry2 = tk.Entry(self.main_frame)
        self.subnet_id_entry2.place(relx=0.3, rely=0.1, anchor=tk.W, relwidth=0.5)
        self.create_tooltip(self.subnet_id_entry2, "e.g., 24")

        self.result_label2 = tk.Label(self.main_frame, text="", justify="left")
        self.result_label2.place(relx=0.5, rely=0.3, anchor=tk.CENTER)

        tk.Button(self.main_frame, text="Calculate Subnet Mask", command=self.calculate_mask).place(relx=0.5, rely=0.2, anchor=tk.CENTER, relwidth=0.4)
        ttk.Button(self.main_frame, text="Back", command=self.back_to_menu).place(relx=0.5, rely=0.4, anchor=tk.CENTER, relwidth=0.4)

    def show_subnets_required(self):
        self.clear_frame()
        tk.Label(self.main_frame, text="Number of Subnets:").place(relx=0.3, rely=0.1, anchor=tk.E)
        self.subnets_entry3 = tk.Entry(self.main_frame)
        self.subnets_entry3.place(relx=0.3, rely=0.1, anchor=tk.W, relwidth=0.5)
        self.create_tooltip(self.subnets_entry3, "e.g., 4")

        self.result_label3 = tk.Label(self.main_frame, text="", justify="left")
        self.result_label3.place(relx=0.5, rely=0.3, anchor=tk.CENTER)

        tk.Button(self.main_frame, text="Calculate Subnet Address", command=self.calculate_subnet_address_subnets).place(relx=0.5, rely=0.2, anchor=tk.CENTER, relwidth=0.4)
        ttk.Button(self.main_frame, text="Back", command=self.back_to_menu).place(relx=0.5, rely=0.4, anchor=tk.CENTER, relwidth=0.4)

    def show_subnets_with_host_bits(self):
        self.clear_frame()
        tk.Label(self.main_frame, text="Number of Host Bits:").place(relx=0.3, rely=0.1, anchor=tk.E)
        self.host_bits_entry_new = tk.Entry(self.main_frame)
        self.host_bits_entry_new.place(relx=0.3, rely=0.1, anchor=tk.W, relwidth=0.5)
        self.create_tooltip(self.host_bits_entry_new, "e.g., 8")

        self.result_label_new = tk.Label(self.main_frame, text="", justify="left")
        self.result_label_new.place(relx=0.5, rely=0.3, anchor=tk.CENTER)

        tk.Button(self.main_frame, text="Calculate Subnet Address", command=self.calculate_subnet_address_with_host_bits).place(relx=0.5, rely=0.2, anchor=tk.CENTER, relwidth=0.4)
        ttk.Button(self.main_frame, text="Back", command=self.back_to_menu).place(relx=0.5, rely=0.4, anchor=tk.CENTER, relwidth=0.4)

    def show_hosts_required(self):
        self.clear_frame()
        tk.Label(self.main_frame, text="Number of Hosts:").place(relx=0.3, rely=0.1, anchor=tk.E)
        self.hosts_entry4 = tk.Entry(self.main_frame)
        self.hosts_entry4.place(relx=0.3, rely=0.1, anchor=tk.W, relwidth=0.5)
        self.create_tooltip(self.hosts_entry4, "e.g., 100")

        self.result_label4 = tk.Label(self.main_frame, text="", justify="left")
        self.result_label4.place(relx=0.5, rely=0.3, anchor=tk.CENTER)

        tk.Button(self.main_frame, text="Calculate Subnet Address", command=self.calculate_subnet_address_hosts).place(relx=0.5, rely=0.2, anchor=tk.CENTER, relwidth=0.4)
        ttk.Button(self.main_frame, text="Back", command=self.back_to_menu).place(relx=0.5, rely=0.4, anchor=tk.CENTER, relwidth=0.4)

    def show_find_broadcast_id(self):
        self.clear_frame()
        tk.Label(self.main_frame, text="IP Address:").place(relx=0.3, rely=0.1, anchor=tk.E)
        self.ip_entry5 = tk.Entry(self.main_frame)
        self.ip_entry5.place(relx=0.3, rely=0.1, anchor=tk.W, relwidth=0.5)
        self.create_tooltip(self.ip_entry5, "e.g., 192.168.1.1")

        tk.Label(self.main_frame, text="Subnet Mask:").place(relx=0.3, rely=0.2, anchor=tk.E)
        self.mask_entry5 = tk.Entry(self.main_frame)
        self.mask_entry5.place(relx=0.3, rely=0.2, anchor=tk.W, relwidth=0.5)
        self.create_tooltip(self.mask_entry5, "e.g., 255.255.255.0")

        self.result_label5 = tk.Label(self.main_frame, text="", justify="left")
        self.result_label5.place(relx=0.5, rely=0.4, anchor=tk.CENTER)

        tk.Button(self.main_frame, text="Calculate Broadcast Address", command=self.calculate_broadcast_id).place(relx=0.5, rely=0.3, anchor=tk.CENTER, relwidth=0.4)
        ttk.Button(self.main_frame, text="Back", command=self.back_to_menu).place(relx=0.5, rely=0.5, anchor=tk.CENTER, relwidth=0.4)

    def show_find_ip_range(self):
        self.clear_frame()
        tk.Label(self.main_frame, text="IP Address:").place(relx=0.3, rely=0.1, anchor=tk.E)
        self.ip_entry6 = tk.Entry(self.main_frame)
        self.ip_entry6.place(relx=0.3, rely=0.1, anchor=tk.W, relwidth=0.5)
        self.create_tooltip(self.ip_entry6, "e.g., 192.168.1.1")

        tk.Label(self.main_frame, text="Subnet Mask:").place(relx=0.3, rely=0.2, anchor=tk.E)
        self.mask_entry6 = tk.Entry(self.main_frame)
        self.mask_entry6.place(relx=0.3, rely=0.2, anchor=tk.W, relwidth=0.5)
        self.create_tooltip(self.mask_entry6, "e.g., 255.255.255.0")

        self.result_label6 = tk.Label(self.main_frame, text="", justify="left")
        self.result_label6.place(relx=0.5, rely=0.4, anchor=tk.CENTER)

        tk.Button(self.main_frame, text="Calculate IP Range", command=self.calculate_ip_range).place(relx=0.5, rely=0.3, anchor=tk.CENTER, relwidth=0.4)
        ttk.Button(self.main_frame, text="Back", command=self.back_to_menu).place(relx=0.5, rely=0.5, anchor=tk.CENTER, relwidth=0.4)

    def show_find_number_of_hosts(self):
        self.clear_frame()
        tk.Label(self.main_frame, text="Subnet Mask:").place(relx=0.3, rely=0.1, anchor=tk.E)
        self.mask_entry7 = tk.Entry(self.main_frame)
        self.mask_entry7.place(relx=0.3, rely=0.1, anchor=tk.W, relwidth=0.5)
        self.create_tooltip(self.mask_entry7, "e.g., 255.255.255.0")

        self.result_label7 = tk.Label(self.main_frame, text="", justify="left")
        self.result_label7.place(relx=0.5, rely=0.3, anchor=tk.CENTER)

        tk.Button(self.main_frame, text="Calculate Number of Usable Hosts", command=self.calculate_number_of_hosts).place(relx=0.5, rely=0.2, anchor=tk.CENTER, relwidth=0.4)
        ttk.Button(self.main_frame, text="Back", command=self.back_to_menu).place(relx=0.5, rely=0.4, anchor=tk.CENTER, relwidth=0.4)

    def show_cidr_to_mask(self):
        self.clear_frame()
        tk.Label(self.main_frame, text="CIDR Notation:").place(relx=0.3, rely=0.1, anchor=tk.E)
        self.cidr_entry8 = tk.Entry(self.main_frame)
        self.cidr_entry8.place(relx=0.3, rely=0.1, anchor=tk.W, relwidth=0.5)
        self.create_tooltip(self.cidr_entry8, "e.g., 24")

        self.result_label8 = tk.Label(self.main_frame, text="", justify="left")
        self.result_label8.place(relx=0.5, rely=0.3, anchor=tk.CENTER)

        tk.Button(self.main_frame, text="Convert to Subnet Mask", command=self.convert_cidr_to_mask).place(relx=0.5, rely=0.2, anchor=tk.CENTER, relwidth=0.4)
        ttk.Button(self.main_frame, text="Back", command=self.back_to_menu).place(relx=0.5, rely=0.4, anchor=tk.CENTER, relwidth=0.4)

    def show_mask_to_cidr(self):
        self.clear_frame()
        tk.Label(self.main_frame, text="Subnet Mask:").place(relx=0.3, rely=0.1, anchor=tk.E)
        self.mask_entry9 = tk.Entry(self.main_frame)
        self.mask_entry9.place(relx=0.3, rely=0.1, anchor=tk.W, relwidth=0.5)
        self.create_tooltip(self.mask_entry9, "e.g., 255.255.255.0")

        self.result_label9 = tk.Label(self.main_frame, text="", justify="left")
        self.result_label9.place(relx=0.5, rely=0.3, anchor=tk.CENTER)

        tk.Button(self.main_frame, text="Convert to CIDR", command=self.convert_mask_to_cidr).place(relx=0.5, rely=0.2, anchor=tk.CENTER, relwidth=0.4)
        ttk.Button(self.main_frame, text="Back", command=self.back_to_menu).place(relx=0.5, rely=0.4, anchor=tk.CENTER, relwidth=0.4)

    def show_check_ip_in_subnet(self):
        self.clear_frame()
        tk.Label(self.main_frame, text="IP Address:").place(relx=0.3, rely=0.1, anchor=tk.E)
        self.ip_entry10 = tk.Entry(self.main_frame)
        self.ip_entry10.place(relx=0.3, rely=0.1, anchor=tk.W, relwidth=0.5)
        self.create_tooltip(self.ip_entry10, "e.g., 192.168.1.1")

        tk.Label(self.main_frame, text="Subnet (CIDR):").place(relx=0.3, rely=0.2, anchor=tk.E)
        self.subnet_entry10 = tk.Entry(self.main_frame)
        self.subnet_entry10.place(relx=0.3, rely=0.2, anchor=tk.W, relwidth=0.5)
        self.create_tooltip(self.subnet_entry10, "e.g., 192.168.1.0/24")

        self.result_label10 = tk.Label(self.main_frame, text="", justify="left")
        self.result_label10.place(relx=0.5, rely=0.4, anchor=tk.CENTER)

        tk.Button(self.main_frame, text="Check IP in Subnet", command=self.check_ip_in_subnet).place(relx=0.5, rely=0.3, anchor=tk.CENTER, relwidth=0.4)
        ttk.Button(self.main_frame, text="Back", command=self.back_to_menu).place(relx=0.5, rely=0.5, anchor=tk.CENTER, relwidth=0.4)

    def calculate_subnet_id(self):
        ip = self.ip_entry1.get()
        mask = self.mask_entry1.get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            info = (f"Network ID: {network.network_address}\n"
                    f"Subnet Mask: /{network.prefixlen}\n"
                    f"Broadcast Address: {network.broadcast_address}\n"
                    f"Usable Hosts: {network.num_addresses - 2}\n"
                    f"First Usable Address: {network.network_address + 1}\n"
                    f"Last Usable Address: {network.broadcast_address - 1}")
            self.result_label1.config(text=info)
            self.plot_network_info(network)
        except ValueError:
            self.result_label1.config(text="Invalid input")

    def calculate_mask(self):
        subnet_id = self.subnet_id_entry2.get()
        try:
            prefix = int(subnet_id)
            if prefix < 0 or prefix > 32:
                raise ValueError
            mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
            self.result_label2.config(text=f"Subnet Mask: {mask}\n"
                                           f"Formula used: /{prefix} => {mask}")
        except ValueError:
            self.result_label2.config(text="Invalid input")

    def calculate_subnet_address_subnets(self):
        subnets = self.subnets_entry3.get()
        try:
            subnets = int(subnets)
            subnet_bits = subnets.bit_length()
            mask_bits = 32 - subnet_bits
            mask = f"/{mask_bits}"
            self.result_label3.config(text=f"Subnet Mask: {mask}\n"
                                           f"Total Subnets: {2 ** subnet_bits}\n"
                                           f"Formula used: 2^(Subnet Bits)")
        except ValueError:
            self.result_label3.config(text="Invalid input")

    def calculate_subnet_address_with_host_bits(self):
        host_bits = self.host_bits_entry_new.get()
        try:
            host_bits = int(host_bits)
            mask_bits = 32 - host_bits
            mask = f"/{mask_bits}"
            self.result_label_new.config(text=f"Subnet Mask: {mask}\n"
                                              f"Usable Hosts per Subnet: {2 ** host_bits - 2}\n"
                                              f"Formula used: 2^(Host Bits) - 2")
        except ValueError:
            self.result_label_new.config(text="Invalid input")

    def calculate_subnet_address_hosts(self):
        hosts = self.hosts_entry4.get()
        try:
            hosts = int(hosts)
            mask_bits = 32 - (hosts + 2).bit_length()
            mask = f"/{mask_bits}"
            self.result_label4.config(text=f"Subnet Mask: {mask}\n"
                                           f"Usable Hosts per Subnet: {hosts}\n"
                                           f"Formula used: 2^(Mask Bits) - 2")
        except ValueError:
            self.result_label4.config(text="Invalid input")

    def calculate_broadcast_id(self):
        ip = self.ip_entry5.get()
        mask = self.mask_entry5.get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label5.config(text=f"Broadcast ID: {network.broadcast_address}\n"
                                           f"Formula used: Network Address + Inverse Subnet Mask")
            self.plot_network_info(network)
        except ValueError:
            self.result_label5.config(text="Invalid input")

    def calculate_ip_range(self):
        ip = self.ip_entry6.get()
        mask = self.mask_entry6.get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label6.config(text=f"IP Range: {network.network_address + 1} - {network.broadcast_address - 1}\n"
                                           f"Formula used: Network Address + 1 to Broadcast Address - 1")
        except ValueError:
            self.result_label6.config(text="Invalid input")

    def calculate_number_of_hosts(self):
        mask = self.mask_entry7.get()
        try:
            network = ipaddress.IPv4Network(f"0.0.0.0/{mask}")
            usable_hosts = network.num_addresses - 2
            self.result_label7.config(text=f"Number of Usable Hosts: {usable_hosts}\n"
                                           f"Formula used: 2^(32 - Prefix Length) - 2")
        except ValueError:
            self.result_label7.config(text="Invalid input")

    def convert_cidr_to_mask(self):
        cidr = self.cidr_entry8.get()
        try:
            prefix = int(cidr)
            if prefix < 0 or prefix > 32:
                raise ValueError
            mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
            self.result_label8.config(text=f"Subnet Mask: {mask}\n"
                                           f"Formula used: /{prefix} => {mask}")
        except ValueError:
            self.result_label8.config(text="Invalid input")

    def convert_mask_to_cidr(self):
        mask = self.mask_entry9.get()
        try:
            network = ipaddress.IPv4Network(f"0.0.0.0/{mask}")
            prefix = network.prefixlen
            self.result_label9.config(text=f"CIDR Notation: /{prefix}\n"
                                           f"Formula used: {mask} => /{prefix}")
        except ValueError:
            self.result_label9.config(text="Invalid input")

    def check_ip_in_subnet(self):
        ip = self.ip_entry10.get()
        subnet = self.subnet_entry10.get()
        try:
            ip_addr = ipaddress.IPv4Address(ip)
            network = ipaddress.IPv4Network(subnet, strict=False)
            result = ip_addr in network
            self.result_label10.config(text=f"IP {ip} is in subnet {subnet}: {result}")
        except ValueError:
            self.result_label10.config(text="Invalid input")

    def create_tooltip(self, widget, text):
        tooltip = tk.Toplevel(widget, padx=1, pady=1)
        tooltip.withdraw()
        tooltip.overrideredirect(True)
        tooltip.wm_attributes('-alpha', 0)
        label = tk.Label(tooltip, text=text, justify='left', relief='solid', borderwidth=1, wraplength=350)
        label.pack()

        def enter(event):
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() - 1500
            y += widget.winfo_rooty() - 1500
            tooltip.geometry(f"+{x+10}+{y+10}")  # This makes the tooltip LESS jumpy. else it renders top left before following the mouse
            tooltip.wm_attributes('-alpha', 0)
            tooltip.deiconify()

        def leave(event):
            tooltip.wm_attributes('-alpha', 0)
            tooltip.withdraw()

        def motion(event):
            x, y = event.x_root, event.y_root
            tooltip.geometry(f"+{x+5}+{y+20}")
            tooltip.wm_attributes('-alpha', 0.8)

        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)
        widget.bind("<Motion>", motion)

    def plot_network_info(self, network):
        fig, ax = plt.subplots(figsize=(5, 3))

        total_hosts = network.num_addresses
        usable_hosts = total_hosts - 2
        unusable_hosts = 2

        ax.bar(["Usable Hosts", "Unusable Hosts"], [usable_hosts, unusable_hosts], color=['green', 'red'])
        ax.set_title("Subnet Host Distribution")
        ax.set_ylabel("Number of Hosts")

        canvas = FigureCanvasTkAgg(fig, master=self.main_frame)
        canvas.draw()
        canvas.get_tk_widget().place(relx=0.5, rely=0.6, anchor=tk.CENTER, relwidth=0.8)

if __name__ == "__main__":
    root = tk.Tk()
    app = SNTSS(root)
    root.mainloop()
