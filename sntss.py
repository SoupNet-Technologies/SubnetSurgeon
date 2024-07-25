import tkinter as tk
from tkinter import ttk, messagebox
import ipaddress
import random

class SNTSS:
    def __init__(self, root):
        self.root = root
        self.root.title("SoupNet Technologies Subnet Surgeon")
        self.root.geometry("600x500")

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self.canvas = tk.Canvas(self.root)
        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.canvas.grid(row=0, column=0, sticky="nsew")

        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.bind('<Configure>', lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        self.main_frame = ttk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.main_frame, anchor="nw")

        self.create_main_menu()
        self.create_menu_bar()

    def create_main_menu(self):
        self.clear_frame()

        internal_frame = ttk.Frame(self.main_frame)
        internal_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)

        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        tk.Label(internal_frame, text="Welcome to SNT-SS", font=('Helvetica', 16)).grid(row=0, column=0, columnspan=2, pady=10)

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
            ("Calculate Wildcard Mask", self.show_calculate_wildcard_mask),
            ("Validate IP Address", self.show_validate_ip),
            ("Validate Subnet Mask", self.show_validate_subnet_mask),
            ("Calculate Supernet", self.show_calculate_supernet),
            ("Find Network Address", self.show_find_network_address),
            ("Find First Usable IP Address", self.show_find_first_usable_ip),
            ("Find Last Usable IP Address", self.show_find_last_usable_ip),
            ("Calculate Prefix Length", self.show_calculate_prefix_length),
            ("Check if IP is Public or Private", self.show_check_public_private_ip),
            ("Find Default Gateway", self.show_find_default_gateway),
            ("Check if Two IPs are in Same Subnet", self.show_check_ips_same_subnet),
            ("Generate Random IP Address", self.show_generate_random_ip),
            ("Generate Random Subnet Mask", self.show_generate_random_subnet_mask),
            ("Convert IP Address to Binary", self.show_ip_to_binary),
            ("Convert Binary to IP Address", self.show_binary_to_ip),
            ("Calculate IPv6 Subnet ID", self.show_find_ipv6_subnet_id),
            ("Calculate IPv6 Prefix Length", self.show_calculate_ipv6_prefix_length),
            ("Find IPv6 Network Address", self.show_find_ipv6_network_address),
            ("Check if IP is in Subnet (IPv6)", self.show_check_ipv6_in_subnet),
            ("Generate Random IPv6 Address", self.show_generate_random_ipv6),
            ("Convert IPv6 Address to Binary", self.show_ipv6_to_binary),
            ("Convert Binary to IPv6 Address", self.show_binary_to_ipv6),
            ("Check if IP Address is Unicast (IPv4/IPv6)", self.show_check_unicast),
            ("Check if IP Address is Unique Local (IPv4/IPv6)", self.show_check_unique_local)
        ]

        self.function_dict = {text: command for text, command in functions}

        self.selected_function = tk.StringVar(self.root)
        self.selected_function.set("Select Function")

        tk.Label(internal_frame, text="Select a Function:").grid(row=1, column=0, pady=5, sticky="e")
        self.dropdown = ttk.Combobox(internal_frame, textvariable=self.selected_function, values=list(self.function_dict.keys()))
        self.dropdown.grid(row=1, column=1, pady=5, sticky="w")

        tk.Button(internal_frame, text="Go", command=self.execute_selected_function).grid(row=2, column=0, columnspan=2, pady=10)

        internal_frame.grid_rowconfigure(0, weight=1)
        internal_frame.grid_rowconfigure(1, weight=1)
        internal_frame.grid_rowconfigure(2, weight=1)
        internal_frame.grid_columnconfigure(0, weight=1)
        internal_frame.grid_columnconfigure(1, weight=1)

    def execute_selected_function(self):
        function_name = self.selected_function.get()
        if function_name in self.function_dict:
            self.function_dict[function_name]()

    def create_menu_bar(self):
        menubar = tk.Menu(self.root)

        network_menu = tk.Menu(menubar, tearoff=0)
        ipv4_menu = tk.Menu(menubar, tearoff=0)
        ipv6_menu = tk.Menu(menubar, tearoff=0)

        for name, command in self.function_dict.items():
            if "IPv6" in name:
                ipv6_menu.add_command(label=name, command=command)
            elif "IPv4" in name or "IP" in name:
                ipv4_menu.add_command(label=name, command=command)
            else:
                network_menu.add_command(label=name, command=command)

        menubar.add_cascade(label="Network", menu=network_menu)
        menubar.add_cascade(label="IPv4", menu=ipv4_menu)
        menubar.add_cascade(label="IPv6", menu=ipv6_menu)

        self.root.config(menu=menubar)

    def clear_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def back_to_menu(self):
        self.create_main_menu()

    def create_tooltip(self, widget, text):
        tool_tip = tk.Toplevel(widget)
        tool_tip.wm_overrideredirect(True)
        tool_tip.wm_geometry("+0+0")
        tk.Label(tool_tip, text=text, background="black", relief='solid', borderwidth=1, wraplength=150).pack(ipadx=1)
        tool_tip.withdraw()
        widget.bind("<Enter>", lambda e: tool_tip.deiconify())
        widget.bind("<Leave>", lambda e: tool_tip.withdraw())
        widget.bind("<Motion>", lambda e: tool_tip.geometry(f"+{e.x_root + 10}+{e.y_root + 10}"))

    def create_two_entry_fields(self, label1, label2, command, button_text):
        internal_frame = ttk.Frame(self.main_frame)
        internal_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)

        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        tk.Label(internal_frame, text=label1).grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.entry1 = tk.Entry(internal_frame)
        self.entry1.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        example1 = "e.g., 192.168.0.1" if "IP Address" in label1 else "e.g., 255.255.255.0" if "Subnet Mask" in label1 else ""
        self.create_tooltip(self.entry1, example1)

        tk.Label(internal_frame, text=label2).grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.entry2 = tk.Entry(internal_frame)
        self.entry2.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        example2 = "e.g., 192.168.0.1" if "IP Address" in label2 else "e.g., 255.255.255.0" if "Subnet Mask" in label2 else ""
        self.create_tooltip(self.entry2, example2)

        self.result_label = tk.Label(internal_frame, text="", justify="left")
        self.result_label.grid(row=3, column=0, columnspan=2, pady=10)

        tk.Button(internal_frame, text=button_text, command=command).grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(internal_frame, text="Back", command=self.back_to_menu).grid(row=4, column=0, columnspan=2, pady=10)

        internal_frame.grid_rowconfigure(0, weight=1)
        internal_frame.grid_rowconfigure(1, weight=1)
        internal_frame.grid_rowconfigure(2, weight=1)
        internal_frame.grid_rowconfigure(3, weight=1)
        internal_frame.grid_rowconfigure(4, weight=1)
        internal_frame.grid_columnconfigure(0, weight=1)
        internal_frame.grid_columnconfigure(1, weight=1)

    def create_one_entry_field(self, label, command, button_text):
        internal_frame = ttk.Frame(self.main_frame)
        internal_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)

        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        tk.Label(internal_frame, text=label).grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.entry = tk.Entry(internal_frame)
        self.entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        example = "e.g., 192.168.0.1" if "IP Address" in label else "e.g., 255.255.255.0" if "Subnet Mask" in label else "e.g., 24" if "CIDR Notation" in label else ""
        self.create_tooltip(self.entry, example)

        self.result_label = tk.Label(internal_frame, text="", justify="left")
        self.result_label.grid(row=2, column=0, columnspan=2, pady=10)

        tk.Button(internal_frame, text=button_text, command=command).grid(row=1, column=0, columnspan=2, pady=10)
        ttk.Button(internal_frame, text="Back", command=self.back_to_menu).grid(row=3, column=0, columnspan=2, pady=10)

        internal_frame.grid_rowconfigure(0, weight=1)
        internal_frame.grid_rowconfigure(1, weight=1)
        internal_frame.grid_rowconfigure(2, weight=1)
        internal_frame.grid_rowconfigure(3, weight=1)
        internal_frame.grid_columnconfigure(0, weight=1)
        internal_frame.grid_columnconfigure(1, weight=1)

    def show_find_subnet_id(self):
        self.clear_frame()
        self.create_two_entry_fields("IP Address:", "Subnet Mask:", self.calculate_subnet_id, "Calculate Subnet ID")

    def show_find_mask(self):
        self.clear_frame()
        self.create_one_entry_field("CIDR Notation:", self.calculate_mask, "Calculate Subnet Mask")

    def show_subnets_required(self):
        self.clear_frame()
        self.create_two_entry_fields("IP Address:", "Number of Subnets:", self.calculate_subnets_required, "Calculate Subnet Address (Subnets)")

    def show_hosts_required(self):
        self.clear_frame()
        self.create_two_entry_fields("IP Address:", "Number of Hosts:", self.calculate_hosts_required, "Calculate Subnet Address (Hosts)")

    def show_subnets_with_host_bits(self):
        self.clear_frame()
        self.create_two_entry_fields("IP Address:", "Number of Host Bits:", self.calculate_subnets_with_host_bits, "Calculate Subnet Address (Host Bits)")

    def show_find_broadcast_id(self):
        self.clear_frame()
        self.create_two_entry_fields("IP Address:", "Subnet Mask:", self.calculate_broadcast_id, "Calculate Broadcast Address")

    def show_find_ip_range(self):
        self.clear_frame()
        self.create_two_entry_fields("IP Address:", "Subnet Mask:", self.calculate_ip_range, "Calculate IP Range")

    def show_find_number_of_hosts(self):
        self.clear_frame()
        self.create_two_entry_fields("IP Address:", "Subnet Mask:", self.calculate_number_of_hosts, "Calculate Number of Usable Hosts")

    def show_cidr_to_mask(self):
        self.clear_frame()
        self.create_one_entry_field("CIDR Notation:", self.convert_cidr_to_mask, "Convert CIDR to Subnet Mask")

    def show_mask_to_cidr(self):
        self.clear_frame()
        self.create_one_entry_field("Subnet Mask:", self.convert_mask_to_cidr, "Convert Subnet Mask to CIDR")

    def show_check_ip_in_subnet(self):
        self.clear_frame()
        self.create_two_entry_fields("IP Address:", "Subnet Address/Mask:", self.check_ip_in_subnet, "Check if IP is in Subnet")

    def show_calculate_wildcard_mask(self):
        self.clear_frame()
        self.create_one_entry_field("Subnet Mask:", self.calculate_wildcard_mask, "Calculate Wildcard Mask")

    def show_validate_ip(self):
        self.clear_frame()
        self.create_one_entry_field("IP Address:", self.validate_ip, "Validate IP Address")

    def show_validate_subnet_mask(self):
        self.clear_frame()
        self.create_one_entry_field("Subnet Mask:", self.validate_subnet_mask, "Validate Subnet Mask")

    def show_calculate_supernet(self):
        self.clear_frame()
        self.create_two_entry_fields("IP Address:", "Subnet Mask:", self.calculate_supernet, "Calculate Supernet")

    def show_find_network_address(self):
        self.clear_frame()
        self.create_two_entry_fields("IP Address:", "Subnet Mask:", self.find_network_address, "Find Network Address")

    def show_find_first_usable_ip(self):
        self.clear_frame()
        self.create_two_entry_fields("IP Address:", "Subnet Mask:", self.find_first_usable_ip, "Find First Usable IP Address")

    def show_find_last_usable_ip(self):
        self.clear_frame()
        self.create_two_entry_fields("IP Address:", "Subnet Mask:", self.find_last_usable_ip, "Find Last Usable IP Address")

    def show_calculate_prefix_length(self):
        self.clear_frame()
        self.create_one_entry_field("Subnet Mask:", self.calculate_prefix_length, "Calculate Prefix Length")

    def show_check_public_private_ip(self):
        self.clear_frame()
        self.create_one_entry_field("IP Address:", self.check_public_private_ip, "Check if IP is Public or Private")

    def show_find_default_gateway(self):
        self.clear_frame()
        self.create_two_entry_fields("IP Address:", "Subnet Mask:", self.find_default_gateway, "Find Default Gateway")

    def show_check_ips_same_subnet(self):
        self.clear_frame()
        self.create_two_entry_fields("IP Address 1:", "IP Address 2:", self.check_ips_same_subnet, "Check if Two IPs are in Same Subnet")

    def show_generate_random_ip(self):
        self.clear_frame()
        self.create_one_entry_field("Subnet Address/Mask:", self.generate_random_ip, "Generate Random IP Address")

    def show_generate_random_subnet_mask(self):
        self.clear_frame()
        self.create_one_entry_field("CIDR Notation:", self.generate_random_subnet_mask, "Generate Random Subnet Mask")

    def show_ip_to_binary(self):
        self.clear_frame()
        self.create_one_entry_field("IP Address:", self.ip_to_binary, "Convert IP Address to Binary")

    def show_binary_to_ip(self):
        self.clear_frame()
        self.create_one_entry_field("Binary String:", self.binary_to_ip, "Convert Binary to IP Address")

    def show_find_ipv6_subnet_id(self):
        self.clear_frame()
        self.create_two_entry_fields("IPv6 Address:", "Prefix Length:", self.calculate_ipv6_subnet_id, "Calculate IPv6 Subnet ID")

    def show_calculate_ipv6_prefix_length(self):
        self.clear_frame()
        self.create_one_entry_field("IPv6 Subnet Mask:", self.calculate_ipv6_prefix_length, "Calculate IPv6 Prefix Length")

    def show_find_ipv6_network_address(self):
        self.clear_frame()
        self.create_two_entry_fields("IPv6 Address:", "Prefix Length:", self.find_ipv6_network_address, "Find IPv6 Network Address")

    def show_check_ipv6_in_subnet(self):
        self.clear_frame()
        self.create_two_entry_fields("IPv6 Address:", "IPv6 Subnet Address/Prefix:", self.check_ipv6_in_subnet, "Check if IP is in Subnet (IPv6)")

    def show_generate_random_ipv6(self):
        self.clear_frame()
        self.create_one_entry_field("Prefix Length:", self.generate_random_ipv6, "Generate Random IPv6 Address")

    def show_ipv6_to_binary(self):
        self.clear_frame()
        self.create_one_entry_field("IPv6 Address:", self.ipv6_to_binary, "Convert IPv6 Address to Binary")

    def show_binary_to_ipv6(self):
        self.clear_frame()
        self.create_one_entry_field("Binary String:", self.binary_to_ipv6, "Convert Binary to IPv6 Address")

    def show_check_unicast(self):
        self.clear_frame()
        self.create_one_entry_field("IP Address:", self.check_unicast, "Check if IP Address is Unicast (IPv4/IPv6)")

    def show_check_unique_local(self):
        self.clear_frame()
        self.create_one_entry_field("IP Address:", self.check_unique_local, "Check if IP Address is Unique Local (IPv4/IPv6)")

    def calculate_subnet_id(self):
        ip = self.entry1.get()
        mask = self.entry2.get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label.config(text=f"Subnet ID: {network.network_address}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_mask(self):
        cidr = self.entry.get()
        try:
            mask = ipaddress.IPv4Network(f"0.0.0.0/{cidr}").netmask
            self.result_label.config(text=f"Subnet Mask: {mask}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_subnets_required(self):
        ip = self.entry1.get()
        subnets = int(self.entry2.get())
        try:
            network = ipaddress.IPv4Network(ip, strict=False)
            new_prefix = network.prefixlen + (subnets - 1).bit_length()
            if new_prefix > 32:
                raise ValueError("Too many subnets required.")
            self.result_label.config(text=f"New Subnet Address: {network.network_address}/{new_prefix}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_hosts_required(self):
        ip = self.entry1.get()
        hosts = int(self.entry2.get())
        try:
            network = ipaddress.IPv4Network(ip, strict=False)
            new_prefix = 32 - (hosts + 2).bit_length()
            if new_prefix < network.prefixlen:
                raise ValueError("Too many hosts required.")
            self.result_label.config(text=f"New Subnet Address: {network.network_address}/{new_prefix}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_subnets_with_host_bits(self):
        ip = self.entry1.get()
        host_bits = int(self.entry2.get())
        try:
            network = ipaddress.IPv4Network(ip, strict=False)
            new_prefix = 32 - host_bits
            self.result_label.config(text=f"New Subnet Address: {network.network_address}/{new_prefix}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_broadcast_id(self):
        ip = self.entry1.get()
        mask = self.entry2.get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label.config(text=f"Broadcast Address: {network.broadcast_address}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_ip_range(self):
        ip = self.entry1.get()
        mask = self.entry2.get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label.config(text=f"IP Range: {network.network_address} - {network.broadcast_address}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_number_of_hosts(self):
        ip = self.entry1.get()
        mask = self.entry2.get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label.config(text=f"Number of Usable Hosts: {network.num_addresses - 2}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def convert_cidr_to_mask(self):
        cidr = self.entry.get()
        try:
            mask = ipaddress.IPv4Network(f"0.0.0.0/{cidr}").netmask
            self.result_label.config(text=f"Subnet Mask: {mask}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def convert_mask_to_cidr(self):
        mask = self.entry.get()
        try:
            cidr = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
            self.result_label.config(text=f"CIDR Notation: /{cidr}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def check_ip_in_subnet(self):
        ip = self.entry1.get()
        subnet = self.entry2.get()
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            ip_addr = ipaddress.ip_address(ip)
            self.result_label.config(text=f"IP is in subnet: {ip_addr in network}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_wildcard_mask(self):
        mask = self.entry.get()
        try:
            network = ipaddress.IPv4Network(f"0.0.0.0/{mask}")
            wildcard = ipaddress.IPv4Address(int(network.hostmask))
            self.result_label.config(text=f"Wildcard Mask: {wildcard}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def validate_ip(self):
        ip = self.entry.get()
        try:
            ipaddress.ip_address(ip)
            self.result_label.config(text="IP Address is valid.")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def validate_subnet_mask(self):
        mask = self.entry.get()
        try:
            ipaddress.IPv4Network(f"0.0.0.0/{mask}")
            self.result_label.config(text="Subnet Mask is valid.")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_supernet(self):
        ip = self.entry1.get()
        mask = self.entry2.get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label.config(text=f"Supernet: {network.supernet()}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def find_network_address(self):
        ip = self.entry1.get()
        mask = self.entry2.get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label.config(text=f"Network Address: {network.network_address}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def find_first_usable_ip(self):
        ip = self.entry1.get()
        mask = self.entry2.get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label.config(text=f"First Usable IP: {network.network_address + 1}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def find_last_usable_ip(self):
        ip = self.entry1.get()
        mask = self.entry2.get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label.config(text=f"Last Usable IP: {network.broadcast_address - 1}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_prefix_length(self):
        mask = self.entry.get()
        try:
            cidr = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
            self.result_label.config(text=f"Prefix Length: /{cidr}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def check_public_private_ip(self):
        ip = self.entry.get()
        try:
            ip_addr = ipaddress.ip_address(ip)
            if ip_addr.is_private:
                self.result_label.config(text="IP Address is private.")
            else:
                self.result_label.config(text="IP Address is public.")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def find_default_gateway(self):
        ip = self.entry1.get()
        mask = self.entry2.get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            default_gateway = network.network_address + 1
            self.result_label.config(text=f"Default Gateway: {default_gateway}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def check_ips_same_subnet(self):
        ip1 = self.entry1.get()
        ip2 = self.entry2.get()
        try:
            ip_addr1 = ipaddress.ip_address(ip1)
            ip_addr2 = ipaddress.ip_address(ip2)
            self.result_label.config(text=f"IPs in same subnet: {ip_addr1.network == ip_addr2.network}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def generate_random_ip(self):
        subnet = self.entry.get()
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            random_ip = random.choice(list(network.hosts()))
            self.result_label.config(text=f"Random IP Address: {random_ip}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def generate_random_subnet_mask(self):
        cidr = int(self.entry.get())
        if 0 <= cidr <= 32:
            network = ipaddress.IPv4Network(f"0.0.0.0/{cidr}")
            self.result_label.config(text=f"Random Subnet Mask: {network.netmask}")
        else:
            self.result_label.config(text="Error: Invalid CIDR notation.")

    def ip_to_binary(self):
        ip = self.entry.get()
        try:
            ip_addr = ipaddress.ip_address(ip)
            self.result_label.config(text=f"Binary: {ip_addr.packed.hex()}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def binary_to_ip(self):
        binary_str = self.entry.get()
        try:
            ip_addr = ipaddress.ip_address(bytes.fromhex(binary_str))
            self.result_label.config(text=f"IP Address: {ip_addr}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_ipv6_subnet_id(self):
        ip = self.entry1.get()
        prefix = int(self.entry2.get())
        try:
            network = ipaddress.IPv6Network(f"{ip}/{prefix}", strict=False)
            self.result_label.config(text=f"IPv6 Subnet ID: {network.network_address}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_ipv6_prefix_length(self):
        mask = self.entry.get()
        try:
            prefix_length = ipaddress.IPv6Network(f"::/{mask}").prefixlen
            self.result_label.config(text=f"IPv6 Prefix Length: /{prefix_length}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def find_ipv6_network_address(self):
        ip = self.entry1.get()
        prefix = int(self.entry2.get())
        try:
            network = ipaddress.IPv6Network(f"{ip}/{prefix}", strict=False)
            self.result_label.config(text=f"IPv6 Network Address: {network.network_address}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def check_ipv6_in_subnet(self):
        ip = self.entry1.get()
        subnet = self.entry2.get()
        try:
            network = ipaddress.IPv6Network(subnet, strict=False)
            ip_addr = ipaddress.IPv6Address(ip)
            self.result_label.config(text=f"IPv6 is in subnet: {ip_addr in network}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def generate_random_ipv6(self):
        prefix = int(self.entry.get())
        if 0 <= prefix <= 128:
            network = ipaddress.IPv6Network(f"::/{prefix}")
            random_ip = random.choice(list(network.hosts()))
            self.result_label.config(text=f"Random IPv6 Address: {random_ip}")
        else:
            self.result_label.config(text="Error: Invalid prefix length.")

    def ipv6_to_binary(self):
        ip = self.entry.get()
        try:
            ip_addr = ipaddress.IPv6Address(ip)
            self.result_label.config(text=f"Binary: {ip_addr.packed.hex()}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def binary_to_ipv6(self):
        binary_str = self.entry.get()
        try:
            ip_addr = ipaddress.IPv6Address(bytes.fromhex(binary_str))
            self.result_label.config(text=f"IPv6 Address: {ip_addr}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def check_unicast(self):
        ip = self.entry.get()
        try:
            ip_addr = ipaddress.ip_address(ip)
            if ip_addr.is_global:
                self.result_label.config(text="IP Address is a global unicast address.")
            else:
                self.result_label.config(text="IP Address is not a global unicast address.")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def check_unique_local(self):
        ip = self.entry.get()
        try:
            ip_addr = ipaddress.ip_address(ip)
            if ip_addr.is_private:
                self.result_label.config(text="IP Address is a unique local address.")
            else:
                self.result_label.config(text="IP Address is not a unique local address.")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SNTSS(root)
    root.mainloop()
