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
            ("Convert CIDR to Subnet Mask", self.show_cidr_to_mask), # General, but typically for IPv4 context from CIDR
            ("Convert Subnet Mask to CIDR (IPv4)", self.show_mask_to_cidr_ipv4),
            ("Check if IP is in Subnet", self.show_check_ip_in_subnet), # Handles both via ipaddress.ip_network
            ("Calculate Wildcard Mask (IPv4)", self.show_calculate_wildcard_mask_ipv4),
            ("Validate IP Address", self.show_validate_ip), # Handles both
            ("Validate Subnet Mask (IPv4)", self.show_validate_subnet_mask_ipv4),
            ("Calculate Supernet (IPv4)", self.show_calculate_supernet_ipv4),
            ("Calculate Supernet (IPv6)", self.show_calculate_supernet_ipv6),
            ("Find Network Address", self.show_find_network_address), # Handles both with ipaddress.ip_network
            ("Find First Usable IP Address", self.show_find_first_usable_ip),
            ("Find Last Usable IP Address", self.show_find_last_usable_ip),
            ("Calculate Prefix Length (from IPv4 Mask)", self.show_calculate_prefix_length_ipv4),
            ("Check if IP is Public or Private", self.show_check_public_private_ip), # Handles both
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

    def create_entry_fields(self, fields, command, button_text):
        internal_frame = ttk.Frame(self.main_frame)
        internal_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)

        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.entries = []
        for i, field_info in enumerate(fields):
            label_text = field_info["label"]
            tooltip_text = field_info.get("tooltip", "")
            example_text = field_info.get("example", "")

            tk.Label(internal_frame, text=label_text).grid(row=i, column=0, padx=5, pady=5, sticky="e")
            entry = tk.Entry(internal_frame)
            entry.grid(row=i, column=1, padx=5, pady=5, sticky="w")
            self.entries.append(entry)

            if not tooltip_text:
                if "IP Address" in label_text:
                    tooltip_text = "e.g., 192.168.0.1"
                elif "Subnet Mask" in label_text:
                    tooltip_text = "e.g., 255.255.255.0"
                elif "CIDR Notation" in label_text:
                    tooltip_text = "e.g., 24"
                elif "Prefix Length" in label_text:
                    tooltip_text = "e.g., 64"
            if example_text: # if example text is provided, use it as tooltip
                tooltip_text = example_text
            self.create_tooltip(entry, tooltip_text)
            
            internal_frame.grid_rowconfigure(i, weight=1)

        current_row = len(fields)
        tk.Button(internal_frame, text=button_text, command=command).grid(row=current_row, column=0, columnspan=2, pady=10)
        internal_frame.grid_rowconfigure(current_row, weight=1)
        
        current_row += 1
        self.result_label = tk.Label(internal_frame, text="", justify="left")
        self.result_label.grid(row=current_row, column=0, columnspan=2, pady=10)
        internal_frame.grid_rowconfigure(current_row, weight=1)

        current_row += 1
        ttk.Button(internal_frame, text="Back", command=self.back_to_menu).grid(row=current_row, column=0, columnspan=2, pady=10)
        internal_frame.grid_rowconfigure(current_row, weight=1)
        
        internal_frame.grid_columnconfigure(0, weight=1)
        internal_frame.grid_columnconfigure(1, weight=1)

    def show_find_subnet_id(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "example": "e.g., 192.168.0.1"},
            {"label": "Subnet Mask:", "example": "e.g., 255.255.255.0"}
        ]
        self.create_entry_fields(fields, self.calculate_subnet_id, "Calculate Subnet ID")

    def show_find_mask(self):
        self.clear_frame()
        fields = [
            {"label": "CIDR Notation:", "example": "e.g., 24"}
        ]
        self.create_entry_fields(fields, self.calculate_mask, "Calculate Subnet Mask")

    def show_subnets_required(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "example": "e.g., 192.168.0.1"},
            {"label": "Number of Subnets:", "example": "e.g., 4"}
        ]
        self.create_entry_fields(fields, self.calculate_subnets_required, "Calculate Subnet Address (Subnets)")

    def show_hosts_required(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "example": "e.g., 192.168.0.1"},
            {"label": "Number of Hosts:", "example": "e.g., 25"}
        ]
        self.create_entry_fields(fields, self.calculate_hosts_required, "Calculate Subnet Address (Hosts)")

    def show_subnets_with_host_bits(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "example": "e.g., 192.168.0.1"},
            {"label": "Number of Host Bits:", "example": "e.g., 5"}
        ]
        self.create_entry_fields(fields, self.calculate_subnets_with_host_bits, "Calculate Subnet Address (Host Bits)")

    def show_find_broadcast_id(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "example": "e.g., 192.168.0.1"},
            {"label": "Subnet Mask:", "example": "e.g., 255.255.255.0"}
        ]
        self.create_entry_fields(fields, self.calculate_broadcast_id, "Calculate Broadcast Address")

    def show_find_ip_range(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "example": "e.g., 192.168.0.1"},
            {"label": "Subnet Mask:", "example": "e.g., 255.255.255.0"}
        ]
        self.create_entry_fields(fields, self.calculate_ip_range, "Calculate IP Range")

    def show_find_number_of_hosts(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "example": "e.g., 192.168.0.1"},
            {"label": "Subnet Mask:", "example": "e.g., 255.255.255.0"}
        ]
        self.create_entry_fields(fields, self.calculate_number_of_hosts, "Calculate Number of Usable Hosts")

    def show_cidr_to_mask(self):
        self.clear_frame()
        fields = [
            {"label": "CIDR Notation:", "example": "e.g., 24"}
        ]
        self.create_entry_fields(fields, self.convert_cidr_to_mask, "Convert CIDR to Subnet Mask")

    def show_mask_to_cidr_ipv4(self):
        self.clear_frame()
        fields = [
            {"label": "IPv4 Subnet Mask:", "example": "e.g., 255.255.255.0"}
        ]
        self.create_entry_fields(fields, self.convert_mask_to_cidr, "Convert Subnet Mask to CIDR (IPv4)")

    def show_check_ip_in_subnet(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "example": "e.g., 192.168.0.10"},
            {"label": "Subnet Address/Mask:", "example": "e.g., 192.168.0.0/24"}
        ]
        self.create_entry_fields(fields, self.check_ip_in_subnet, "Check if IP is in Subnet")

    def show_calculate_wildcard_mask_ipv4(self):
        self.clear_frame()
        fields = [
            {"label": "IPv4 Subnet Mask:", "example": "e.g., 255.255.255.0"}
        ]
        self.create_entry_fields(fields, self.calculate_wildcard_mask, "Calculate Wildcard Mask (IPv4)")

    def show_validate_ip(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "example": "e.g., 192.168.0.1"}
        ]
        self.create_entry_fields(fields, self.validate_ip, "Validate IP Address")

    def show_validate_subnet_mask_ipv4(self):
        self.clear_frame()
        fields = [
            {"label": "IPv4 Subnet Mask:", "example": "e.g., 255.255.255.0"}
        ]
        self.create_entry_fields(fields, self.validate_subnet_mask, "Validate Subnet Mask (IPv4)")

    def show_calculate_supernet_ipv4(self):
        self.clear_frame()
        fields = [
            {"label": "IPv4 Address:", "example": "e.g., 192.168.0.0"},
            {"label": "IPv4 Subnet Mask:", "example": "e.g., 255.255.255.0"}
        ]
        self.create_entry_fields(fields, self.calculate_supernet_ipv4, "Calculate Supernet (IPv4)")

    def show_calculate_supernet_ipv6(self):
        self.clear_frame()
        fields = [
            {"label": "IPv6 Address:", "example": "e.g., 2001:db8:abcd::"},
            {"label": "Prefix Length:", "example": "e.g., 48"}
        ]
        self.create_entry_fields(fields, self.calculate_supernet_ipv6, "Calculate Supernet (IPv6)")

    def show_find_network_address(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "example": "e.g., 192.168.0.10"},
            {"label": "Subnet Mask:", "example": "e.g., 255.255.255.0"}
        ]
        self.create_entry_fields(fields, self.find_network_address, "Find Network Address")

    def show_find_first_usable_ip(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "example": "e.g., 192.168.0.10"},
            {"label": "Subnet Mask:", "example": "e.g., 255.255.255.0"}
        ]
        self.create_entry_fields(fields, self.find_first_usable_ip, "Find First Usable IP Address")

    def show_find_last_usable_ip(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "example": "e.g., 192.168.0.10"},
            {"label": "Subnet Mask:", "example": "e.g., 255.255.255.0"}
        ]
        self.create_entry_fields(fields, self.find_last_usable_ip, "Find Last Usable IP Address")

    def show_calculate_prefix_length_ipv4(self):
        self.clear_frame()
        fields = [
            {"label": "IPv4 Subnet Mask:", "example": "e.g., 255.255.255.0"}
        ]
        self.create_entry_fields(fields, self.calculate_prefix_length, "Calculate Prefix Length (from IPv4 Mask)")

    def show_check_public_private_ip(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "example": "e.g., 192.168.0.1"}
        ]
        self.create_entry_fields(fields, self.check_public_private_ip, "Check if IP is Public or Private")

    def show_find_default_gateway(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "example": "e.g., 192.168.0.10"},
            {"label": "Subnet Mask:", "example": "e.g., 255.255.255.0"}
        ]
        self.create_entry_fields(fields, self.find_default_gateway, "Find Default Gateway")

    def show_check_ips_same_subnet(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address 1:", "example": "e.g., 192.168.0.10"},
            {"label": "IP Address 2:", "example": "e.g., 192.168.0.20"}
        ]
        self.create_entry_fields(fields, self.check_ips_same_subnet, "Check if Two IPs are in Same Subnet")

    def show_generate_random_ip(self):
        self.clear_frame()
        fields = [
            {"label": "Subnet Address/Mask:", "tooltip": "e.g., 192.168.0.0/24 or 10.0.0.0/255.0.0.0"}
        ]
        self.create_entry_fields(fields, self.generate_random_ip, "Generate Random IP Address")

    def show_generate_random_subnet_mask(self):
        self.clear_frame()
        fields = [
            {"label": "CIDR Notation:", "example": "e.g., 24 (0-32)"}
        ]
        self.create_entry_fields(fields, self.generate_random_subnet_mask, "Generate Random Subnet Mask")

    def show_ip_to_binary(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "example": "e.g., 192.168.0.1"}
        ]
        self.create_entry_fields(fields, self.ip_to_binary, "Convert IP Address to Binary")

    def show_binary_to_ip(self):
        self.clear_frame()
        fields = [
            {"label": "Binary String:", "example": "e.g., c0a80001 (Hexadecimal representation of IP)"}
        ]
        self.create_entry_fields(fields, self.binary_to_ip, "Convert Binary to IP Address")

    def show_find_ipv6_subnet_id(self):
        self.clear_frame()
        fields = [
            {"label": "IPv6 Address:", "example": "e.g., 2001:db8::1"},
            {"label": "Prefix Length:", "example": "e.g., 64"}
        ]
        self.create_entry_fields(fields, self.calculate_ipv6_subnet_id, "Calculate IPv6 Subnet ID")

    def show_calculate_ipv6_prefix_length(self):
        self.clear_frame()
        fields = [
            {"label": "IPv6 Subnet Mask:", "example": "e.g., ffff:ffff:ffff:ffff::"}
        ]
        self.create_entry_fields(fields, self.calculate_ipv6_prefix_length, "Calculate IPv6 Prefix Length")

    def show_find_ipv6_network_address(self):
        self.clear_frame()
        fields = [
            {"label": "IPv6 Address:", "example": "e.g., 2001:db8::1"},
            {"label": "Prefix Length:", "example": "e.g., 64"}
        ]
        self.create_entry_fields(fields, self.find_ipv6_network_address, "Find IPv6 Network Address")

    def show_check_ipv6_in_subnet(self):
        self.clear_frame()
        fields = [
            {"label": "IPv6 Address:", "example": "e.g., 2001:db8::10"},
            {"label": "IPv6 Subnet Address/Prefix:", "example": "e.g., 2001:db8::/64"}
        ]
        self.create_entry_fields(fields, self.check_ipv6_in_subnet, "Check if IP is in Subnet (IPv6)")

    def show_generate_random_ipv6(self):
        self.clear_frame()
        fields = [
            {"label": "Prefix Length:", "example": "e.g., 64 (0-128)"}
        ]
        self.create_entry_fields(fields, self.generate_random_ipv6, "Generate Random IPv6 Address")

    def show_ipv6_to_binary(self):
        self.clear_frame()
        fields = [
            {"label": "IPv6 Address:", "example": "e.g., 2001:db8::1"}
        ]
        self.create_entry_fields(fields, self.ipv6_to_binary, "Convert IPv6 Address to Binary")

    def show_binary_to_ipv6(self):
        self.clear_frame()
        fields = [
            {"label": "Binary String:", "example": "e.g., 20010db8000000000000000000000001 (Hex representation)"}
        ]
        self.create_entry_fields(fields, self.binary_to_ipv6, "Convert Binary to IPv6 Address")

    def show_check_unicast(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "tooltip": "Enter IPv4 or IPv6 address", "example": "e.g., 192.168.0.1 or 2001:db8::1"}
        ]
        self.create_entry_fields(fields, self.check_unicast, "Check if IP Address is Unicast (IPv4/IPv6)")

    def show_check_unique_local(self):
        self.clear_frame()
        fields = [
            {"label": "IP Address:", "tooltip": "Enter IPv4 or IPv6 address", "example": "e.g., 192.168.0.1 or fc00::1"}
        ]
        self.create_entry_fields(fields, self.check_unique_local, "Check if IP Address is Unique Local (IPv4/IPv6)")

    def calculate_subnet_id(self):
        ip = self.entries[0].get()
        mask = self.entries[1].get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label.config(text=f"Subnet ID: {network.network_address}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_mask(self):
        cidr_str = self.entries[0].get()
        try:
            cidr = int(cidr_str)
            if not (0 <= cidr <= 32):
                self.result_label.config(text="Error: CIDR must be an integer between 0 and 32.")
                return
            mask = ipaddress.IPv4Network(f"0.0.0.0/{cidr}").netmask
            self.result_label.config(text=f"Subnet Mask: {mask}")
        except ValueError:
            self.result_label.config(text="Error: CIDR must be a valid integer.")
        except Exception as e: # Catch other potential errors from ipaddress module
            self.result_label.config(text=f"Error: {e}")

    def calculate_subnets_required(self):
        ip_str = self.entries[0].get()
        subnets_str = self.entries[1].get()
        try:
            subnets = int(subnets_str)
            if subnets <= 0:
                self.result_label.config(text="Error: Number of subnets must be a positive integer.")
                return
            
            network = ipaddress.IPv4Network(ip_str, strict=False) # Validates ip_str
            new_prefix = network.prefixlen + (subnets - 1).bit_length()
            if new_prefix > 32:
                # This error is specific and clear.
                self.result_label.config(text="Error: Too many subnets required for the given IP network space.")
                return
            self.result_label.config(text=f"New Subnet Address: {network.network_address}/{new_prefix}")
        except ValueError as e:
            # Check if error is from int() conversion or ipaddress module
            if "invalid literal for int()" in str(e):
                self.result_label.config(text="Error: Number of subnets must be a valid integer.")
            else: # Error from ipaddress module or custom ValueError
                self.result_label.config(text=f"Error: {e}")
        except Exception as e:
            self.result_label.config(text=f"An unexpected error occurred: {e}")

    def calculate_hosts_required(self):
        ip_str = self.entries[0].get()
        hosts_str = self.entries[1].get()
        try:
            hosts = int(hosts_str)
            if hosts <= 0:
                self.result_label.config(text="Error: Number of hosts must be a positive integer.")
                return

            network = ipaddress.IPv4Network(ip_str, strict=False) # Validates ip_str
            
            # Calculate bits needed for hosts + network/broadcast
            required_host_bits = (hosts + 2 -1 ).bit_length() if hosts > 0 else 0 # (hosts + 2 - 1).bit_length() is more robust for powers of 2
            if hosts + 2 < 0: # Overflow check, though unlikely with positive hosts
                 required_host_bits = 32 # Will lead to error

            new_prefix = 32 - required_host_bits
            
            if new_prefix < 0 : # e.g. too many hosts requested than possible in IPv4
                self.result_label.config(text="Error: Too many hosts required for IPv4 address space.")
                return
            if new_prefix < network.prefixlen: # Check if new prefix is smaller than original
                 self.result_label.config(text="Error: Too many hosts required for the given IP network space.")
                 return
            self.result_label.config(text=f"New Subnet Address: {network.network_address}/{new_prefix}")
        except ValueError as e:
            if "invalid literal for int()" in str(e):
                self.result_label.config(text="Error: Number of hosts must be a valid integer.")
            else:
                self.result_label.config(text=f"Error: {e}")
        except Exception as e:
            self.result_label.config(text=f"An unexpected error occurred: {e}")

    def calculate_subnets_with_host_bits(self):
        ip_str = self.entries[0].get()
        host_bits_str = self.entries[1].get()
        try:
            host_bits = int(host_bits_str)
            if not (0 <= host_bits <= 30): # Sensible range for host bits (e.g. /32 has 0, /2 has 30)
                                          # /31 and /32 are special, usually not defined by host bits.
                                          # A /0 network means 32 host bits, /1 means 31 host bits. Max usable prefix is /30 for traditional N-2 hosts.
                self.result_label.config(text="Error: Number of host bits must be an integer between 0 and 30 for typical networks.")
                return

            network = ipaddress.IPv4Network(ip_str, strict=False) # Validates ip_str
            new_prefix = 32 - host_bits
            
            # Check if the new prefix is valid in context of original network (optional, but good)
            # For example, if original is /24, new_prefix must be >= 24.
            # This function's purpose is usually to find a subnet mask given an IP and desired host bits.
            # So, the new_prefix must be valid for IPv4.
            if new_prefix < network.prefixlen and new_prefix >=0 : # Allow expanding network if that's the intent, but typically it's for subnetting
                 pass # This is fine, effectively means we are changing the network definition based on host bits.

            if not (0 <= new_prefix <= 32): # Final check on prefix validity
                 self.result_label.config(text="Error: Calculated prefix based on host bits is invalid.")
                 return

            self.result_label.config(text=f"New Subnet Address: {network.network_address}/{new_prefix}")
        except ValueError as e:
            if "invalid literal for int()" in str(e):
                self.result_label.config(text="Error: Number of host bits must be a valid integer.")
            else:
                self.result_label.config(text=f"Error: {e}")
        except Exception as e:
            self.result_label.config(text=f"An unexpected error occurred: {e}")

    def calculate_broadcast_id(self):
        ip = self.entries[0].get()
        mask = self.entries[1].get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label.config(text=f"Broadcast Address: {network.broadcast_address}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_ip_range(self):
        ip = self.entries[0].get()
        mask = self.entries[1].get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label.config(text=f"IP Range: {network.network_address} - {network.broadcast_address}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_number_of_hosts(self):
        ip_str = self.entries[0].get()
        mask_str = self.entries[1].get()
        try:
            # Validate IP and mask by attempting to create the network object.
            # strict=False allows host bits to be set in the IP address part.
            network = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)

            if network.prefixlen == 32:
                self.result_label.config(text="Number of Usable Hosts: 1 (host address itself)")
            elif network.prefixlen == 31:
                self.result_label.config(text="Number of Usable Hosts: 2 (for point-to-point links)")
            else: # For prefixes < /31
                # Traditional calculation: network and broadcast addresses are unusable.
                # network.num_addresses includes network and broadcast.
                if network.num_addresses < 2: # Should not happen for prefixlen < 31
                    usable_hosts = 0 
                else:
                    usable_hosts = network.num_addresses - 2
                self.result_label.config(text=f"Number of Usable Hosts: {usable_hosts}")
        
        except ValueError as e: # Catches errors from IPv4Network if IP/mask is invalid
            self.result_label.config(text=f"Error: Invalid IP address or subnet mask. {e}")
        except Exception as e: # Catch any other unexpected errors
            self.result_label.config(text=f"An unexpected error occurred: {e}")

    def convert_cidr_to_mask(self):
        cidr_str = self.entries[0].get()
        try:
            cidr = int(cidr_str)
            if not (0 <= cidr <= 32):
                self.result_label.config(text="Error: CIDR must be an integer between 0 and 32.")
                return
            mask = ipaddress.IPv4Network(f"0.0.0.0/{cidr}").netmask
            self.result_label.config(text=f"Subnet Mask: {mask}")
        except ValueError:
            self.result_label.config(text="Error: CIDR must be a valid integer.")
        except Exception as e: # Catch other potential errors from ipaddress module
            self.result_label.config(text=f"Error: {e}")

    def convert_mask_to_cidr(self):
        mask = self.entries[0].get()
        try:
            cidr = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
            self.result_label.config(text=f"CIDR Notation: /{cidr}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def check_ip_in_subnet(self):
        ip = self.entries[0].get()
        subnet = self.entries[1].get()
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            ip_addr = ipaddress.ip_address(ip)
            self.result_label.config(text=f"IP is in subnet: {ip_addr in network}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_wildcard_mask(self):
        mask = self.entries[0].get()
        try:
            network = ipaddress.IPv4Network(f"0.0.0.0/{mask}")
            wildcard = ipaddress.IPv4Address(int(network.hostmask))
            self.result_label.config(text=f"Wildcard Mask: {wildcard}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def validate_ip(self):
        ip = self.entries[0].get()
        try:
            ipaddress.ip_address(ip)
            self.result_label.config(text="IP Address is valid.")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def validate_subnet_mask(self): # Renamed to validate_subnet_mask_ipv4 in function_dict
        mask_str = self.entries[0].get()
        try:
            # Attempt to create a network with the mask to validate it.
            # This implicitly checks if it's a valid IPv4 mask.
            ipaddress.IPv4Network(f"0.0.0.0/{mask_str}", strict=True)
            self.result_label.config(text="IPv4 Subnet Mask is valid.")
        except ValueError: # Catches invalid mask format or value
            try: # Check if it's a CIDR prefix length
                prefix = int(mask_str)
                if 0 <= prefix <= 32:
                     ipaddress.IPv4Network(f"0.0.0.0/{prefix}", strict=True)
                     self.result_label.config(text="IPv4 CIDR Prefix is valid.")
                else:
                    self.result_label.config(text="Error: IPv4 CIDR prefix out of range (0-32).")
            except ValueError: # Not an int, and not a valid mask string
                 self.result_label.config(text="Error: Invalid IPv4 Subnet Mask format.")
        except Exception as e: # Other errors
            self.result_label.config(text=f"Error: {e}")


    def calculate_supernet_ipv4(self): # Renamed from calculate_supernet
        ip_str = self.entries[0].get()
        mask_str = self.entries[1].get()
        try:
            network_str = f"{ip_str}/{mask_str}"
            # Validate IP and mask separately for clearer errors potentially
            ipaddress.IPv4Address(ip_str) # Validate IP
            # Validate mask (can be CIDR or full mask)
            try:
                # Check if mask_str is CIDR
                prefix = int(mask_str)
                if not (0 <= prefix <= 32):
                    raise ValueError("CIDR prefix out of range")
            except ValueError:
                # If not CIDR, assume it's a full mask and let IPv4Network validate
                ipaddress.IPv4Address(mask_str) # quick check if it's a valid IP format for a mask

            network = ipaddress.IPv4Network(network_str, strict=False)
            self.result_label.config(text=f"Supernet (IPv4): {network.supernet()}")
        except ValueError as e:
            self.result_label.config(text=f"Error: Invalid IPv4 address or mask. {e}")
        except Exception as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_supernet_ipv6(self):
        ip_str = self.entries[0].get()
        prefix_str = self.entries[1].get()
        try:
            prefix = int(prefix_str)
            if not (0 <= prefix <= 128):
                self.result_label.config(text="Error: IPv6 Prefix Length must be an integer between 0 and 128.")
                return
            
            ipaddress.IPv6Address(ip_str) # Validate IPv6 address format

            network = ipaddress.IPv6Network(f"{ip_str}/{prefix}", strict=False)
            self.result_label.config(text=f"Supernet (IPv6): {network.supernet()}")
        except ValueError: # Catches int conversion, prefix range, IPv6Address, IPv6Network errors
            self.result_label.config(text="Error: Invalid IPv6 address or prefix length.")
        except Exception as e:
            self.result_label.config(text=f"Error: {e}")

    def find_network_address(self):
        ip = self.entries[0].get()
        mask = self.entries[1].get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label.config(text=f"Network Address: {network.network_address}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def find_first_usable_ip(self):
        ip = self.entries[0].get()
        mask = self.entries[1].get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label.config(text=f"First Usable IP: {network.network_address + 1}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def find_last_usable_ip(self):
        ip = self.entries[0].get()
        mask = self.entries[1].get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            self.result_label.config(text=f"Last Usable IP: {network.broadcast_address - 1}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_prefix_length(self): # Renamed to calculate_prefix_length_ipv4 in function_dict
        mask_str = self.entries[0].get()
        try:
            # This function expects an IPv4 subnet mask.
            # We can validate by attempting to create a network with it.
            # Using 0.0.0.0 as a base is a common way to validate/convert a mask.
            network = ipaddress.IPv4Network(f"0.0.0.0/{mask_str}", strict=True)
            self.result_label.config(text=f"Prefix Length: /{network.prefixlen}")
        except ValueError:
            # Check if it's a valid CIDR prefix itself
            try:
                prefix = int(mask_str)
                if 0 <= prefix <= 32:
                    self.result_label.config(text=f"Prefix Length: /{prefix}")
                else:
                    self.result_label.config(text="Error: Invalid IPv4 Subnet Mask or CIDR prefix out of range.")
            except ValueError: # Not an int, and not a valid mask string
                self.result_label.config(text="Error: Invalid IPv4 Subnet Mask format.")
        except Exception as e:
            self.result_label.config(text=f"Error: {e}")


    def check_public_private_ip(self):
        ip = self.entries[0].get()
        try:
            ip_addr = ipaddress.ip_address(ip)
            if ip_addr.is_private:
                self.result_label.config(text="IP Address is private.")
            else:
                self.result_label.config(text="IP Address is public.")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def find_default_gateway(self):
        ip = self.entries[0].get()
        mask = self.entries[1].get()
        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            default_gateway = network.network_address + 1
            self.result_label.config(text=f"Default Gateway: {default_gateway}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def check_ips_same_subnet(self):
        ip1 = self.entries[0].get()
        ip2 = self.entries[1].get()
        try:
            ip_addr1 = ipaddress.ip_address(ip1)
            ip_addr2 = ipaddress.ip_address(ip2)
            self.result_label.config(text=f"IPs in same subnet: {ip_addr1.network == ip_addr2.network}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def generate_random_ip(self):
        subnet_str = self.entries[0].get()
        try:
            network = ipaddress.ip_network(subnet_str, strict=False) # Validates input format

            if not isinstance(network, ipaddress.IPv4Network):
                self.result_label.config(text="Error: Input must be an IPv4 subnet (e.g., 192.168.1.0/24).")
                return

            if network.prefixlen == 32:
                self.result_label.config(text=f"Host IP: {network.network_address}")
            elif network.prefixlen == 31:
                # For /31, both addresses are considered usable for point-to-point
                ips = [network.network_address, network.network_address + 1]
                random_ip = random.choice(ips)
                self.result_label.config(text=f"Point-to-Point IP: {random_ip}")
            else: # prefixlen < 31
                # network.hosts() generator is empty for /31 and /32
                # For < /31, it correctly yields usable hosts.
                # We calculate manually to be explicit and avoid list conversion.
                first_usable_host = network.network_address + 1
                last_usable_host = network.broadcast_address - 1
                
                num_usable_hosts = int(last_usable_host) - int(first_usable_host) + 1

                if num_usable_hosts <= 0:
                    # This case should ideally not be reached if prefixlen < 31
                    self.result_label.config(text="Error: No usable host IP addresses in this subnet.")
                    return
                
                offset = random.randint(0, num_usable_hosts - 1)
                random_ip_int = int(first_usable_host) + offset
                random_ip = ipaddress.IPv4Address(random_ip_int)
                self.result_label.config(text=f"Random IP Address: {random_ip}")

        except ValueError as e: # Catches parsing errors from ip_network or IPv4Address
            self.result_label.config(text=f"Error: Invalid subnet format or IP address. {e}")
        except Exception as e: # Catch any other unexpected errors
            self.result_label.config(text=f"An unexpected error occurred: {e}")

    def generate_random_subnet_mask(self):
        cidr_str = self.entries[0].get()
        try:
            cidr = int(cidr_str)
            if not (0 <= cidr <= 32):
                self.result_label.config(text="Error: CIDR must be an integer between 0 and 32.")
                return
            network = ipaddress.IPv4Network(f"0.0.0.0/{cidr}")
            self.result_label.config(text=f"Random Subnet Mask: {network.netmask}")
        except ValueError:
            self.result_label.config(text="Error: CIDR must be a valid integer.")
        except Exception as e: # Catch other potential errors from ipaddress module
            self.result_label.config(text=f"Error: {e}")

    def ip_to_binary(self):
        ip = self.entries[0].get()
        try:
            ip_addr = ipaddress.ip_address(ip)
            self.result_label.config(text=f"Binary: {ip_addr.packed.hex()}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def binary_to_ip(self):
        binary_str = self.entries[0].get()
        try:
            ip_addr = ipaddress.ip_address(bytes.fromhex(binary_str))
            self.result_label.config(text=f"IP Address: {ip_addr}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def calculate_ipv6_subnet_id(self):
        ip = self.entries[0].get()
        prefix_str = self.entries[1].get()
        try:
            prefix = int(prefix_str)
            if not (0 <= prefix <= 128):
                self.result_label.config(text="Error: IPv6 Prefix Length must be an integer between 0 and 128.")
                return
            # Validate IP separately to give a more specific error if IP is wrong
            try:
                ip_addr = ipaddress.IPv6Address(ip)
            except ValueError:
                self.result_label.config(text=f"Error: Invalid IPv6 address format: {ip}")
                return
            
            network = ipaddress.IPv6Network(f"{ip_addr}/{prefix}", strict=False)
            self.result_label.config(text=f"IPv6 Subnet ID: {network.network_address}")
        except ValueError as e: # Catches issues from int(), IPv6Address, or IPv6Network.
            if "invalid literal for int()" in str(e):
                 self.result_label.config(text="Error: IPv6 Prefix Length must be a valid integer.")
            elif "Expected 8 groups" in str(e) or "is not a valid IPv6 address" in str(e) : # More specific to ipaddress.IPv6Address
                 self.result_label.config(text=f"Error: Invalid IPv6 address format. {e}")
            else: # General for other ValueErrors from ipaddress or logic
                 self.result_label.config(text=f"Error: Invalid IPv6 address or prefix. {e}")
        except Exception as e: # Catch other potential errors
            self.result_label.config(text=f"An unexpected error occurred: {e}")

    def calculate_ipv6_prefix_length(self):
        mask = self.entries[0].get()
        try:
            prefix_length = ipaddress.IPv6Network(f"::/{mask}").prefixlen
            self.result_label.config(text=f"IPv6 Prefix Length: /{prefix_length}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def find_ipv6_network_address(self):
        ip = self.entries[0].get()
        prefix_str = self.entries[1].get()
        try:
            prefix = int(prefix_str)
            if not (0 <= prefix <= 128):
                self.result_label.config(text="Error: IPv6 Prefix Length must be an integer between 0 and 128.")
                return
            # Validate IP separately
            try:
                ip_addr = ipaddress.IPv6Address(ip)
            except ValueError:
                self.result_label.config(text=f"Error: Invalid IPv6 address format: {ip}")
                return

            network = ipaddress.IPv6Network(f"{ip_addr}/{prefix}", strict=False)
            self.result_label.config(text=f"IPv6 Network Address: {network.network_address}")
        except ValueError as e: # Catches issues from int(), IPv6Address, or IPv6Network.
            if "invalid literal for int()" in str(e):
                 self.result_label.config(text="Error: IPv6 Prefix Length must be a valid integer.")
            elif "Expected 8 groups" in str(e) or "is not a valid IPv6 address" in str(e):
                 self.result_label.config(text=f"Error: Invalid IPv6 address format. {e}")
            else:
                 self.result_label.config(text=f"Error: Invalid IPv6 address or prefix. {e}")
        except Exception as e: # Catch other potential errors
            self.result_label.config(text=f"An unexpected error occurred: {e}")

    def check_ipv6_in_subnet(self):
        ip = self.entries[0].get()
        subnet = self.entries[1].get()
        try:
            network = ipaddress.IPv6Network(subnet, strict=False)
            ip_addr = ipaddress.IPv6Address(ip)
            self.result_label.config(text=f"IPv6 is in subnet: {ip_addr in network}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def generate_random_ipv6(self):
        prefix_str = self.entries[0].get()
        try:
            prefix = int(prefix_str)
            if not (0 <= prefix <= 128):
                self.result_label.config(text="Error: IPv6 Prefix Length must be an integer between 0 and 128.")
                return

            # Using ::/prefix as the base network for random generation
            # If a specific network base (e.g. 2001:db8::) is desired, input field would need to change.
            network = ipaddress.IPv6Network(f"::/{prefix}", strict=False)

            if prefix == 128:
                self.result_label.config(text=f"Host IPv6 Address: {network.network_address}")
            elif prefix == 127:
                # For /127, both addresses are typically usable in point-to-point links
                ips = [network.network_address, network.network_address + 1]
                random_ip = random.choice(ips)
                self.result_label.config(text=f"Point-to-Point IPv6: {random_ip}")
            else: # prefix < 127
                # For IPv6, typically the whole range is usable, no separate broadcast.
                # The network.network_address is the first address.
                # network.num_addresses gives the total count.
                if network.num_addresses <= 0: # Should not happen for prefix < 127
                    self.result_label.config(text="Error: Invalid or too small network for random generation.")
                    return
                
                # Generate an offset within the entire range of the network
                # For IPv6, it's common to use any address in the range.
                # Unlike IPv4, there isn't a strict concept of "network address" and "broadcast address"
                # that are unusable for hosts in the same way.
                # The first address is network.network_address.
                # The last address is network.broadcast_address (which is network.network_address + num_addresses - 1)
                
                offset = random.randint(0, network.num_addresses - 1)
                random_ip_int = int(network.network_address) + offset
                random_ip = ipaddress.IPv6Address(random_ip_int)
                self.result_label.config(text=f"Random IPv6 Address: {random_ip}")

        except ValueError: # Catches issues from int(prefix_str)
            self.result_label.config(text="Error: IPv6 Prefix Length must be a valid integer.")
        except Exception as e: # Catch other potential errors (e.g., from ipaddress module)
            self.result_label.config(text=f"An unexpected error occurred: {e}")


    def ipv6_to_binary(self):
        ip = self.entries[0].get()
        try:
            ip_addr = ipaddress.IPv6Address(ip)
            self.result_label.config(text=f"Binary: {ip_addr.packed.hex()}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def binary_to_ipv6(self):
        binary_str = self.entries[0].get()
        try:
            ip_addr = ipaddress.IPv6Address(bytes.fromhex(binary_str))
            self.result_label.config(text=f"IPv6 Address: {ip_addr}")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def check_unicast(self):
        ip = self.entries[0].get()
        try:
            ip_addr = ipaddress.ip_address(ip)
            if ip_addr.is_global:
                self.result_label.config(text="IP Address is a global unicast address.")
            else:
                self.result_label.config(text="IP Address is not a global unicast address.")
        except ValueError as e:
            self.result_label.config(text=f"Error: {e}")

    def check_unique_local(self):
        ip = self.entries[0].get()
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
