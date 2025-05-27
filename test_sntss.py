import unittest
import tkinter as tk
from sntss import SNTSS
import ipaddress # For IP validation in tests

class TestSntssFunctions(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw() # Hide the Tkinter window
        self.app = SNTSS(self.root)

    def tearDown(self):
        self.root.destroy()

    # --- Tests for calculate_number_of_hosts ---
    def test_calculate_number_of_hosts_slash_32(self):
        self.app.show_find_number_of_hosts() # Sets up self.app.entries
        self.app.entries[0].insert(0, "192.168.1.1")
        self.app.entries[1].insert(0, "255.255.255.255") # or /32
        self.app.calculate_number_of_hosts()
        self.assertEqual(self.app.result_label.cget("text"), "Number of Usable Hosts: 1 (host address itself)")

    def test_calculate_number_of_hosts_slash_32_cidr(self):
        self.app.show_find_number_of_hosts()
        self.app.entries[0].insert(0, "192.168.1.1")
        self.app.entries[1].insert(0, "32")
        self.app.calculate_number_of_hosts()
        self.assertEqual(self.app.result_label.cget("text"), "Number of Usable Hosts: 1 (host address itself)")

    def test_calculate_number_of_hosts_slash_31(self):
        self.app.show_find_number_of_hosts()
        self.app.entries[0].insert(0, "192.168.1.0")
        self.app.entries[1].insert(0, "255.255.255.254") # or /31
        self.app.calculate_number_of_hosts()
        self.assertEqual(self.app.result_label.cget("text"), "Number of Usable Hosts: 2 (for point-to-point links)")

    def test_calculate_number_of_hosts_slash_31_cidr(self):
        self.app.show_find_number_of_hosts()
        self.app.entries[0].insert(0, "192.168.1.0")
        self.app.entries[1].insert(0, "31")
        self.app.calculate_number_of_hosts()
        self.assertEqual(self.app.result_label.cget("text"), "Number of Usable Hosts: 2 (for point-to-point links)")

    def test_calculate_number_of_hosts_slash_30(self):
        self.app.show_find_number_of_hosts()
        self.app.entries[0].insert(0, "192.168.1.0")
        self.app.entries[1].insert(0, "255.255.255.252") # or /30
        self.app.calculate_number_of_hosts()
        self.assertEqual(self.app.result_label.cget("text"), "Number of Usable Hosts: 2")

    def test_calculate_number_of_hosts_slash_30_cidr(self):
        self.app.show_find_number_of_hosts()
        self.app.entries[0].insert(0, "192.168.1.0")
        self.app.entries[1].insert(0, "30")
        self.app.calculate_number_of_hosts()
        self.assertEqual(self.app.result_label.cget("text"), "Number of Usable Hosts: 2")

    def test_calculate_number_of_hosts_slash_24(self):
        self.app.show_find_number_of_hosts()
        self.app.entries[0].insert(0, "192.168.1.0")
        self.app.entries[1].insert(0, "255.255.255.0") # or /24
        self.app.calculate_number_of_hosts()
        self.assertEqual(self.app.result_label.cget("text"), "Number of Usable Hosts: 254")

    def test_calculate_number_of_hosts_slash_24_cidr(self):
        self.app.show_find_number_of_hosts()
        self.app.entries[0].insert(0, "192.168.1.0")
        self.app.entries[1].insert(0, "24")
        self.app.calculate_number_of_hosts()
        self.assertEqual(self.app.result_label.cget("text"), "Number of Usable Hosts: 254")

    def test_calculate_number_of_hosts_invalid_ip(self):
        self.app.show_find_number_of_hosts()
        self.app.entries[0].insert(0, "invalid_ip")
        self.app.entries[1].insert(0, "24")
        self.app.calculate_number_of_hosts()
        self.assertTrue(self.app.result_label.cget("text").startswith("Error: Invalid IP address or subnet mask."))

    def test_calculate_number_of_hosts_invalid_mask(self):
        self.app.show_find_number_of_hosts()
        self.app.entries[0].insert(0, "192.168.1.1")
        self.app.entries[1].insert(0, "invalid_mask")
        self.app.calculate_number_of_hosts()
        self.assertTrue(self.app.result_label.cget("text").startswith("Error: Invalid IP address or subnet mask."))
    
    def test_calculate_number_of_hosts_mask_out_of_range_cidr(self):
        self.app.show_find_number_of_hosts()
        self.app.entries[0].insert(0, "192.168.1.1")
        self.app.entries[1].insert(0, "33") # Invalid CIDR
        self.app.calculate_number_of_hosts()
        self.assertTrue(self.app.result_label.cget("text").startswith("Error: Invalid IP address or subnet mask."))


    # --- Tests for Input Validation (CIDR/Prefix Length) ---

    # Test calculate_mask (implicitly tests convert_cidr_to_mask's validation if shared)
    def test_calculate_mask_valid_cidr(self):
        self.app.show_find_mask() # Sets up self.app.entries for CIDR input
        self.app.entries[0].insert(0, "24")
        self.app.calculate_mask()
        self.assertEqual(self.app.result_label.cget("text"), "Subnet Mask: 255.255.255.0")

    def test_calculate_mask_invalid_cidr_non_integer(self):
        self.app.show_find_mask()
        self.app.entries[0].insert(0, "abc")
        self.app.calculate_mask()
        self.assertEqual(self.app.result_label.cget("text"), "Error: CIDR must be a valid integer.")

    def test_calculate_mask_invalid_cidr_out_of_range_too_high(self):
        self.app.show_find_mask()
        self.app.entries[0].insert(0, "33")
        self.app.calculate_mask()
        self.assertEqual(self.app.result_label.cget("text"), "Error: CIDR must be an integer between 0 and 32.")

    def test_calculate_mask_invalid_cidr_out_of_range_too_low(self):
        self.app.show_find_mask()
        self.app.entries[0].insert(0, "-1")
        self.app.calculate_mask()
        self.assertEqual(self.app.result_label.cget("text"), "Error: CIDR must be an integer between 0 and 32.")

    # Test calculate_ipv6_subnet_id (prefix validation part)
    def test_calculate_ipv6_subnet_id_valid_inputs(self):
        self.app.show_find_ipv6_subnet_id()
        self.app.entries[0].insert(0, "2001:db8::1")
        self.app.entries[1].insert(0, "64")
        self.app.calculate_ipv6_subnet_id()
        self.assertEqual(self.app.result_label.cget("text"), "IPv6 Subnet ID: 2001:db8::")

    def test_calculate_ipv6_subnet_id_invalid_prefix_non_integer(self):
        self.app.show_find_ipv6_subnet_id()
        self.app.entries[0].insert(0, "2001:db8::1")
        self.app.entries[1].insert(0, "abc")
        self.app.calculate_ipv6_subnet_id()
        self.assertEqual(self.app.result_label.cget("text"), "Error: IPv6 Prefix Length must be a valid integer.")

    def test_calculate_ipv6_subnet_id_invalid_prefix_out_of_range(self):
        self.app.show_find_ipv6_subnet_id()
        self.app.entries[0].insert(0, "2001:db8::1")
        self.app.entries[1].insert(0, "129")
        self.app.calculate_ipv6_subnet_id()
        self.assertEqual(self.app.result_label.cget("text"), "Error: IPv6 Prefix Length must be an integer between 0 and 128.")

    def test_calculate_ipv6_subnet_id_invalid_ipv6_address(self):
        self.app.show_find_ipv6_subnet_id()
        self.app.entries[0].insert(0, "invalid-ipv6")
        self.app.entries[1].insert(0, "64")
        self.app.calculate_ipv6_subnet_id()
        self.assertTrue(self.app.result_label.cget("text").startswith("Error: Invalid IPv6 address format."))
    
    # --- Tests for Random IP Generation ---

    # generate_random_ip (IPv4)
    def test_generate_random_ip_slash_32(self):
        self.app.show_generate_random_ip()
        self.app.entries[0].insert(0, "192.168.1.1/32")
        self.app.generate_random_ip()
        self.assertEqual(self.app.result_label.cget("text"), "Host IP: 192.168.1.1")

    def test_generate_random_ip_slash_31(self):
        self.app.show_generate_random_ip()
        self.app.entries[0].insert(0, "192.168.1.0/31")
        self.app.generate_random_ip()
        result_text = self.app.result_label.cget("text")
        self.assertTrue(result_text == "Point-to-Point IP: 192.168.1.0" or \
                        result_text == "Point-to-Point IP: 192.168.1.1")

    def test_generate_random_ip_slash_24(self):
        self.app.show_generate_random_ip()
        subnet_str = "192.168.1.0/24"
        self.app.entries[0].insert(0, subnet_str)
        self.app.generate_random_ip()
        result_text = self.app.result_label.cget("text")
        self.assertTrue(result_text.startswith("Random IP Address: "))
        generated_ip_str = result_text.replace("Random IP Address: ", "")
        
        network = ipaddress.ip_network(subnet_str, strict=False)
        first_host = network.network_address + 1
        last_host = network.broadcast_address - 1
        generated_ip = ipaddress.ip_address(generated_ip_str)
        
        self.assertTrue(first_host <= generated_ip <= last_host)

    def test_generate_random_ip_invalid_subnet_string(self):
        self.app.show_generate_random_ip()
        self.app.entries[0].insert(0, "invalid/subnet")
        self.app.generate_random_ip()
        self.assertTrue(self.app.result_label.cget("text").startswith("Error: Invalid subnet format or IP address."))

    # generate_random_ipv6
    def test_generate_random_ipv6_slash_128(self):
        self.app.show_generate_random_ipv6()
        self.app.entries[0].insert(0, "128")
        self.app.generate_random_ipv6()
        # Based on ::/128, the address is ::
        self.assertEqual(self.app.result_label.cget("text"), "Host IPv6 Address: ::")

    def test_generate_random_ipv6_slash_127(self):
        self.app.show_generate_random_ipv6()
        self.app.entries[0].insert(0, "127")
        self.app.generate_random_ipv6()
        result_text = self.app.result_label.cget("text")
        # Based on ::/127, IPs are :: and ::1
        self.assertTrue(result_text == "Point-to-Point IPv6: ::" or \
                        result_text == "Point-to-Point IPv6: ::1")
        
    def test_generate_random_ipv6_slash_64(self):
        self.app.show_generate_random_ipv6()
        prefix_len = "64"
        self.app.entries[0].insert(0, prefix_len)
        self.app.generate_random_ipv6()
        result_text = self.app.result_label.cget("text")
        self.assertTrue(result_text.startswith("Random IPv6 Address: "))
        generated_ip_str = result_text.replace("Random IPv6 Address: ", "")
        
        network = ipaddress.ip_network(f"::/{prefix_len}", strict=False)
        generated_ip = ipaddress.ip_address(generated_ip_str)
        
        self.assertIn(generated_ip, network) # Check if it belongs to the network

    def test_generate_random_ipv6_invalid_prefix_non_integer(self):
        self.app.show_generate_random_ipv6()
        self.app.entries[0].insert(0, "abc")
        self.app.generate_random_ipv6()
        self.assertEqual(self.app.result_label.cget("text"), "Error: IPv6 Prefix Length must be a valid integer.")

    def test_generate_random_ipv6_invalid_prefix_out_of_range(self):
        self.app.show_generate_random_ipv6()
        self.app.entries[0].insert(0, "129")
        self.app.generate_random_ipv6()
        self.assertEqual(self.app.result_label.cget("text"), "Error: IPv6 Prefix Length must be an integer between 0 and 128.")


if __name__ == '__main__':
    unittest.main()
