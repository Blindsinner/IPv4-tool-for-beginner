from ip_tool import error
from ip_tool import successful
from ip_tool import ip_class_private_public
from ip_tool import cidr_to_subnet_mask
from ip_tool import network_address
from ip_tool import ip_to_binary
from ip_tool import binary_to_ip
import sys
import unittest


class TestIPAddress(unittest.TestCase):
    """Single IP Address testings. Also check binary conversions"""

    def test_binary_to_ip(self):
        """Test conversion from binary to IPv4"""
        # test for class C IP addresses
        self.assertEqual(
            binary_to_ip("11000000.10101000.00001010.00000001"),
            successful("Decimal IP: 192.168.10.1"))
        # test for class B IP addresses
        self.assertEqual(
            binary_to_ip("10101100.00010000.00010100.00001010"),
            successful("Decimal IP: 172.16.20.10"))
        # test for class A IP addresses
        self.assertEqual(
            binary_to_ip("00001010.00001010.00000001.00000001"),
            successful("Decimal IP: 10.10.1.1"))

    def test_ip_to_binary(self):
        """Test conversion from IPv4 to binary"""
        self.assertEqual(ip_to_binary("10.10.1.1"), successful(
            "Binary IP Address: 00001010.00001010.00000001.00000001"))

        self.assertEqual(ip_to_binary("172.16.20.10"), successful(
            "Binary IP Address: 10101100.00010000.00010100.00001010"))

        self.assertEqual(ip_to_binary("192.168.10.1"), successful(
            "Binary IP Address: 11000000.10101000.00001010.00000001"))


class TestNetworkAddress(unittest.TestCase):
    def test_network_address(self):
        """Test conversion from IP Address and Dotted Decimal Notaion Subnet Mask to IPAddress/CIDR"""
        self.assertEqual(network_address("192.168.10.1", "255.255.255.0"),
                         successful("Network address with CIDR Notation: 192.168.10.0/24"))

    def test_cidr_to_subnet_mask(self):
        """Test conversion from IPAddress/CIDR to  IP Address and Dotted Decimal Notation Subnet Mask"""
        self.assertEqual(cidr_to_subnet_mask("172.16.30.15/25"),
                         successful("Network Address: 172.16.30.0\nSubnet Mask: 255.255.255.128"))


class TestIPClass(unittest.TestCase):
    def test_ip_private_class(self):
        """Checks if IP is private"""
        self.assertEqual(ip_class_private_public("10.50.200.5"),
                         successful("IP class and private/public: Class A, Private"))

        self.assertEqual(ip_class_private_public("172.16.40.21"),
                         successful("IP class and private/public: Class B, Private"))

        self.assertEqual(ip_class_private_public("192.168.100.10"),
                         successful("IP class and private/public: Class C, Private"))

    def test_ip_public_class(self):
        """Checks if IP is public"""
        self.assertEqual(ip_class_private_public("8.8.8.8"),
                         successful("IP class and private/public: Class A, Public"))

        self.assertEqual(ip_class_private_public("13.107.42.14"),
                         successful("IP class and private/public: Class A, Public"))

        self.assertEqual(ip_class_private_public("142.250.200.78"),
                         successful("IP class and private/public: Class B, Public"))

        self.assertEqual(ip_class_private_public("193.43.21.1"),
                         successful("IP class and private/public: Class C, Public"))


if __name__ == '__main__':
    unittest.main()
