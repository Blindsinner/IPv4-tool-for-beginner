from __future__ import print_function
import sys

if sys.version_info[0] < 3:
    input = raw_input

try:
    import ipaddress
except ImportError:
    sys.exit("This code requires the 'ipaddress' library. Please install it using 'pip install ipaddress' and try again.")


# ANSI escape sequences for bold red text and reset
bold_red = "\033[1;31m"  # for errors
bold_green = "\033[1;32m"  # for successful responses
reset = "\033[0m"

# number of bits in an IPv4 address
ip_bits_total = 32
ip_octet = 8


def successful(text):
    """an easier way to print successful responses"""
    return "{}{}{}".format(bold_green, text, reset)


def error(text):
    """an easier way to print errors"""
    return "{}{}{}".format(bold_red, text, reset)


def binary_to_ip(binary_ip):
    """Convert a valid 32-bit value into an IPv4 address"""
    binary_ip = binary_ip.replace(".", "")
    octets = [binary_ip[i : i + ip_octet] for i in range(0, ip_bits_total, ip_octet)]
    try:
        return successful("Decimal IP: {}".format(".".join(str(int(octet, 2)) for octet in octets)))
    except ValueError:
        print(error("Error: Probably an incorrect binary value."))


def ip_to_binary(ip_address):
    """Convert an IPv4 address into its binary form"""
    try:
        ip = ipaddress.ip_address(ip_address)
        binary_ip = bin(int(ip)).replace("0b", "")
    except ValueError as ip_error:
        print(error(ip_error))
    else:
        binary_ip = binary_ip.rjust(ip_bits_total, "0")
        return successful(
            "{}".format(".".join([binary_ip[i : i + ip_octet] for i in range(0, ip_bits_total, ip_octet)]))
        )


def network_address(ip_address, subnet_mask):
    """Converts an IP Subnet into its CIDR notation equivalent"""
    try:
        ip = ipaddress.IPv4Interface("{}/{}".format(ip_address, subnet_mask))
    except ipaddress.AddressValueError:
        print(error("Error: Invalid subnet mask or IP address"))
    else:
        return str(successful("Network address with CIDR Notation: {}".format(ip.network)))


def cidr_to_subnet_mask(ip_address):
    """Converts IPAddress/CIDR into dotted-decimal-notation IPAddress/Subnet Mask"""
    try:
        network = ipaddress.IPv4Network(ip_address, strict=False)
    except ipaddress.AddressValueError:
        print(error("Error: Invalid subnet mask or IP address"))
    else:
        return str(
            successful("Network address: {}\nIP Subnet Mask: {}".format(network.network_address, network.netmask))
        )


def possible_number_of_subnets(ip_address, subnet_mask):
    try:
        ip = ipaddress.IPv4Network("{}/{}".format(ip_address, subnet_mask), strict=False)
    except ipaddress.AddressValueError:
        print(error("Error: Invalid subnet mask or IP address"))
    else:
               return successful("Possible Number of Subnets: {}".format(2 ** (ip_bits_total - ip.prefixlen)))

def ip_class_by_hosts(ip_address, subnet_mask_or_cidr):
    try:
        subnet_mask = int(subnet_mask_or_cidr)
        cidr = subnet_mask_or_cidr
    except ValueError:
        subnet_mask = subnet_mask_or_cidr
        cidr = ipaddress.IPv4Network(
            "{}/{}".format(ip_address, subnet_mask), strict=False
        ).prefixlen
    else:
        ip = ipaddress.IPv4Network("{}/{}".format(ip_address, cidr), strict=False)
        total_hosts = ip.num_addresses

        if total_hosts >= 2 ** 16:
            return "Class A"
        elif total_hosts >= 2 ** 8:
            return "Class B"
        else:
            return "Class C"

def ip_class_private_public(ip_address):
    """Is it a Private Address or Public Address? That's what this function answers"""
    try:
        ip = ipaddress.IPv4Address(ip_address)
    except ipaddress.AddressValueError:
        print(error("Error: Invalid Address"))
    else:
        first_octet = int(str(ip).split(".")[0])
        if first_octet >= 1 and first_octet <= 126:
            ip_class = "A"
        elif first_octet <= 191:
            ip_class = "B"
        elif first_octet <= 223:
            ip_class = "C"
        elif first_octet >= 224 and first_octet <= 239:
            ip_class = "D"
        else:
            ip_class = "E"
        if ip.is_private:
            return "{}{}{}".format(successful("According to first octet: Class "), ip_class, successful(", Private"))
        else:
            return "{}{}{}".format(successful("According to first octet: Class "), ip_class, successful(", Public"))

def display_all_info(ip_address, subnet_mask_or_cidr):
    try:
        subnet_mask = int(subnet_mask_or_cidr)
        cidr = subnet_mask_or_cidr
    except ValueError:
        subnet_mask = subnet_mask_or_cidr
        cidr = ipaddress.IPv4Network(
            "{}/{}".format(ip_address, subnet_mask), strict=False
        ).prefixlen

    ip_int = int(ipaddress.IPv4Address(ip_address))
    ip_hex = hex(ip_int)

    network = ipaddress.IPv4Network("{}/{}".format(ip_address, cidr), strict=False)
    total_hosts = network.num_addresses
    usable_hosts = total_hosts - 2
    first_address, last_address = list(network.hosts())[0], list(network.hosts())[-1]
    wildcard_mask = ipaddress.IPv4Address((~int(network.netmask)) & 0xFFFFFFFF)
    reverse_dns = ".".join(reversed(ip_address.split("."))) + ".in-addr.arpa"

    print(f"IP Address: {successful(ip_address)}")
    print(f"Subnet Mask: {successful(network.netmask)}")
    print(f"CIDR Notation: {successful(cidr)}")
    print(f"Network Address: {successful(network.network_address)}")
    print(f"Broadcast Address: {successful(network.broadcast_address)}")
    print(f"Network Address with CIDR Notation: {successful(network)}")
    print(f"Possible Number of Subnets: {successful(2 ** (ip_bits_total - int(cidr)))}")
    print(f"Total Number of Hosts: {successful(total_hosts)}")
    print(f"Number of Usable Hosts: {successful(usable_hosts)}")
    print(f"IP class and private/public:{successful(ip_class_private_public(ip_address))}")
    print(f"IP Class (based on total number of hosts): {successful(ip_class_by_hosts(ip_address, subnet_mask_or_cidr))}")
    print(f"Binary Version of IP: {ip_to_binary(ip_address)}")
    subnet_mask_str = str(ipaddress.IPv4Network(f'0.0.0.0/{cidr}', strict=False).netmask)
    print(f"Binary Subnet Mask: {successful('.'.join([bin(int(octet))[2:].rjust(8, '0') for octet in subnet_mask_str.split('.')]))}")
    print(f"Usable Host IP Range: {successful(f'{first_address} - {last_address}')}")
    print(f"Integer ID:\t{successful(ip_int)}")
    print(f"Hex ID:\t\t{successful(ip_hex)}")
    print(f"in-addr.arpa:\t{successful(reverse_dns)}")
    print(f"Wildcard Mask: {successful(wildcard_mask)}")
    print(f"IPv4 Mapped Address: {successful(ipaddress.IPv6Address(f'::ffff:{ip_address}'))}")
    print(successful(f"6to4 Prefix: 2002:{int(ip_address.split('.')[0]):02x}{int(ip_address.split('.')[1]):02x}:{int(ip_address.split('.')[2]):02x}{int(ip_address.split('.')[3]):02x}::/48"))

def main_menu():
    print("\nChoose an option:")
    print("1. Binary IP to Dotted Decimal Notation IP address")
    print("2. IP address to Binary")
    print("3. Find Network Address from IP and Subnet Mask")
    print("4. Find Network Address from IP/CIDR notation")
    print("5. Calculate Possible Subnetting from IP range")
    print("6. Determine IP Class and Private/Public Status")
    print("7. Display All Information for an IP Address and Subnet")
    print("8. Exit\n")


def run_tool():
    running = True
    while running:
        main_menu()
        try:
            choice = int(input("Enter the option number: "))
        except ValueError:
            print(error("Error: Use the options provided"))
        except (KeyboardInterrupt, EOFError):
            sys.exit(error("Exited"))
        else:
            try:
                if choice == 1:
                    # Binary to IP
                    binary_ip = input("Enter the binary IP address: ")
                    print(binary_to_ip(binary_ip))
                elif choice == 2:
                    # IP to binary
                    ip_address = input("Enter the IP address: ")
                    print(ip_to_binary(ip_address))
                elif choice == 3:
                    # network address from IP and Subnet Mask
                    ip_address = input("Enter the IP address: ")
                    subnet_mask = input("Enter the subnet mask: ")
                    print(network_address(ip_address, subnet_mask))
                elif choice == 4:
                    # network address from IP/CIDR
                    ip_address = input("Enter the IP address/CIDR: ")
                    print(cidr_to_subnet_mask(ip_address))
                elif choice == 5:
                    # possible number of subnets
                    ip_address = input("Enter the IP network: ")
                    subnet_mask = input("Enter the subnet mask or CIDR: ")
                    print(possible_number_of_subnets(ip_address, subnet_mask))
                elif choice == 6:
                    # is it a private or public IP address?
                    ip_address = input("Enter the IP address: ")
                    print(ip_class_private_public(ip_address))
                elif choice == 7:
                    # get a nice consolidated view on the IP address
                    ip_address = input("Enter the IP address: ")
                    subnet_mask_or_cidr = input("Enter the subnet mask or CIDR notation: ")
                    display_all_info(ip_address, subnet_mask_or_cidr)
                elif choice == 8:
                    # exit
                    sys.exit(successful('Exiting...'))
                else:
                    # input validation
                    print(error('Invalid option. Please try again.'))

            except (KeyboardInterrupt, EOFError):
                sys.exit(error("Exited"))

if __name__ == "__main__":
    run_tool()
