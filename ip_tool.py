import ipaddress
import sys

# ANSI escape sequences for bold red text and reset
bold_red = "\033[1;31m"  # for errors
bold_green = "\033[1;32m"  # for successful responses
reset = "\033[0m"

# number of bits in an IPv4 address
ip_bits_total = 32
ip_octet = 8

def successful(text):
    """an easier way to print successful responses"""
    return f"{bold_green}{text}{reset}"

def error(text):
    """an easier way to print errors"""
    return f"{bold_red}{text}{reset}"

def binary_to_ip(binary_ip):
    """Convert a valid 32-bit value into an IPv4 address"""
    binary_ip = binary_ip.replace('.', '')
    octets = [binary_ip[i:i + ip_octet]
              for i in range(0, ip_bits_total, ip_octet)]
    try:
        return successful(f"Decimal IP: {'.'.join(str(int(octet, 2)) for octet in octets)}")
    except ValueError:
        print(error("Error: Probably an incorrect binary value."))

def ip_to_binary(ip_address):
    """Convert an IPv4 address into its binary form"""
    try:
        ip = ipaddress.ip_address(ip_address)
        binary_ip = bin(int(ip)).replace('0b', '')
    except ValueError as ip_error:
        print(error(ip_error))
    else:
        binary_ip = binary_ip.rjust(ip_bits_total, '0')
        return successful(f'{".".join([binary_ip[i:i+ip_octet] for i in range(0, ip_bits_total, ip_octet)])}')


def network_address(ip_address, subnet_mask):
    """Converts an IP Subnet into its CIDR notation equivalent"""
    try:
        ip = ipaddress.IPv4Interface(f"{ip_address}/{subnet_mask}")
    except ipaddress.AddressValueError:
        print(error("Error: Invalid subnet mask or IP address"))
    else:
        return str(successful(f'Network address with CIDR Notation: {ip.network}'))


def cidr_to_subnet_mask(ip_address):
    """Converts IPAddress/CIDR into dotted-decimal-notation IPAddress/Subnet Mask"""
    try:
        network = ipaddress.IPv4Network(ip_address, strict=False)
    except ipaddress.AddressValueError:
        print(error("Error: Invalid subnet mask or IP address"))
    else:
        return str(successful(f'Network Address: {network.network_address}\nSubnet Mask: {network.netmask}'))


def ip_range_info(ip_network, subnet_mask, new_prefix=None):
    try:
        ip = ipaddress.IPv4Network(f'{ip_network}/{subnet_mask}', strict=False)
    except ipaddress.AddressValueError:
        print(error("Error: Invalid subnet mask or IP address"))
    else:
        total_usable_ip_addr = [addr for addr in ip.hosts()]
        first_usable_ip = total_usable_ip_addr[0]
        last_usable_ip = total_usable_ip_addr[-1]

        # selectively return data if user chose to get the subnets and not just default info
        if new_prefix:
            # first subnet.
            first_usable_subnet = get_subnets(
                ip_network, subnet_mask, new_prefix)[0]
            # last subnet
            last_usable_subnet = get_subnets(
                ip_network, subnet_mask, new_prefix)[-1]
            # total number of subnets
            total_possible_subnets = len(get_subnets(
                ip_network, subnet_mask, new_prefix))
            # checks total assignable host addresses
            total_assignable_host_addresses = ipaddress.ip_network(get_subnets(
                ip_network, subnet_mask, new_prefix)[0]).num_addresses
            
            return {
                f'Total Subnets Possible with prefix /{new_prefix}': total_possible_subnets,
               'Total assignable IP Addresses per subnet': total_assignable_host_addresses,
                'First usable subnet': first_usable_subnet,
                'Last usable subnet': last_usable_subnet,
            }

        # default info
        return {
            'Possible Number of Subnets': f'{2 ** (ip_bits_total - ip.prefixlen)}',
            'Total Assignable IP Address': len(total_usable_ip_addr),
            'First assignable IP Address': first_usable_ip,
            'Last assignable IP Address': last_usable_ip,
            'Broadcast Address': ip.broadcast_address,
        }


def print_subnets(network_info):
    try:
        for title, data in network_info.items():
            print(successful(f'{title}: {data}'))

    except:
        print(error("Invalid network info"))


def get_subnets(ip_network, subnet_mask, prefix=None):
    """Takes care of spitting out the possible subnets that can be created

    ip_network: The base IP network/subnet address (E.g. 192.168.10.0)
    subnet_mask: Accepts either DDN subnet mask or CIDR (E.g. 255.255.255.0 or 24)
    prefix (optoinal): The new prefix/subnet mask to subnet from 
                       the base network/subnet address. (E.g. 27)

    Examples: 
        - get_subnets("192.168.10.0", "255.255.255.0", 27)
        - get_subnets("192.168.10.0", 24, 27)
        - get_subnets("192.168.10.0", 24)
    """
    if prefix:
        network = ipaddress.IPv4Network(
            f"{ip_network}/{subnet_mask}", strict=False)
        try:
            subnets = []
            for subnet in network.subnets(new_prefix=int(prefix)):
                subnets.append(str(subnet))
            return subnets
        except ValueError as p_error:
            print(error(p_error))

    else:
        return ipaddress.IPv4Network(
            f"{ip_network}/{subnet_mask}", strict=False)


def ip_class_by_hosts(ip_address, subnet_mask_or_cidr):
    try:
        subnet_mask = int(subnet_mask_or_cidr)
        cidr = subnet_mask_or_cidr
    except ValueError:
        subnet_mask = subnet_mask_or_cidr
        cidr = ipaddress.IPv4Network(
            f'{ip_address}/{subnet_mask}', strict=False).prefixlen
    else:
        ip = ipaddress.IPv4Network(f'{ip_address}/{cidr}', strict=False)
        total_hosts = ip.num_addresses

        if total_hosts >= 2**16:
            return "Class A"
        elif total_hosts >= 2**8:
            return "Class B"
        else:
            return "Class C"


def ip_class_private_public(ip_address):
    """Is it a Private Address or Public Address? That's what this function answers
    This function is limited to using the first octet to determine the classful address.
    
    It is possible to 192.168.0.0/20 and still receive a Class C because of the first octet.
    """
    try:
        ip = ipaddress.IPv4Address(ip_address)
    except ipaddress.AddressValueError:
        print(error("Error: Invalid Addresss"))
    else:
        first_octet = int(str(ip).split('.')[0])
        if first_octet >= 1 and first_octet <= 126:
            ip_class = 'A'
        elif first_octet <= 191:
            ip_class = 'B'
        elif first_octet <= 223:
            ip_class = 'C'
        elif first_octet >= 224 and first_octet <= 239:
            ip_class = 'D'
        # class E -> 240 - 255
        else:
            ip_class = 'E'

        # return results
        if ip.is_private:
            return f"{successful(f' According to first octet: Class {ip_class}, Private')}"
        else:
            return f"{successful(f'According to first octet: Class {ip_class}, Public')}"
        

def display_all_info(ip_address, subnet_mask_or_cidr):
    if isinstance(ipaddress.ip_address(ip_address), ipaddress.IPv4Address):
        try:
            subnet_mask = int(subnet_mask_or_cidr)
            cidr = subnet_mask_or_cidr
        except ValueError:
            subnet_mask = subnet_mask_or_cidr
            cidr = ipaddress.IPv4Network(
                f'{ip_address}/{subnet_mask}', strict=False).prefixlen
            print(successful(f"IP Address: {ip_address}"))
            print(successful(f"Subnet Mask: {subnet_mask}"))
        finally:
            print(f"{successful(f'CIDR Notation: {cidr}')}")
            print_subnets(ip_range_info(ip_address, cidr))
            print(network_address(ip_address, cidr))
            print(ip_class_private_public(ip_address))
            print(ip_to_binary(ip_address))
    
    else:
        print(error(f"{ip_address} is an nvalid IP address"))
        

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
                match choice:
                    case 1:
                        # Binary to IP
                        binary_ip = input("Enter the binary IP address: ")
                        print(binary_to_ip(binary_ip))
                    
                    case 2:
                        # IP to binary
                        ip_address = input("Enter the IP address: ")
                        print(ip_to_binary(ip_address))

                    case 3:
                        # network address from IP and Subnet Mask
                        ip_address = input("Enter the IP address: ")
                        subnet_mask = input("Enter the subnet mask: ")
                        print(network_address(ip_address, subnet_mask))

                    case 4:
                        # network address from IP/CIDR
                        ip_address = input("Enter the IP address/CIDR: ")
                        print(cidr_to_subnet_mask(ip_address))

                    case 5:
                        # possible number of subnets
                        ip_address = input("Enter the IP network: ")
                        subnet_mask = input("Enter the subnet mask or CIDR: ")
                        new_prefix = input("Enter new netmask/CIDR: ")
                        print_subnets(ip_range_info(
                            ip_address, subnet_mask, new_prefix))

                    case 6:
                        # is it a private or public IP address?
                        ip_address = input("Enter the IP address: ")
                        print(ip_class_private_public(ip_address))

                    case 7:
                        # get a nice consolidated view on the IP address
                        ip_address = input("Enter the IP address: ")
                        subnet_mask_or_cidr = input(
                            "Enter the subnet mask or CIDR notation: ")
                        display_all_info(ip_address, subnet_mask_or_cidr)

                    case 8:
                    # exit
                        sys.exit(successful('Exiting...'))

                    case _:
                    # input validation
                        print(error('Invalid option. Please try again.'))

            except (KeyboardInterrupt, EOFError):
                sys.exit(error("Exited"))
    
if __name__ == "__main__":
    run_tool()


# TODO: Make functios to return only data, this will allow for easier testing
# TODO: Use functions to format and present data. Have a function for getting data and another for presenting
