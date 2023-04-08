import ipaddress

# ANSI escape sequences for bold red text and reset
bold_red = "\033[1;31m"
reset = "\033[0m"

def binary_to_ip(binary_ip):
    # Remove dots from the input string
    binary_ip = binary_ip.replace('.', '')
    # Split the binary string into 4 octets
    octets = [binary_ip[i:i+8] for i in range(0, 32, 8)]
    # Convert each octet to decimal and join with dots to form IP address
    return '.'.join(str(int(octet, 2)) for octet in octets)

def ip_to_binary(ip_address):
    ip = ipaddress.ip_address(ip_address)
    binary_ip = bin(int(ip))[2:]
    binary_ip = binary_ip.rjust(32, '0')  # Pad with zeros if necessary
    return ".".join([binary_ip[i:i+8] for i in range(0, 32, 8)])

def network_address(ip_address, subnet_mask):
    ip = ipaddress.IPv4Interface(f"{ip_address}/{subnet_mask}")
    return str(ip.network)

def cidr_to_subnet_mask(ip_address, cidr):
    network = ipaddress.IPv4Network(f'{ip_address}/{cidr}', strict=False)
    return str(network.netmask)

def possible_subnets(ip_address, subnet_mask):
    ip = ipaddress.IPv4Network(f'{ip_address}/{subnet_mask}', strict=False)
    max_bits_borrowed = 32 - ip.prefixlen
    return 2 ** max_bits_borrowed

def ip_class_private_public(ip_address):
    ip = ipaddress.IPv4Address(ip_address)
    first_octet = int(str(ip).split('.')[0])
    
    if first_octet >= 1 and first_octet <= 126:
        ip_class = 'A'
    elif first_octet >= 128 and first_octet <= 191:
        ip_class = 'B'
    elif first_octet >= 192 and first_octet <= 223:
        ip_class = 'C'
    elif first_octet >= 224 and first_octet <= 239:
        ip_class = 'D'
    else:
        ip_class = 'E'
        
    if ip.is_private:
        return f"Class {ip_class}, Private"
    else:
        return f"Class {ip_class}, Public"
#def display_all_info(ip_address, subnet_mask_or_cidr):
    try:
        if '/' in subnet_mask_or_cidr:
            cidr = int(subnet_mask_or_cidr.split('/')[-1])
            subnet_mask = cidr_to_subnet_mask(ip_address, cidr)
        else:
            subnet_mask = subnet_mask_or_cidr
            cidr = ipaddress.IPv4Network(f'{ip_address}/{subnet_mask}', strict=False).prefixlen

        print(f"IP Address: {ip_address}")
        print(f"Subnet Mask: {subnet_mask}")
        print(f"CIDR Notation: {cidr}")
        print(f"Binary IP: {ip_to_binary(ip_address)}")
        print(f"Network Address: {network_address(ip_address, subnet_mask)}")
        print(f"Possible Subnets: {possible_subnets(ip_address, subnet_mask)}")
        print(f"IP Class and Private/Public: {ip_class_private_public(ip_address)}")
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as e:
        print(f"{bold_red}Error: {str(e)}{reset}")
def display_all_info(ip_address, subnet_mask_or_cidr):
    try:
        cidr = int(subnet_mask_or_cidr)
        subnet_mask = cidr_to_subnet_mask(ip_address, cidr)
    except ValueError:
        subnet_mask = subnet_mask_or_cidr
        cidr = ipaddress.IPv4Network(f'{ip_address}/{subnet_mask}', strict=False).prefixlen

    print(f"{bold_red}IP Address: {ip_address}{reset}")
    print(f"{bold_red}Subnet Mask: {subnet_mask}{reset}")
    print(f"{bold_red}CIDR Notation: {cidr}{reset}")
    print(f"{bold_red}Binary IP: {ip_to_binary(ip_address)}{reset}")
    print(f"{bold_red}Network Address: {network_address(ip_address, subnet_mask)}{reset}")
    print(f"{bold_red}Possible Subnets: {possible_subnets(ip_address, subnet_mask)}{reset}")
    print(f"{bold_red}IP Class and Private/Public: {ip_class_private_public(ip_address)}{reset}")

def main_menu():
    print("Choose an option:")
    print("1. Binary IP to Floating Point IP address")
    print("2. IP address to Binary")
    print("3. Find Network Address from IP and Subnet Mask")
    print("4. Convert IP and CIDR Notation to Subnet Mask")
    print("5. Calculate Possible Subnetting from IP range")
    print("6. Determine IP Class and Private/Public Status")
    print("7. Display All Information for an IP Address and Subnet")
    print("8. Exit")


if __name__ == "__main__":
    while True:
        main_menu()
        choice = int(input("Enter the option number: "))
        
        if choice == 1:
            binary_ip = input("Enter the binary IP address: ")
            print(f"{bold_red}Decimal IP: {binary_to_ip(binary_ip)}{reset}")
        elif choice == 2:
            ip_address = input("Enter the IP address: ")
            print(f"{bold_red}Binary IP: {ip_to_binary(ip_address)}{reset}")
        elif choice == 3:
            ip_address = input("Enter the IP address: ")
            subnet_mask = input("Enter the subnet mask: ")
            print(f"{bold_red}Network address With CIDR Notation: {network_address(ip_address, subnet_mask)}{reset}")
        elif choice == 4:
            ip_address = input("Enter the IP address: ")
            cidr = input("Enter the CIDR notation: ")
            print(f"{bold_red}IP Subnet mask: {cidr_to_subnet_mask(ip_address, cidr)}{reset}")
        elif choice == 5:
            ip_address = input("Enter the IP address: ")
            subnet_mask = input("Enter the subnet mask: ")
            print(f"{bold_red}Possible subnets: {possible_subnets(ip_address, subnet_mask)}{reset}")
        elif choice == 6:
            ip_address = input("Enter the IP address: ")
            print(f"{bold_red}IP class and private/public: {ip_class_private_public(ip_address)}{reset}")
        elif choice == 7:
            ip_address = input("Enter the IP address: ")
            subnet_mask_or_cidr = input("Enter the subnet mask or CIDR notation: ")
            display_all_info(ip_address, subnet_mask_or_cidr)

        elif choice == 8:
            print("Exiting...")
            break
        else:
            print("Invalid option. Please try again.")
