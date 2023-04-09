# IPv4 Tool for Beginner

IP Tool is a Python-based command-line utility for working with IP addresses. It provides various functionalities such as converting binary IP to decimal IP, determining IP class and private/public status, calculating possible subnets, and more.

This is a command-line tool that performs various operations on IPv4 addresses, including:

-   Converting a binary IP address to a dotted decimal notation IP address
-   Converting an IP address to binary
-   Finding the network address from an IP address and subnet mask
-   Finding the network address from an IP/CIDR notation
-   Calculating possible subnetting from an IP range
-   Determining the IP class and private/public status
-   Displaying all information for an IP address and subnet

## Installation

1. Clone this repository to your local machine.

2. git clone https://github.com/Blindsinner/IPv4-tool-for-beginner.git


## Usage

To use the command-line interface, navigate to the directory containing the `ip_tool.py` script and run: 

python ip_tool.py
## Examples

### Convert binary IP address to dotted decimal notation



`Enter the binary IP address: 11000000.10101000.00000001.00000001
Decimal IP: 192.168.1.1` 

### Convert IP address to binary



`Enter the IP address: 192.168.1.1
11000000.10101000.00000001.00000001` 

### Find network address from IP and subnet mask



`Enter the IP address: 192.168.1.1
Enter the subnet mask: 255.255.255.0
Network address with CIDR Notation: 192.168.1.0/24` 

### Find network address from IP/CIDR notation



`Enter the IP address/CIDR: 192.168.1.1/24
Network address: 192.168.1.0
IP Subnet Mask: 255.255.255.0` 

### Calculate possible subnetting from IP range



`Enter the IP network: 192.168.1.0
Enter the subnet mask or CIDR: 27
Possible Number of Subnets: 32` 

### Determine IP class and private/public status



`Enter the IP address: 192.168.1.1
 According to first octet: Class C, Private` 

### Display all information for an IP address and subnet

`Enter the IP address: 192.168.1.1
Enter the subnet mask or CIDR notation: 255.255.255.0
IP Address: 192.168.1.1
Subnet Mask: 255.255.255.0
CIDR Notation: 24
Network Address: 192.168.1.0
Broadcast Address: 192.168.1.255
Network Address with CIDR Notation: 192.168.1.0/24
Possible Number of Subnets: 1
Total Number of Hosts: 256
Number of Usable Hosts: 254
IP class and private/public: According to first octet: Class C, Private
IP Class (based on total number of hosts): Class C
Binary Version of IP: 11000000.10101000.00000001.00000001
Binary Subnet Mask: 11111111.11111111.11111111.00000000
Usable Host IP Range: 192.168.1.1 - 192.168.1.254
Integer ID:` `3232235777`
`Hex ID:         0xc0a80101
in-addr.arpa:   1.1.168.192.in-addr.arpa
Wildcard Mask:  0.0.0.255
IPv4 Mapped Address: ::ffff:192.168.1.1
6to4 Prefix:    2002:c0a8:0101::/48` 

Follow the on-screen prompts to perform various IP-related tasks.

## Contributing

If you would like to contribute to this project, please feel free to submit a pull request or open an issue on GitHub.

## License

This project is licensed under the [MIT License](LICENSE).

