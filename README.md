# IPv4 Tool for Beginner

IP Tool is a Python-based command-line utility for working with IP addresses. 

It provides various functionalities such as:
 - converting binary IP to decimal IP
 - determining IP class and private/public status 
 - calculating possible subnets
 - and more.

### **Capabilities:**
-   Converting a binary IP address to a dotted decimal notation IP address
-   Converting an IP address to binary
-   Finding the network address from an IP address and subnet mask
-   Finding the network address from an IP/CIDR notation
-   Calculating possible subnetting from an IP range
-   Determining the IP class and private/public status
-   Displaying all information for an IP address and subnet

## Installation

1. Clone this repository to your local machine.
2. `git clone https://github.com/nanafox/IPv4-tool-for-beginner.git` _(Forked)_ **OR**
3. `git clone https://github.com/Blindsinner/IPv4-tool-for-beginner.git` _(Original Developer)_


## Usage

To use the command-line interface, navigate to the directory containing the `ip_tool.py` script and run: 

`python ip_tool.py`

## Examples

### Convert binary IP address to dotted decimal notation

```
Enter the binary IP address: 11000000.10101000.00000001.00000001
Decimal IP: 192.168.1.1
```

### Convert IP address to binary

```
Enter the IP address: 192.168.1.1
Binary IP Address: 11000000.10101000.00000001.00000001
``` 

### Find network address from IP and subnet mask

```
Enter the IP address: 192.168.1.1
Enter the subnet mask: 255.255.255.0
Network address with CIDR Notation: 192.168.1.0/24
``` 

### Find network address from IP/CIDR notation

```
Enter the IP address/CIDR: 192.168.1.1/24
Network address: 192.168.1.0
IP Subnet Mask: 255.255.255.0
```

### Calculate possible subnetting from IP range

#### Example 1 - With new prefix
```
Enter the IP network: 192.168.10.0
Enter the subnet mask or CIDR: 24
Enter new netmask/CIDR: 27

Base Network Address: 192.168.10.0/24
Base Network Mask: 255.255.255.0
Total Subnets Possible with prefix /27: 8
Total assignable IP Addresses per subnet: 30
First usable subnet: 192.168.10.0/27
Last usable subnet: 192.168.10.224/27
Wildcard mask: 0.0.0.255
PTR IP Address: 0.10.168.192.in-addr.arpa
PTR Network Address: 10.168.192.in-addr.arpa
Binary Subnet Mask: 11111111.11111111.11111111.00000000
```

#### Example 2 - Without a new prefix
```commandline
Enter the IP network: 192.168.10.5
Enter the subnet mask or CIDR: 23
Enter new netmask/CIDR: 

Possible Number of Subnets: 512
Total Assignable IP Address: 510
First assignable IP Address: 192.168.10.1
Last assignable IP Address: 192.168.11.254
Broadcast Address: 192.168.11.255
Wildcard mask: 0.0.1.255
PTR IP Address: 5.10.168.192.in-addr.arpa
PTR Network Address: 10.168.192.in-addr.arpa
Binary Subnet Mask: 11111111.11111111.11111110.00000000
```
### Determine IP class and private/public status

```
Enter the IP address: 192.168.1.1
Network Class: C
Address Type: Private
```

### Display all information for an IP address and subnet

```
Enter the IP address: 192.168.10.4
Enter the subnet mask or CIDR notation: 24

Network Address: 192.168.10.0
Subnet Mask: 255.255.255.0
CIDR Notation: 24
Possible Number of Subnets: 256
Total Assignable IP Address: 254
First assignable IP Address: 192.168.10.1
Last assignable IP Address: 192.168.10.254
Broadcast Address: 192.168.10.255
Wildcard mask: 0.0.0.255
PTR IP Address: 4.10.168.192.in-addr.arpa
PTR Network Address: 10.168.192.in-addr.arpa
Binary Subnet Mask: 11111111.11111111.11111111.00000000
Binary IP Address: 11000000.10101000.00001010.00000100
Network address with CIDR Notation: 192.168.10.0/24
Network Class: C
Address Type: Private
```

Follow the on-screen prompts to perform various IP-related tasks.

## Contributing

If you would like to contribute to this project, please feel free to submit a pull request or open an issue on GitHub.

## License

This project is licensed under the [MIT License](LICENSE).
