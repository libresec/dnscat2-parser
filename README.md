# dnscat2-parser
Simple, incomplete, dnscat2 parser. Take a PCAP as input prints out decoded
messages.

## Usage
---------------
```no-highlight
$ python dnscat2-parser.py
        Usage:
            python dnscat2-parser.py <pcap>
            python dnscat2-parser.py <pcap> -v
```

## Sample Output
---------------
```no-highlight
$ python dnscat2-parser.py ~/Desktop/example.pcap 
executing a shell
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C
:\Users\*****\Desktop>
ipconfig

Windows IP Configuration


Ethernet adapter Bluetooth Network Connection:

   Media State
. . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 

Wireless LAN adapte
r Wireless Network Connection:

   Media State . . . . . . . . . . . : Media disconnected
   Connection
. : foo.com
   IPv4 Address. . . . . . . . . . . : **.**.**.**
   Subnet Mask . . . . . . . . .
. . : 255.255.255.0
   Default Gateway . . . . . . . . . : **.**.**.**

Ethernet adapter VMware Networ

   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :
Ethernet adapter VMware Network Adapter VMnet8:

   Connection-specific DNS Suffix  . : 
   IPv4 Addres
s. . . . . . . . . . . : 192.168.28.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Ga
teway . . . . . . . . . : 

C:\Users\*****\Desktop>
command session
executing a shell
s

```