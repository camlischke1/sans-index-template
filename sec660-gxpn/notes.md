# Advanced Network Attacks
## 1) Accessing the Network
- Network Admission Control NAC provides some level of security or requirement to ensure that authenticated or authorized devices can gain access to the network
- *Captive portals* act as an intermediate network, drop most traffic until successful authentication
    - attack the portal itself
    - attack pre-auth services like DNS, DHCP
    - attack other pre-auth devices/infra on the pre-auth network
- Bypassing captive portal authentication requirements
    - don't always use TLS for the authentication traffic --> sniffing with Cain possible
    - some checks for authentication based on IP/MAC address --> impersonation possible
        - `ifconfig` on mac and Linux can spoof MAC addresses
        - `macshift` tool from github on Windows
    - some NAC solutions have exceptions to devices that don't require authentication
        1. identify the NAC solution in use
        2. identify possible devices that would blend in but not require auth 
            - native protocol limitations
            - MAC OUI "goodlist" is sometimes published
    - additional checks to validate MAC checks
        - browser user-agent matching with extensions like User Agent Switcher
        - passive network fingerprinting with tools like OSfuscate
        - javascript OS validations by changing other browser settings
            - see Fingerbank or Panopticlick
- *802.1x Authentication*
    - client device must have supplicant software to authenticate to network before the port becomes "open"
    - legitimate devices that are incompatible with supplicant software are generally excluded from netwokr policies
        - hard-wired connections like printers can have their ports reused by attackers since they are likely excluded from the policies
    - three required components
        1. supplicant on client device
        2. Port Access Entity (likely a switch)
        3. authentication server 
            - authentication mechanism uses EAP
    - attacking pre-auth traffic
        - supplicants are allowed to communicate with auth services over specified EAP type prior to authentication
        - switch does not monitor traffic 
        - this allows the attacker to fuzz or exploit packet-parsing vulnerabilities on the auth server
    - attacking authenticated devices
        - Wired EAP Shadow Attack
            - attacker impersonates MAC of authenticated victim, giving access to all stateless protocols
        - MiTM 802.1x Shadow (need to research further)
            - device with two ethernet ports can mitm authenticated devices and switch
            - if the device is just a simple traffic mirror
    - VLAN Manipulations
        - these attacks often require ethernet adapters for VMs or Linux-native host OSes
        - VLAN Trunking
            - access v trunk ports
                - a "trunk port" allows traffic from multiple VLANs to pass through a single connection
                - an "access port" is dedicated to carrying traffic for only one VLAN
            - convincing the upstream switch into thinking our device is an 802.1Q/ISL switch, we can turn the port into a trunk port
                - switch then passes all VLAN traffic to us
            - this can be used as a way to laterally move across different VLANs (VLAN hopping)
        - VOIP VLAN Hopping
            - common to see VOIP phone connected to ethernet switch and workstation connected to VOIP phone

                        SWITCH <---> VOIP <----> Machine

            - this means VOIP phone is configured as a switch between voice VLAN and regular VLAN
            - if attacker accesses either, it can laterally move
                1. have access to machine connected to VOIP phone (which is essentially a switch here)
                2. VLAN hop to voice VLAN
                3. exploit other phones on voice VLAN
            - to VLAN hop, you need to kno the VLAN number in order to create a new sub-interface
                - can be gathered through a Cisco Discovery Protocol CDP capture or bruteforced, since there are only 4094 possibilities

## 2) Abusing the Network
- MitM via ARP Spoofing
    - impersonate the default gateway and all connected machines for the network
        1. get list of devices on the LAN via ICMP Echos or ARP flooding
        2. convince the default gateway that you are the devices on the network 
        3. convince the devices on the network that you are the default gateway
    - Ettercap automates this, performs password sniffing, can be extended using plugins, filters, etc
        - can replace info in responses like HTTP headers and HTML tags
    - can force SMB relays/sniffs
        1. write a filter to change the `If-Modiofied-Since` header to bypass browser caching
        2. write a filter to change the `Accept-Encoding` filter to force server to send text response instead of gzip
        3. write a filter to make the HTML page reference an image on your SMB server
        4. start Responder for an SMB sniffer/relay
        5. when the user requests a page with your smb server IP address, the user will have to send NTLM hashes to your server
        6. crack the hashes!
    - Other tools
        - Bettercap provides extensibility and Autopwn 
        - mitmproxy
        - sslstrip
- Routing Attacks
    - Hot-Standby Router Protocol (HSRP)
        - multiple routers with same IP address, if primary fails then secondary router takes over
            - secondary device fails to see a preconfigured number of hello messages from primary, it believes primary has failed
            - ALL devices on network see the HSRP traffic due to using multicast address 224.0.0.2
        - ATTACK using Yersinia
            - if attacker finds HSRP authentication string, attacker can impersonate HSRP router
                1. Attacker sends HSRP hello messages with higher priority than primary router
                2. attacker changes MAC address to 00:00:0c:07:ac:\<HSRP group address\>
                3. attacker changes IP address to match other routers (default gateway)
                4. can set up MitM attack
                5. must continue to send HSRP hello messages to maintain primary status
    - Virtual Router Redundancy Protocol (VRRP)
        - essentially the same as HSRP except:
            - MAC address to 00:00:5e:00:01:\<VRRP group address\>
            - uses multicast address to send hello packets 224.0.0.18
            - no authentication or integrity checks
        - Loki tool 
    - if attacker ever sees routing protocol traffic (OSPF, RIP, EIGRP) there is exploitation opportunity
        - routing traffic should be limited to router interfaces, not end-user clients
    - OSPF (Open Shortest Path First)
        - essentially how a router stays aware of network topology and other routers within the LAN
            - routers send OSPF traffic and Link State Advertisements (LSAs) to neighbor devices
        - uses multicast group 224.0.0.5
        - Enumeration Attack Against OSPF
            - attacker must participate as an OSPF neighbor to receive LSAs that reveal network topology
                1. requires responding to MD5 challenge/response authentication if configured to use authentication
                2. after joinging OSPF routing neighborship, attacker steps through state tree with peer router
        - MD5 Dictionary Attack
            - if OSPF is configured to use authentication, we can capture hello messages and crack the shared secret
    - Summary
        - routing protocol traffic is assumed to be isolated but can sometimes be seen from LAN
        - authentication tends to be weak
        - attacker objective: manipulate protocol to become primary router, intercept, and redirect traffic
- IPv6 Attacks
    - Neighbor Discovery/Impersonation Attacks
        - ARP is replaced by Neighbor Discovery (ND) in IPv6
            - ICMPv6 Neighbor Solicitation request replied with a Neighbor Advertisement
        - Essentially the same as ARP spoofing but with Neighbor Advertisement replies and ICMPv6 Override flag
        - use parasite6 tool




# Miscellaneous
## Passwords 
- Password Lists
    - COMB Compilation of Many Breaches
    - The Probable Password List
- [Coalfire's NPK AWS-Managed Rig](https://github.com/c6fc/npk)