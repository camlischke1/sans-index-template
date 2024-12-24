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
    - use IPv6 to get around IPv4 filters/blacklists!
        1. Identify active ipv6 nodes
        2. scan and identify services
            - which ports and services are blocked for my ipv4 address?
            - can I bypass these blocks by using my ipv6 address or manipulate it in such a way that allows access via ipv6?
    - (Local) Neighbor Discovery/Impersonation Attacks
        - ARP is replaced by Neighbor Discovery (ND) in IPv6
            - ICMPv6 Neighbor Solicitation request replied with a Neighbor Advertisement
        - Essentially the same as ARP spoofing but with Neighbor Advertisement replies and ICMPv6 Override flag
        - use parasite6 tool
    - (Local) Router Solicitation MitM attacks
        - responding to router solicitation messages
            - nodes regularly ask for router solicitation messages (RS) at the anycast address (directed to all routers)
                - sent at FF02::2 anycast address
            - routers send multicast messages router advertisement (RA) responses to all nodes 
                - sent at FF02::1 address multicast
        - Attacker inserts RA messages that specify himself as the priority router
            - nodes send all ipv6 traffic to external networks through attacker router
    - remote attacks require direct access to ipv6 network through ISP or ipv4-to-ipv6 tunneled connection
    - Remote IPv6 Node Discovery
        - no opportunity for multicast node discovery, must rely on other techniques
            - DNS, 
            - error messages, 
            - HTTP/JS content
    - Goals/Objectives
        - become the gateway (mitm)
        - avoid duplicate address detection
        - use router announcement to your advantage
        - override flag helps override current settings
    - Potential attack technique
        1. find filtered service with an ipv4 blacklist
        2. test if the same machine has an ipv6 interface that is not filtered
        3. identify vulnerable IPv4 machine
        4. find MAC address
        5. match MAC address with IPv6 address
        6. exploit vulnerable service from ipv6
- Attacking Encrypted Traffic 
    - `sslstrip` useful for when attacker is MitM already
        - only exploits when browsers go to http site and then redirected to connect to https
    - mitigated by HTTP Strict Transport Security (HSTS) feature which disallows clients to visit unless HTTPS
        - HSTS bypasses
            - time -- spoofing NTP to make browser think the HSTS header is expired
            - hostname -- make the victim browse to a different site and then Mitm it to be the site you want
                - ie wwww.facebook does not have HSTS header set yet because it has not been visited yet
                - user clicks malformed link, goes to wwww.facebook, attacker mitm changes it to www.facebook and reads traffic
    - KRACK Attack  
        - WPA2 uses an incrementing IV to encrypt traffic
        - before the IV space runs out, the client must reauthenticate and a new IV and secret key is given, which is then re-incremented
            - an attacker can replay the handshake with the same secret key, and then the IVs are reused for the subsequent packets
            - reused IVs with reused secret keys allow attacker to decrypt the traffic

# Advanced Post-exploitation
## 1) Bypassing Windows Restrictions
- Types of restictions
    - Group Policy Objects and Software Restriction Policies
        - Unrestricted -- software access rights are determined by user access
        - Disallowed -- software does not run regardless of user access rights
    - Windows Defender Application Control (WDAC)
        - basic allow/deny rule defined on certificate, hash, zone, or path of the executable
    - virtualized applications
    - Third party restrictions
        - replace the windows shell explorer by pointing HKLM/HKCU registry key to a different executable
- Bypassing restricted desktops
    - command shell for execution and output via cmd or Powershell or even third-party alternatives/built-in DLLs
    - notepad to write ascii to file system
    - explorer gui to grab files from internet/smb share
    - notepad/paint/browser/media player to browse file system
    - Certutil
        1. base64-encode the binary file in a certificate format 
        2. download the fake certificate file via notepad
        2. certutil to write the certificate to a binary executable on disk
    - restrictions are usually placed on EXE, but try scripts/DLLs/macros too
- Living off the Land
    - Rundll32.exe, cscript
    - Screensavers are special types of portable executables
        - good way for persistence and backdoors, replace the screensaver with a command shell or msfvenom payload
    - Powershell
        - has a .bashrc-like feature where profiles are run every single time Powershell starts. we can inject here. 
        - persistent modules are loaded if included in the PSModulePath variable. we can inject here
        
        



# Miscellaneous
## Passwords 
- Password Lists
    - COMB Compilation of Many Breaches
    - The Probable Password List
- [Coalfire's NPK AWS-Managed Rig](https://github.com/c6fc/npk)