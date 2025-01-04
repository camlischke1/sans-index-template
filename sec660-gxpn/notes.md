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
        - In order to leverage an already performed authentication, you need to impersonate a user that is still authenticated but already departed. This means the user has not actively logged out.
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
    - Broadcast addresses are no longer used in IPv6, having been replaced with multicast addresses. 
        - instead of broadcast IPv4 address and an FF:FF:FF:FF:FF:FF MAC address, the host uses the FF02::1 IPv6 address with a destination MAC address of 33:33:00:00:00:01.
        - IPv6 address ff02::1 is used for contacting all link-local devices.
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
        - Teredo tunnel via miredo daemon 
            - start miraedo, then Teredo tunnel is established and allow you to scan and enumerate remote IPv6 targets
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

# Cryptography
- Encryption Algorithms
    - Stream Ciphers
        - All stream ciphers generate keystream data, which is then XORed with the plaintext to produce ciphertext (or vice versa). 
        - Since the keystream is always the same for a given key, all stream ciphers must use a given key no more than once to encrypt data. 
            - law of stream ciphers: never use the same key twice.
    - Block Ciphers
        - When the data to be encrypted are of an uneven length that is not evenly divisible by the block length, the data must be padded to an even block length.
    - cipher block chaining (CBC) mode
        - a plaintext block is XORed with the output of the prior ciphertext block before being encrypted. 
        - This new ciphertext block becomes the input to the next encryption routine.
- Attacks on Encryption
    - oracle padding attack
        - recover plaintext content from a vulnerable cipher block chaining (CBC)-mode block cipher. 
    - stream cipher IV reuse attack
        - must have knowledge of a known plaintext and ciphertext pair. 
        - possible to identify limited quantities of known plaintext from encrypted data, especially in stream ciphers when the original packet length is known. 
            - For example, Windows clients send several packets that have consistent content with unique frame sizes (such as DHCP requests) that are consistently known; 
        - when you see a ciphertext value that matches the length of the Windows DHCP request, you can use the known plaintext content as a component against an IV collision to recover unknown plaintext.
        - KRACK attack allows an attacker to leverage IV reuse to decrypt packets sent over a WPA2 network.
    - Hash length extension attack
        - the resulting hash of applying the MD5 calculation on the first block is used to initialize the registers for the second block
        - As the hash for the first block is known to the attacker, the calculation can be continued with known values for the appended data, resulting in a valid hash for the new string that consists of the old string plus content of the attacker's choosing.
    - Birthday paradox
        - A concern with sequential initialization vector (IV) selection is how the IV is handled when a device reboots; 
            - does it return to 0 (therefore colliding with all prior IVs that were used)? 
            - What happens when the IV space is exhausted? 
            - If the IV is randomly selected (and a history of prior IVs is not maintained to avoid collisions), then the IV selection algorithm is vulnerable to the birthday paradox attack, where the likeliness of a collision is exponentially increased for each IV used. 
    - POODLE attack
        - necessary to have a machine-in-the-middle (MitM) position that allows you to intercept the traffic between client (browser) and server to 
        1. drop requests for TLS protocols and only allow requests for SSL3.0 to pass. 
        2. JavaScript injection can be done from the MitM position, allowing an attacker to force the client to make requests until they are able to determine the key.
- Common vulnerabilities
    - AppArmor rules are fixed on the path
        - symbolic links can bypass these
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
## 2) Obfuscation/Bypasses
- Living off the Land
    - Rundll32.exe, cscript
    - Screensavers are special types of portable executables
        - good way for persistence and backdoors, replace the screensaver with a command shell or msfvenom payload
    - Powershell
        - has a .bashrc-like feature where profiles are run every single time Powershell starts. we can inject here. 
        - persistent modules are loaded if included in the PSModulePath variable. we can inject here
    - Exploiting pre-installed applications 
        - Adobe and other PDF readers can run javascript
        - browsers as PDF-viewers do not run JavaScript inside the pdf file
- Library Loading
    - use tracing techniques to understand the vulnerable executable
    - dynamic libraries (.so and .dll) are loaded at runtime based on some pre-defined sequence. inject here.
    - Linux 
        - LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT environment vars
        - RPATH and RUNPATH defined in the ELF binary overwrite these environment variables
    - Windows   
        - PE executables use a statically-defined import table (likely with relative paths)
        - DLL hijacking
    - Metasploit/msfvenom can be used to make malicious libraries
- EDR bypasses  
    - Windows will allow any other EDR product to disable the Defender features
        - make own (purposefully) horrible EDR and install it to essentially disable Windows Defender    

# Application Security
## Fuzzing
- Scapy
    - sr(packet) sends the packet and receives responses solicited from the transmitted frame, displaying the summarized results to the user.
        - sr() stops receiving when interrupted (with CTRL-S) or when it recognizes that the transmission is complete
    - sr1(packet) is similar to sr(packet), but it stops after the first response
    - send(packet) sends the packet but does not care about the response
    - sendp(packet) is similar to send(packet) but sends the packet without adding the Ethernet header
- Instrumented fuzzing is an automated mutation selection and delivery mechanism that uses monitored, dynamic analysis of a target process. 
    - With instrumented fuzzing, the fuzzer launches (or is attached to) a process, monitors the execution flow of the process, and adjusts the input to the process to achieve high code coverage levels.
    - DynamoRIO tools helps
        - `drcov`
            - tracks basic block hits for an instrumented application, writing the block addresses and basic target binary information to a log file in ASCII or binary format when the instrumented application terminates.
        - `DynaPstalker`
            - Python script written to read from drcov log files and produce an IDA Pro IDC script that color-codes each basic block reached during instrumentation.
    - Sulley is a framework for building a protocol grammar for intelligent mutation fuzzing, generating mutations based on the analyst's description of a protocol
        - When the fuzzing target is not on the same system as the fuzzer, you can deploy another instance of Sulley, which is controlled by the fuzzer system over a custom remote procedure call (RPC) protocol known as "pedrpc".
        - s_num_mutations() function to identify the number of mutations that will be generated
        - s_initialize function creates a new fuzzer construct definition
- source code is not available for analysis, you can also evaluate the disassembly of a binary, identifying the basic blocks that are executed

# Exploit Development
## 1) Linux
- Stack vs Heap
    - Heap is dynamic for large memory allocations
        - grows low to high
    - Stack often used for short, finite operations and memory allocations related to function calls and function arguments
        - grows from high to low memory space
- Linkers v Loaders
    - Linkers locate memory address of function from system Library
    - Loaders responsible for loading that function/program from disk to memory
    - Relocation
        - programs typically have a defined loading address that is desired
        - if that address is in use, relocation section patches the program to new addresses
        - most functions are called via Relative Virtual Addresses based on offset from load address
- Writing Shellcode
    - shellcode is often dropped into address space via buffers and string operations
        - this requires no null bytes
    - shellcode is often executed as a user-level shell due to applications dropping privileges of the exploited application
        - this requires setreuid()
- Stack Overflows
    - vulnerable copy function overwrites the return pointer to attacker-controlled memory location
    - once you store shellcode at that location, we can execute it
    - Return-to-libc
        - used when buffer is too small or when the stack is nonexecutable
        - same idea but we write the return pointer to be a function in libc
            - using the same buffer, we can also set arguments for that function we call
    - Protections
        - Canaries
            - value is known before execution and then checked once the buffer is written
                - can be null
                - can be a fixed value with a null byte in it to be sure string operations don't overwrite it
                - can be a random value
        - Stack Smashing Protector or StackGuard built into `gcc`
            - built off of ProPolice
        - ASLR Address Space Layout Randomization randomizes stack and heap addressing
            - use `LDD` command to check if a library isn't getting randomized for some reason -- this could help in exploitation
    - Bypassing protections



        
- Return-Oriented Programming
    - used when we can't inject shellcode into memory, instead we just use bbytes that are already there
    - string together tons of gadgets to achieve a shellcode-like execution path
        - gadgets are executable blocks of code typically already loaded into memory (ASLR disabled is preferred)
        - we can literally cherry-pick bytes of instructions for our own purposes
    - ROP Shellcode
        - new goal of executing an `execve()` system call requires:
            1. AL register contains the system call number (0x0b in this case)
            2. base pointer BX holds the pointer to the argument for execve
            3. count register CX points to the argument vector ARGV pointer array
            4. data register DX points to ENVP array (environment variable pointer)
        - 


    


## 2) Windows
- Writing Shellcode
    - Challenges
        - forced to use Windows API to make system calls
        - locations of system calls and functions change with each version/OS kit
            - Kernel32.dll, kernelbase.dll, ntdll.dll are always loaded but hard to locate
        - does not allow for direct access to opening sockets/network ports via system calls
    - `Kernel32.dll`
        1. Locating `kernel32.dll` using Process Environment Block PEB
            - per-process structure that lists all loaded modules, including the base address of this dll
            - always the second- or third-loaded library in the PEB
            - OR Locating using SEH Unhandled Exception Handler
                - raising an exception will call a function within `kernel32.dll` which can then be used to walk back to find the base address of the library
        
        2. GetProcAddress() allows shellcode to obtain the addresses of desired functions within the loaded libraries
            - find the RVA offset of this function by using the Export Address Table EAT for kernel32dll
        3. LoadLibraryA() allows to load libraries into process
            - find the RVA using the GetProcAddress() function 
        4. Now that these have been found:
            - any module can be loaded with LoadLibraryA()
            - APIs and functions can be resolved GetProcAddress()

# Miscellaneous
## Passwords 
- Password Lists
    - COMB Compilation of Many Breaches
    - The Probable Password List
- [Coalfire's NPK AWS-Managed Rig](https://github.com/c6fc/npk)