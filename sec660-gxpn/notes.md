# Advanced Network Attacks
### 1) Accessing the Network
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

### 2) Abusing the Network
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
### 1) Bypassing Windows Restrictions
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
### 2) Obfuscation/Bypasses
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
### Fuzzing
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
### 1) Linux
- Stack vs Heap
    - Heap is dynamic for large memory allocations
        - grows low to high
    - Stack often used for short, finite operations and memory allocations related to function calls and function arguments
        - grows from high to low memory space
- Memory
    - Paging
        - If more memory is needed than what is physically available or if a flat memory model is not desired, the processor can provide virtual memory through an indirect memory mapping
    - Registers
        - Processor registers are physically integrated into the processor cores
            - by far the fastest for the processor to access and has limited storage capacity
        - 16 general-purpose registers 
            - fourth control register, CR3, holds the starting address of the page directory. 
                - This is the location where page tables start, used for physical-to-linear address mapping
            - CS register is used for the code segment
            - IP for the instruction pointer
            - FLAGS for mathematical operations.
            - EBP is used to reference variables on the stack, such as an argument passed to a called function
            - ESP/RSP is used to maintain the address of the top of the stack, serving as the return pointer to restore the instruction pointer after the called function is complete
            - EBX/RBX serves more as a true general register with no specific purpose. 
            - EAX/RAX is used as an accumulator register
            - RAX holds the desired system call number, and RDI, RSI, RDX, R10, R8, and R9 hold the arguments, in that order
            - DX data register (EDX on a 32-bit system) has to point to the envp array, which is a pointer to the environment variables passed to the called function
            - count register (ECX/RCX) is often used with loops and shifts to hold the number of iterations
            - code segment registers
                - FS code segment register holds a pointer to the Thread Information Block (TIB)
                - DS and ES registers are data segment registers that are used for other purposes.
- Intel v AT&T assembly
    - AT&T Syntax 
        - dollar sign ($) implies an immediate operand, as opposed to a value or address stored in a register
            - ie `mov $4, %eax` would move the value 4 into the EAX register
    - IA-32 system with PAE
        - protected mode memory model
        - 32-bit Intel processor 
        - can support up to 64 GB of physical address space when using physical address extension (PAE)
- Files
    - Block Started by Symbol (BSS) segment contains uninitialized global variables
        - Some of these variables may never be defined, and 
        - some may be defined if a particular function is called. 
        - any variable with a value of zero upon runtime may reside in the BSS segment
        - Some compilers do not store these uninitialized variables in the BSS segment if it is determined that they are blocks of dead code that are unused.
    - Set User ID (SUID) or Set Group ID (SGID) 
        - identifying these programs may lead to a privilege escalation for the attacker
        - `find / -perm /6000`
- Linkers v Loaders
    - Linkers locate memory address of function from system Library
        - dynamic linker 
            - populates a table known as the Global Offset Table (GOT). 
            - obtains the absolute address of requested functions and updates the GOT, as requested. 
    - Loaders responsible for loading that function/program from disk to memory
    - Relocation
        - programs typically have a defined loading address that is desired
        - if that address is in use, relocation section patches the program to new addresses
        - most functions are called via Relative Virtual Addresses RVA based on offset from load address
        - Files do not need to be relocatable because the GOT takes requests for locations from the Procedure Linkage Table (PLT)
- Writing Shellcode
    - shellcode is often dropped into address space via buffers and string operations
        - this requires no null bytes
    - shellcode is often executed as a user-level shell due to applications dropping privileges of the exploited application
        - this requires setreuid()
    - when invoking system calls
        - arguments are loaded into processor registers and an interrupt is made. 
            - On x86_64 systems, RAX holds the desired system call number, and RDI, RSI, RDX, R10, R8, and R9 hold the arguments,
- Stack Overflows
    - vulnerable copy function overwrites the return pointer to attacker-controlled memory location
    - once you store shellcode at that location, we can execute it
    - Return-to-libc
        - used when buffer is too small or when the stack is nonexecutable
        - same idea but we write the return pointer to be a function in libc
            - using the same buffer, we can also set arguments for that function we call
        - ret2puts technique 
            - used to bypass ASLR
            - print out memory addressing of something internal to the process in order to leak addressing
    - Protections
        - Canaries
            - place a 4- or 8-byte value onto the stack after the buffer and before the return pointer
                - UNIX-based OSes, this value is often called a "canary," 
                - Windows-based OSes, it is often called a "security cookie."
            - value is known before execution and then checked once the buffer is written
                - can be null
                - can be a fixed value with a null byte in it to be sure string operations don't overwrite it
                    -  terminator canary uses the value 0x00000aff
                    - strcpy() fails to recreate the canary due to the null terminator value of 0x00
                - can be a random value
        - Stack Smashing Protector or StackGuard built into `gcc`
            - built off of ProPolice
            - placing a random canary on the stack to protect the return pointer and the saved frame pointer
                - if "urandom" strong number generator cannot be used, the canary reverts to using a terminator canary
            - reorders local variables
        - ASLR Address Space Layout Randomization randomizes stack and heap addressing
            - use `LDD` command to check if a library isn't getting randomized for some reason -- this could help in exploitation
            - default application is compiled as position independent executable (PIE)
                - which enables address space layout randomization (ASLR) on the binary
                - compiler setting in GCC (which is enabled by default with modern versions of GCC) specifies whether or not the binary image itself is to participate in randomization
                - To disable the protection for a binary, you would use the `-no-pie` flag
            - To ensure that stacks continue to grow from higher memory down toward the heap segment, and vice versa, without colliding, the most significant bits (MSBs) are not randomized
            - command `echo 2 > /proc/sys/kernel/randomize_va_space` 
                - writes the value 2 to the randomize_va_space file
                - enables full ASLR to randomize: 
                    - addresses of the stack, 
                    - mmap regions, 
                    - VDSO page
                    - heap memory for each process
        - Write XOR Execute
            - NX bit used by AMD 64-bit processors and the XD (also known as ED) bit used by Intel processors provide protection through a form of W^X (Write XOR Execute) on Linux.
    - Bypassing protections
        - Egg hunting
            - after initial shellcode execution, search for the unique tag prepended to the additional shellcode already on machine
                - Once the tag is discovered, the appended shellcode is immediately executed
- Return-Oriented Programming
    - used when we can't inject shellcode into memory, instead we just use bbytes that are already there
    - demonstrated to defeat hardware Data Execution Prevention (DEP)
    - string together tons of gadgets to achieve a shellcode-like execution path
        - gadgets are executable blocks of code typically already loaded into memory
            - sequences of instructions that perform a desired operation and are usually followed by a return
        - we can literally cherry-pick bytes of instructions for our own purposes
    - ROP Shellcode
        - new goal of executing an `execve()` system call requires:
            1. AL register contains the system call number (0x0b in this case)
            2. base pointer BX holds the pointer to the argument for execve
            3. count register CX points to the argument vector ARGV pointer array
            4. data register DX points to ENVP array (environment variable pointer)
    - Stack Pivoting
        - allows us to move the position of the stack pointer to point away from the stack and onto another area in memory
            - only the stack pointer can use the `push`, `pop`, and `ret` instrucitons, which may be held at a different memory region than on the stack
        - uses the `xchg` instruction in assembly
    - PUSHAD instruction pushes each register onto the stack in the following order: EAX, ECX, EDX, EBX, original ESP, EBP, ESI, and EDI.
        - instead of having to find multiple instructions/gadgets to obtain the same result.


    


### 2) Windows
- Background
    - Two Access Modes
        - Ring 0 Kernel mode
            - core OS and drivers, hardware interactions, interrupts, concurrency
            - Kernel memory shares a single address space, unlike user-mode applications. On 32-bit systems, the kernel can easily access all memory on all processes with unlimited control.
            - shared memory for all kernel mode processes
                - 32-bit machines unlimited control for all processes
                - 64-bit machines introduced KMCS which requires a CA to vouch for a driver when trying to access memory/address space
        - Ring 3 User mode = application code and drivers
            - Immunity Debugger is a Ring 3 debugger, it does not have visibility in Ring 0 instructions
                - address 0x704050F0 should show up in the disassembler pane since that is a memory address assigned to the user memory pool (ring 3), which goes from 0x00000000 to 0x7fffffff. 
                - On the other side, the kernel memory pool goes from 0x80000000 to 0xffffffff, and Immunity Debugger (as well as other userland debuggers) is incapable of debugging kernel memory addresses (ring 0)
    - Differences from Linux
        - Windows API calls replace Linux system calls
            - Kernel32.dll, kernelbase.dll, ntdll.dll are always loaded
        - PE/COFF
            - DOS MZ header. You will most commonly see the hex value "4D 5A" as the first value. The magic number 4D 5A translates from hex to ASCII as MZ, which stands for Mark Zbikowski, one of the original DOS developers. 
                - This header also has a stub area. An example of when the code in this stub area is executed is when a user attempts to run the file under DOS. The following message would display in this case: "This program cannot be run in DOS mode."
            - replace ELF in Linux
            - DLL and Executable formats
            - Import Address Table
                - Windows equivalent of PLT in Linux
                - holds symbols that require resolution from external DLLs upon runtime
                - if the executable makes use of an external library, this function must be listed in the IAT
            - Export Address Table
                - Windows equivalent of Linux GOT
                - holds symbols that can be used by other DLL/PE files
                - contains the RVA of the requested functions, which must be added to the load address to get logical address
        - Threading is used on Windows as opposed to forking
            - threads share same address space and ID as parent process and can inherit attributes 
            - Thread Information Block TIB
                - FS segment register holds location in 32-bit proc, GS segment register on 64-bit
                - The address of the TIB can be found at offset 0x18 within the FS segment register. The other offsets hold different information:
                - holds: 
                    - pointer to structured error handling seh chain
                    - address of Process Environment Block PEB
                        - PEB contains process-specfici information including base address of the image, heap address, and imported modules
    - Structured Exception Handling SEH
        - if exception occurs, Windows OS uses callback function to handle the exception
            - callback function is defined in TIB
        - an entire chain of what to do in the case of exceptions is defined
            - if none of these contraints are met, an unhandled exception will terminate process
            - If the end of the SEH chain is reached, the Windows Unhandled_Exception_Handler handles the exception, typically terminating the process 
        - ESP+8 is holding a pointer back to the "next structured exception handling" (NSEH) position on the stack associated with this SEH call
    - WOW64
        - set of DLLs used to translate 32-bit applications on a 64-bit machine
- Exploit Mitigation Controls (quick reference at book 5, page 60)
    - OS controls
        - system-enforced and cannot be disabled by an application
        - Data Execution Prevention
            - marks memory pages as nonexecutable (ie stack or heap cannot contain executable code)
            - hardware-based controls in which processor marks memory pages with a flag as they are allocated by the processor
                - NX No execute bit on AMD
                - XD Execute Disable on Intel
            - Software DEP is supported even if hardware DEP is not available. However, software DEP only prevents structured exception handling (SEH) attacks, using SafeSEH.
            - SEHOP Structured Exception Handling Overwrite Protection
                - idea is that if an error handler address is overwritten, the entire chain will never be able to be walked fully
                - SEHOP puts a special character at the end of the chain and walks the entire chain before implementing the handling functions
                    - if chain never reaches the special character, the chain does not execute
                - SEHOP inserts a symbolic record called the "FinalExceptionHandler" at the end of the SEH chain in ntdll.dll, ensuring that the SEH chain is intact before passing control to the handler
            - hardware-based DEP in Windows (book 5, page 87)
                - default only for essential Windows services and applications
                - flagged for DEP in ProcessExecuteFlags ProcessInformationClass
                    - goal is to overwrite the ProcessExecuteFlags to set DEP to disabled using the ZwSetInformationProcess() in ntdll
                    - can be done with ROP (lab 5.3, page 397)
                - this still requires stack overflows, but changing the return pointer can lead to execution    
                    - canaries can still stop this from happening, but not if we use SEH overwrite
        - PEB randomization 
            - PEB is a structure that holds image and load library addresses
            - reachabkle by dereferencing FS:[0x30]
        - Safe Unlinking
        - ASLR cannot be disabled
        - Control Flow Guard CFG
            - identifies addresses deemed as safe entry point for indirect calls and only allows execution to occur if the indirect call exists within a block where a true function call entry point exists
                - stores this info in a bitmap that is checked prior to allowing execution of indirect calls
            - you must use a gadget within a block of code that contains at least one function entry point
        - Control flow Integrity and Control Flow Enforcement CFI CET
            - Shadow stacks
                - essentially a second stack
                    - this second stack only allows the `call` instruction to write a copy of the return address used in the call chain
                - before returning execution to the return pointer address, the shadow stack is checked
                    - if shadow stack EBP and regular EBP do not match, exception is thrown
            - Indirect branch tracking
                - injects an instruction `ENDBR32` and `ENDBR64` after each `call` instruction
                - OS throws exception if this is not the next instruction
    - Compile time controls
        - added at compilation and include code or metadata into a program
        - SafeSEH protections
            - builds table of all valid error handlers inside DLL and checks if ever overwritten by an attack
            - requires all imported modules to participate, otherwise basically ineffective
            - Beginning with Windows XP SP2, the SafeSEH compiler option was added to provide protection against common attacks on structured exception handling (SEH) overwrites. When this flag is used during compile time, the linker builds a table of good exception handlers that may be used. If the exception handler is overwritten and the address is not listed in the table as a valid handler, the program terminates and control is not passed to the unknown address.
        - Cookies/Canaries
            - Low Fragmentation Heap LFH encodes 32-bits
        - MemGC
            - Deferred Frees
                - instead of immediate release once freed, they are held onto and not released until a threshold is met
                - MemGC replaced this
            - checks for references to any objects marked to be freed
                - an object marked to be freed with references that still exist will cause an exception and prevent exploitation
        - Isolated Heaps
            - object allocations are not made part of the standard process heap but are now isolated
            - replacement of freed objects much more difficult
        - Dyanmic Base
    - ExploitGuard
        - Windows 10+ replacement for EMET
        - Untrusted fonts
        - Core isolation
        - BASLR
        - ACG
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
- Disabling DEP
    - done through ROP
    - VirtualProtect() function is used to disable Data Execution Prevention (DEP) in a desired range of memory. It does not affect the whole process and is used to mark the area of memory that contains the shellcode as executable. 
    - SetProcessDEPPolicy() changes the DEP policy for the whole process.
# Miscellaneous
### Passwords 
- Password Lists
    - COMB Compilation of Many Breaches
    - The Probable Password List
- [Coalfire's NPK AWS-Managed Rig](https://github.com/c6fc/npk)