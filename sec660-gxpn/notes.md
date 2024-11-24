## Network Admission Control (NAC)
- NAC provides some level of security or requirement to ensure that authenticated or authorized devices can gain access to the network
- Captive portals act as an intermediate network, drop most traffic until successful authentication
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


## Passwords 
- Password Lists
    - COMB Compilation of Many Breaches
    - The Probable Password List
- [Coalfire's NPK AWS-Managed Rig](https://github.com/c6fc/npk)