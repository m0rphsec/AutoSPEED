# AutoSPEED

**Auto**mated **S**can **P**arse **E**numerate **E**xploit **D**ata Collection

*Automating the easy stuff (for internal network pentesting).*

## Current Capabilities
- Nmap TCP/UDP/Egress scans on a provided scope with the ability to add an exclusion list.
- Parsing of the Nmap results into separate text files for use by other tools.
- CrackMapExec to generate screenshottable output as well as hosts that support SMBv1 or do not have SMB Signing enforced.
- Metasploit RDP NLA checking with an output file created and a list of hosts that do not have NLA enabled.
- Metasploit IPMI scanning to automatically dump hashes of IPMI hosts if vulnerable, with output files.
- Eyewitness scanning of all web URLs.

<sub>Tested on various Kali Linux versions. (what else?)</sub>

## Dependencies

Can be installed by running: 
`sudo ./install-dependencies.sh`

- Nmap (https://nmap.org/)
- crackmapexec (https://github.com/byt3bl33d3r/CrackMapExec)
- Metasploit Framework (https://www.metasploit.com/)
- eyewitness (https://github.com/RedSiege/EyeWitness)

## Usage
From a non-root account, use:
```
sudo ./AutoSpeed.sh (options)
              -h:  print help dialog
              -c:  specify client code (AKA output folder name) (REQUIRED)
              -t:  specify target file with IP addresses or ranges to scan (REQUIRED)
              -s:  specify scan type (OPTIONAL, default is default)
                   scan types:
                   default:  top 1000 TCP ports scan, top 3 UDP, egress
                   allports: full port TCP scan
                   nodisc:   top 1000 skip host discovery
                   seg:      segmentation scanning for TCP and UDP ONLY
                   egress:   egress scanning ONLY
              -o:  optional scan skipping (OPTIONAL)
                   e:  skip egress scanning
                   u:  skip UDP scanning
                   eu:  skip egress and UDP scanning
              -e:  specify exclusions file (OPTIONAL)
```
A non-root account is required for EyeWitness to run correctly, as most browsers do not run correctly as root.

### Example: Print help dialog
`sudo ./Autospeed.sh -h`

### Example: Default Scan
`sudo ./Autospeed.sh -c auto_test -t scope.txt`

## Disclaimer
As a general disclaimer: We are not liable for any issues that may arise from the use of this tool. It is intended solely to assist, completely at a user's discretion, and proper due diligence should be performed before executing any tool on any network.
