#!/bin/bash

# some quick colors
RED="\033[1;31m"
BLUE="\033[1;34m"
BLUE2="\033[0;34m"
RESET="\033[0m"
BOLD="\e[1m"

# some cool variables
scantype="default"
options="a"

# heading!

echo -e "${RED}"
echo -e " ##################################################################################"
echo -e "#${BLUE}░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░${RED}#"
echo -e "#${BLUE}░░      ░░  ░░░░  ░        ░░      ░░░      ░░       ░░        ░        ░       ░░${RED}#"
echo -e "#${BLUE}▒  ▒▒▒▒  ▒  ▒▒▒▒  ▒▒▒▒  ▒▒▒▒  ▒▒▒▒  ▒  ▒▒▒▒▒▒▒  ▒▒▒▒  ▒  ▒▒▒▒▒▒▒  ▒▒▒▒▒▒▒  ▒▒▒▒  ▒${RED}#"
echo -e "#${BLUE}▓  ▓▓▓▓  ▓  ▓▓▓▓  ▓▓▓▓  ▓▓▓▓  ▓▓▓▓  ▓▓      ▓▓       ▓▓      ▓▓▓      ▓▓▓  ▓▓▓▓  ▓${RED}#"
echo -e "#${BLUE}█        █  ████  ████  ████  ████  ███████  █  ███████  ███████  ███████  ████  █${RED}#"
echo -e "#${BLUE}█  ████  ██      █████  █████      ███      ██  ███████        █        █       ██${RED}#"
echo -e "#${BLUE}██████████████████████████████████████████████████████████████████████████████████${RED}#"
echo -e "#${BLUE2}████████████  ${BOLD}Auto${BLUE2}mated ${BOLD}S${BLUE2}can ${BOLD}P${BLUE2}arse ${BOLD}E${BLUE2}numerate ${BOLD}E${BLUE2}xploit ${BOLD}D${BLUE2}ata Collection  ████████████${RED}#"
echo -e "#${BLUE2}▓▓▓▓▓▓▓▓▓▓▓▓                    Script Version 1.0                    ▓▓▓▓▓▓▓▓▓▓▓▓${RED}#"
echo -e "#${BLUE}▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                                      ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒${RED}#"
echo -e "#${BLUE2}░░░░░░░░░░░░░░░░░░░░░░    by Chris McMahon and Kyle Hoehn   ░░░░░░░░░░░░░░░░░░░░░░${RED}#"
echo -e "#${BLUE}░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░${RED}#"
echo -e " ##################################################################################"
echo -e "${RESET}"

# root check

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo -e "[${RED}!${RESET}] Must be running with sudo. Quitting.\n"
    exit
fi

# processing options

while getopts 'c:t:s:e:o:h' opt; do
  case "$opt" in
    c)
      clientcode="$OPTARG"
      echo -e "[${BLUE}*${RESET}] Setting client code to '$clientcode'"
      ;;
    t)
      targetfile="$OPTARG"
      echo -e "[${BLUE}*${RESET}] Setting target file to '$targetfile'"
      ;;

    s)
      scantype="$OPTARG"
      echo -e "[${BLUE}*${RESET}] Setting scan type to '$scantype'"
      ;;
      
    e)
      exclusions="$OPTARG"
      echo -e "[${BLUE}*${RESET}] Setting exclusions file to '$exclusions'"
      ;;

    o)
      options="$OPTARG"
      echo -e "[${BLUE}*${RESET}] Setting options to '$options'"
      ;;

    h)
      echo -e "[${BLUE}*${RESET}] Usage: $(basename $0) -c clientcode -t targetfile -s scantype [options]"
      echo -e "              -h:  print this help dialog"
      echo -e "              -c:  specify client code"
      echo -e "              -t:  specify target file with IP addresses or ranges to scan"
      echo -e "              -s:  specify scan type"
      echo -e "                   scan types:"
      echo -e "                   default:  top 1000 TCP ports scan"
      echo -e "                   allports: full port TCP scan"
      echo -e "                   nodisc:   skip host discovery"
      echo -e "                   seg:      segmentation scanning for TCP and UDP ONLY"
      echo -e "                   egress:   egress scanning ONLY"
      echo -e "              -o:  optional scan skipping"
      echo -e "                   e:  skip egress scanning"
      echo -e "                   u:  skip UDP scanning"
      echo -e "                   eu:  skip egress and UDP scanning"
      echo -e "              -e:  specify exclusions file\n"
      exit 0
      ;;

    :)
      echo -e "[${RED}!${RESET}] Option requires an argument.\n\n    For usage, use $(basename $0) -h"
      exit 1
      ;;

    ?)
      echo -e "[${RED}!${RESET}] For usage, use $(basename $0) -h"
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

sleep 2

echo -e "[${BLUE}*${RESET}] And away we go.....\n"

# Check for missing arguments

if [ -z "$clientcode" ]; then
        echo -e "[${RED}!${RESET}] .....just kidding. Missing required client code.\n\n    For usage, use $(basename $0) -h"
        exit 1
fi

# make directory structure

echo -e "[${BLUE}*${RESET}] Creating directory structure..."

  mkdir ./${clientcode}
  mkdir ./${clientcode}/scans
  mkdir ./${clientcode}/other
  echo -e "[${BLUE}*${RESET}] Directory structure created successfully. Continuing.\n"
  
sleep 2

if [[ "$scantype" == "egress" ]]; then
        echo -e "[${BLUE}*${RESET}] Starting egress scans...\n"
        sudo nmap -Pn -p- egadz.metasploit.com -oA ./${clientcode}/scans/${clientcode}_egress_fullport
        sudo nmap -Pn --top-ports 40 egadz.metasploit.com -oN ./${clientcode}/scans/${clientcode}_egress_top_40
        echo -e "\n[${BLUE}*${RESET}] Egress scans completed! \n"
        exit 0
fi

if [ -z "$targetfile" ] || [ -z "$clientcode" ]; then
        echo -e "[${RED}!${RESET}] .....just kidding. Missing required target file.\n\n    For usage, use $(basename $0) -h"
        exit 1
fi

sleep 2

# checking for wrong scan argument

if [[ "$scantype" != "default" ]] && [[ "$scantype" != "allports" ]] && [[ "$scantype" != "nodisc" ]] && [[ "$scantype" != "seg" ]] && [[ "$scantype" != "egress" ]]; then
        echo -e "[${RED}!${RESET}] .....just kidding. Wrong scan type.\n"
        exit 1
fi

# check for exclusions file, creating temporary one if it doesn't exist

if [ -z "$exclusions" ]; then
        touch exclude.tmp
        exclusions=exclude.tmp        
fi

# start scanning

if [[ "$scantype" == "allports" ]]; then
        echo -e "[${BLUE}*${RESET}] Starting full port TCP nmap scan...\n"
        tcpscanoutput="./${clientcode}/scans/${clientcode}_tcp_fullport"
        tcpgreppable="./${clientcode}/scans/${clientcode}_tcp_fullport.gnmap"
        sudo nmap -iL $targetfile -R -p- --max-retries=5 --stats-every=2m --excludefile ${exclusions} -oA ${tcpscanoutput}
        echo -e "\n[${BLUE}*${RESET}] Full port TCP nmap completed!\n"

fi

if [[ "$scantype" == "default" ]]; then
        echo -e "[${BLUE}*${RESET}] Starting top 1000 TCP nmap scan...\n"
        tcpscanoutput="./${clientcode}/scans/${clientcode}_tcp_top1000"
        tcpgreppable="./${clientcode}/scans/${clientcode}_tcp_top1000.gnmap"
        sudo nmap -iL $targetfile -R --top-ports 1000 --max-retries=5 --stats-every=2m --excludefile ${exclusions} -oA ${tcpscanoutput}
        echo -e "\n[${BLUE}*${RESET}] TCP top 1000 ports nmap scan completed!\n"
fi

if [[ "$scantype" == "nodisc" ]]; then
        echo -e "[${BLUE}*${RESET}] Starting top 1000 TCP nmap scan with no host discovery...\n"
        tcpscanoutput="./${clientcode}/scans/${clientcode}_tcp_top1000_nodisc"
        tcpgreppable="./${clientcode}/scans/${clientcode}_tcp_top1000_nodisc.gnmap"
        sudo nmap -iL $targetfile -R --top-ports 1000 --max-retries=5 --stats-every=2m -Pn --excludefile ${exclusions} -oA ${tcpscanoutput}
        echo -e "\n[${BLUE}*${RESET}] TCP top 1000 ports nmap scan completed!\n"
fi

if [[ "$scantype" == "seg" ]]; then
        echo -e "[${BLUE}*${RESET}] Starting segmentation TCP nmap scan...\n"
        tcpscanoutput="./${clientcode}/scans/${clientcode}_tcp_seg"
        sudo nmap -iL $targetfile -Pn -p- --max-retries=5 --stats-every=2m --excludefile ${exclusions} -oA ${tcpscanoutput}
        echo -e "\n[${BLUE}*${RESET}] TCP top 1000 ports nmap scan completed!\n"
        echo -e "[${BLUE}*${RESET}] Starting segmentation UDP nmap scan...\n"
        udpscanoutput="./${clientcode}/scans/${clientcode}_udp_CDE"
        sudo nmap -iL $targetfile -sU -Pn --top-ports 100 --max-retries=5 --excludefile ${exclusions} --stats-every=2m -oA ${udpscanoutput}
        echo -e "\n[${BLUE}*${RESET}] UDP nmap scan completed!\n"
        exit 0
fi

# varying variables

varTempRandom=$(( ( RANDOM % 9999 ) + 1 ))
varTempFile="temp-nmp-$varTempRandom.txt"
if [ -f "$varTempFile" ]; then rm $varTempFile; fi
varDoSummary="Y"
varDoSplit="Y"
varRenameSplit="Y"
varDoWebUrl="Y"
varDoSmbUrl="Y"
varDoLiveHosts="Y"
varInFile=$tcpgreppable
varChangeOutDir="Y"
varCustomOut="./${clientcode}/scans/${clientcode}_parsed"
varOutPath="${varCustomOut}/"
varWorkingDir="$(pwd)"

# parsing function
# parsing script (https://github.com/actuated/nmap-grep/blob/master/nmap-grep.sh)

parsing() {

echo -e "[${BLUE}*${RESET}] Parsing nmap output "
echo -e "    File: ${tcpgreppable}"

    if [ ! -e "$varCustomOut" ]; then
      mkdir "$varCustomOut"
    else
      varFlagOutExists="Y"
    fi
sleep 2

# Read input file for up-hosts.txt
if [ "$varDoLiveHosts" = "Y" ]; then
  varLine=""
  varLastIP=""
  while read varLine; do
    varOutIP=""
    varOutIP=$(echo $varLine | grep 'Status: Up' | awk '{print $2}')
    if [ "$varOutIP" != "" ] && [ "$varOutIP" != "$varLastIP" ]; then echo "$varOutIP" >> ${varOutPath}up-hosts.txt; varLastIP=$varOutIP; fi
  done < $varInFile
fi

# Process each comma-separated open port result to the CSV temp file, with the host IP
varLine=""
while read varLine; do
  varCheckForOpen=""
  varCheckForOpen=$(echo $varLine | grep '/open/')
  if [ "$varCheckForOpen" != "" ]; then
    varLineHost=$(echo $varLine | awk '{print $2}')
    varLinePorts=$(echo $varLine | awk '{$1=$2=$3=$4=""; print $0}')
# Create temporary file to write each port result for this host
      varTempRandom2=$(( ( RANDOM % 9999 ) + 1 ))
      varTempFile2="temp-nmp2-$varTempRandom2.txt"
      if [ -f "$varTempFile2" ]; then rm $varTempFile2; fi
      echo "$varLinePorts" | tr "," "\n" | sed 's/^ *//g' >> $varOutPath$varTempFile2
# Read the per-host temp file to write each open port as a line to the CSV temp file
    while read varTempLine; do
      varCheckForOpen=""
      varCheckForOpen=$(echo $varTempLine | grep "/open/")
      if [ "$varCheckForOpen" != "" ]; then
        varLinePort=$(echo $varTempLine | awk -F '/' '{print $1}')
        varLineTCPUDP=$(echo $varTempLine | awk -F '/' '{print $3}')
        varLineProto=$(echo $varTempLine | awk -F '/' '{print $5}')
        varLineSvc=$(echo $varTempLine | awk -F '/' '{print $7}')
        echo "$varLineHost,$varLinePort,$varLineTCPUDP,$varLineProto,$varLineSvc" >> $varOutPath$varTempFile
      fi
    done < $varOutPath$varTempFile2
    rm $varOutPath$varTempFile2
  fi
done < $varInFile

mv $varOutPath$varTempFile ${varOutPath}unsorted.txt
cat ${varOutPath}unsorted.txt | sort -V | uniq > $varOutPath$varTempFile
rm ${varOutPath}unsorted.txt

# Create summary file
if [ "$varDoSummary" = "Y" ] && [ -e "$varOutPath$varTempFile" ]; then
  echo "+------------------+--------------+-----------------------------------------------------+" >> ${varOutPath}summary.txt
  printf "%-18s %-14s %-52.52s %-2s \n" "| HOST " "| OPEN PORT " "| PROTOCOL - SERVICE" " |" >> ${varOutPath}summary.txt
  varLastHost=""
  while read varLine; do
    varLineHost=""
    varLinePort=""
    varLineTCPUDP=""
    varLineProto=""
    varLineSvc=""
    varLineHost=$(echo $varLine | awk -F ',' '{print $1}')
    varLinePort=$(echo $varLine | awk -F ',' '{print $2}')
    varLineTCPUDP=$(echo $varLine | awk -F ',' '{print $3}')
    varLineProto=$(echo $varLine | awk -F ',' '{print $4}')
    varLineSvc=$(echo $varLine | awk -F ',' '{print $5}')
    if [ "$varLineHost" != "$varLastHost" ]; then echo "+------------------+--------------+-----------------------------------------------------+" >> ${varOutPath}summary.txt; fi
    if [ "$varLineSvc" = "" ]; then
      varLineSvc=""
    else
      varLineSvc="- $varLineSvc"
    fi
    printf "%-18s %-14s %-52.52s %-2s \n" "| $varLineHost " "| $varLinePort / $varLineTCPUDP " "| $varLineProto $varLineSvc" " |" >> ${varOutPath}summary.txt
    varLastHost="$varLineHost"
  done < $varOutPath$varTempFile
  echo "+------------------+--------------+-----------------------------------------------------+" >> ${varOutPath}summary.txt
fi

# Create split hosts files for each protocol
if [ "$varDoSplit" = "Y" ]; then
  while read varLine; do
    varLineHost=""
    varLinePort=""
    varLineTCPUDP=""
    varLineHost=$(echo $varLine | awk -F ',' '{print $1}')
    varLinePort=$(echo $varLine | awk -F ',' '{print $2}')
    varLineTCPUDP=$(echo $varLine | awk -F ',' '{print $3}')
    echo $varLineHost >> $varOutPath${varLinePort}-${varLineTCPUDP}-hosts.txt
  done < $varOutPath$varTempFile
fi

# Rename hosts files for common protocols
if [ "$varRenameSplit" = "Y" ]; then
  if [ -f "${varOutPath}21-tcp-hosts.txt" ]; then mv ${varOutPath}21-tcp-hosts.txt ${varOutPath}ftp-hosts.txt; fi
  if [ -f "${varOutPath}22-tcp-hosts.txt" ]; then mv ${varOutPath}22-tcp-hosts.txt ${varOutPath}ssh-hosts.txt; fi
  if [ -f "${varOutPath}23-tcp-hosts.txt" ]; then mv ${varOutPath}23-tcp-hosts.txt ${varOutPath}telnet-hosts.txt; fi
  if [ -f "${varOutPath}25-tcp-hosts.txt" ]; then mv ${varOutPath}25-tcp-hosts.txt ${varOutPath}smtp-hosts.txt; fi
  if [ -f "${varOutPath}53-tcp-hosts.txt" ]; then mv ${varOutPath}53-tcp-hosts.txt ${varOutPath}dns-tcp-hosts.txt; fi
  if [ -f "${varOutPath}53-udp-hosts.txt" ]; then mv ${varOutPath}53-udp-hosts.txt ${varOutPath}dns-udp-hosts.txt; fi
  if [ -f "${varOutPath}69-udp-hosts.txt" ]; then mv ${varOutPath}69-udp-hosts.txt ${varOutPath}tftp-hosts.txt; fi
  if [ -f "${varOutPath}80-tcp-hosts.txt" ]; then mv ${varOutPath}80-tcp-hosts.txt ${varOutPath}http-hosts.txt; fi
  if [ -f "${varOutPath}110-tcp-hosts.txt" ]; then mv ${varOutPath}110-tcp-hosts.txt ${varOutPath}pop3-hosts.txt; fi
  if [ -f "${varOutPath}123-udp-hosts.txt" ]; then mv ${varOutPath}123-udp-hosts.txt ${varOutPath}ntp-hosts.txt; fi
  if [ -f "${varOutPath}143-tcp-hosts.txt" ]; then mv ${varOutPath}143-tcp-hosts.txt ${varOutPath}imap-hosts.txt; fi
  if [ -f "${varOutPath}161-udp-hosts.txt" ]; then mv ${varOutPath}161-udp-hosts.txt ${varOutPath}snmp-hosts.txt; fi
  if [ -f "${varOutPath}162-udp-hosts.txt" ]; then mv ${varOutPath}162-udp-hosts.txt ${varOutPath}snmptrap-hosts.txt; fi
  if [ -f "${varOutPath}179-tcp-hosts.txt" ]; then mv ${varOutPath}179-tcp-hosts.txt ${varOutPath}bgp-hosts.txt; fi
  if [ -f "${varOutPath}389-tcp-hosts.txt" ]; then mv ${varOutPath}389-tcp-hosts.txt ${varOutPath}ldap-hosts.txt; fi
  if [ -f "${varOutPath}443-tcp-hosts.txt" ]; then mv ${varOutPath}443-tcp-hosts.txt ${varOutPath}https-hosts.txt; fi
  if [ -f "${varOutPath}445-tcp-hosts.txt" ]; then mv ${varOutPath}445-tcp-hosts.txt ${varOutPath}smb-hosts.txt; fi
  if [ -f "${varOutPath}465-tcp-hosts.txt" ]; then mv ${varOutPath}465-tcp-hosts.txt ${varOutPath}smtps-hosts.txt; fi
  if [ -f "${varOutPath}500-udp-hosts.txt" ]; then mv ${varOutPath}500-udp-hosts.txt ${varOutPath}ike-hosts.txt; fi
  if [ -f "${varOutPath}513-tcp-hosts.txt" ]; then mv ${varOutPath}513-tcp-hosts.txt ${varOutPath}rlogin-hosts.txt; fi
  if [ -f "${varOutPath}514-tcp-hosts.txt" ]; then mv ${varOutPath}514-tcp-hosts.txt ${varOutPath}remoteshell-hosts.txt; fi
  if [ -f "${varOutPath}636-tcp-hosts.txt" ]; then mv ${varOutPath}636-tcp-hosts.txt ${varOutPath}ldaps-hosts.txt; fi
  if [ -f "${varOutPath}873-tcp-hosts.txt" ]; then mv ${varOutPath}873-tcp-hosts.txt ${varOutPath}rsync-hosts.txt; fi
  if [ -f "${varOutPath}989-tcp-hosts.txt" ]; then mv ${varOutPath}989-tcp-hosts.txt ${varOutPath}ftps-data-hosts.txt; fi
  if [ -f "${varOutPath}990-tcp-hosts.txt" ]; then mv ${varOutPath}990-tcp-hosts.txt ${varOutPath}ftps-hosts.txt; fi
  if [ -f "${varOutPath}992-tcp-hosts.txt" ]; then mv ${varOutPath}992-tcp-hosts.txt ${varOutPath}telnets-hosts.txt; fi
  if [ -f "${varOutPath}993-tcp-hosts.txt" ]; then mv ${varOutPath}993-tcp-hosts.txt ${varOutPath}imaps-hosts.txt; fi
  if [ -f "${varOutPath}995-tcp-hosts.txt" ]; then mv ${varOutPath}995-tcp-hosts.txt ${varOutPath}pop3s-hosts.txt; fi
  if [ -f "${varOutPath}1433-tcp-hosts.txt" ]; then mv ${varOutPath}1433-tcp-hosts.txt ${varOutPath}mssql-hosts.txt; fi
  if [ -f "${varOutPath}3389-tcp-hosts.txt" ]; then mv ${varOutPath}3389-tcp-hosts.txt ${varOutPath}rdp-hosts.txt; fi
  if [ -f "${varOutPath}5432-tcp-hosts.txt" ]; then mv ${varOutPath}5432-tcp-hosts.txt ${varOutPath}postgresql-hosts.txt; fi
  if [ -f "${varOutPath}8080-tcp-hosts.txt" ]; then mv ${varOutPath}8080-tcp-hosts.txt ${varOutPath}http-8080-hosts.txt; fi
  if [ -f "${varOutPath}8443-tcp-hosts.txt" ]; then mv ${varOutPath}8443-tcp-hosts.txt ${varOutPath}http-8443-hosts.txt; fi
fi

# Create web-urls.txt
if [ "$varDoWebUrl" = "Y" ]; then
  while read varLine; do
    varLineHost=""
    varLinePort=""
    varLineHost=$(echo $varLine | awk -F ',' '{print $1}')
    varLinePort=$(echo $varLine | awk -F ',' '{print $2}')
    if [ "$varLinePort" = "80" ]; then echo "http://${varLineHost}/" >> ${varOutPath}web-urls.txt; fi
    if [ "$varLinePort" = "443" ]; then echo "https://${varLineHost}/" >> ${varOutPath}web-urls.txt; fi
    if [ "$varLinePort" = "8080" ]; then echo "http://${varLineHost}:8080/" >> ${varOutPath}web-urls.txt; fi
    if [ "$varLinePort" = "8443" ]; then echo "https://${varLineHost}:8443/" >> ${varOutPath}web-urls.txt; fi
  done < $varOutPath$varTempFile
fi

# Create smb-urls.txt
if [ "$varDoSmbUrl" = "Y" ]; then
  while read varLine; do
    varLineHost=""
    varLinePort=""
    varLineHost=$(echo $varLine | awk -F ',' '{print $1}')
    varLinePort=$(echo $varLine | awk -F ',' '{print $2}')
    if [ "$varLinePort" = "445" ]; then echo "smb://${varLineHost}/" >> ${varOutPath}smb-urls.txt; fi
  done < $varOutPath$varTempFile
fi

rm $varOutPath$varTempFile

echo -e "[${BLUE}*${RESET}] TCP parsing complete!\n"
}

parsing

# more varying variables

parsedtargetfile="./${clientcode}/scans/${clientcode}_parsed/up-hosts.txt"

# UDP scan and parse

if [[ "$options" != *"u"* ]]; then
        echo -e "[${BLUE}*${RESET}] Starting UDP nmap scan...\n"
        udpscanoutput="./${clientcode}/scans/${clientcode}_udp"
        udpgreppable="./${clientcode}/scans/${clientcode}_udp.gnmap"
        sudo nmap -iL $parsedtargetfile -sU -R -p53,161,623 --max-retries=5 --excludefile ${exclusions} --stats-every=2m -oA ${udpscanoutput}
        echo -e "\n[${BLUE}*${RESET}] UDP nmap scan completed!\n"

	if [ -f "$udpgreppable" ]; then
  	  cat ${udpgreppable} | grep "53/open/udp" | cut -d ' ' -f 2 > ./${clientcode}/scans/${clientcode}_parsed/dns_hosts.txt
	fi

	if [ -f "$udpgreppable" ]; then
	  cat ${udpgreppable} | grep "161/open/udp" | cut -d ' ' -f 2 > ./${clientcode}/scans/${clientcode}_parsed/snmp_hosts.txt
	fi

	if [ -f "$udpgreppable" ]; then
	  cat ${udpgreppable} | grep "623/open/udp" | cut -d ' ' -f 2 > ./${clientcode}/scans/${clientcode}_parsed/ipmi_hosts.txt
	fi

# cleanup of blank files

  find ./${clientcode}/scans/${clientcode}_parsed -size 0 -print -delete

	echo -e "[${BLUE}*${RESET}] UDP parsing and cleanup complete!\n"
fi

if [[ "$options" != *"e"* ]]; then
        echo -e "[${BLUE}*${RESET}] Starting egress scans...\n"
        sudo nmap -Pn -vv --reason -p- egadz.metasploit.com -oA ./${clientcode}/scans/${clientcode}_egress_fullport
        sudo nmap -Pn -vv --reason --top-ports 40 egadz.metasploit.com -oN ./${clientcode}/scans/${clientcode}_egress_top_40
        echo -e "\n[${BLUE}*${RESET}] Egress scans completed! \n"
fi

# remove temporary exclusions file

tempfile=exclude.tmp
if [ -f "$tempfile" ]; then
    rm exclude.tmp
fi

sleep 2

# SMB Time!

echo -e "[${BLUE}*${RESET}] Starting SMB Enumeration!\n"

# make directory structure
sleep 2

smbdir=./${clientcode}/smb
echo -e "[${BLUE}*${RESET}] Creating 'smb' directory..."

if [ -d "$smbdir" ];
then
    echo -e "[${RED}!${RESET}] Directory 'smb' already exists. Skipping.\n"
else
  mkdir ./${clientcode}/smb
  echo -e "[${BLUE}*${RESET}] Directory 'smb' created successfully. Continuing.\n"
fi

sleep 2

# crackmapexec time!

echo -e "[${BLUE}*${RESET}] Running Crackmapexec...\n"
crackmapexec smb $targetfile --gen-relay-list ./${clientcode}/smb/cme_relay_hosts.txt | tee ./${clientcode}/smb/cme.out
if [ -f "./${clientcode}/smb/cme_relay_hosts.txt" ]; then
    echo -e "[${BLUE}+${RESET}] SMB relay targets list successfully generated."
    numRelay=$(cat ./${clientcode}/smb/cme_relay_hosts.txt | wc -l)
    echo -e "[${BLUE}+${RESET}] $numRelay hosts can be relayed to."
else 
    echo -e "[${RED}!${RESET}] No targets can be relayed to, but still parsing CME output.\n"
fi
cat ./${clientcode}/smb/cme.out | grep -a "signing:False" > ./${clientcode}/smb/no_signing.out
cat ./${clientcode}/smb/cme.out | grep -a "SMBv1:True" > ./${clientcode}/smb/smbv1.out
cat ./${clientcode}/smb/smbv1.out | cut -d ' ' -f 23 > ./${clientcode}/smb/smbv1_hosts.txt
cat ./${clientcode}/smb/no_signing.out | cut -d ' ' -f 23 > ./${clientcode}/smb/no_signing_hosts.txt

# file check and msfconsole rdp scanner

echo -e "[${BLUE}*${RESET}] Running MSF RDP Check...\n"
rdphosts=${varOutPath}rdp-hosts.txt
if [ -f "$rdphosts" ]; then
    msfconsole -q -x "use auxiliary/scanner/rdp/rdp_scanner; set RHOSTS file:${varWorkingDir}/${clientcode}/scans/${clientcode}_parsed/rdp-hosts.txt; run; exit" | tee ${varWorkingDir}/${clientcode}/other/rdp_scan.out
    cat ./${clientcode}/other/rdp_scan.out | grep -a "NLA: No" > ./${clientcode}/other/rdp_nla.out
    cat ./${clientcode}/other/rdp_nla.out | cut -d ' ' -f 2 | cut -d ':' -f 1 > ./${clientcode}/other/rdp_nla_hosts.txt
    echo -e "\n[${BLUE}*${RESET}] MSF RDP check completed. Check other directory for results.\n"
else 
    echo -e "[${RED}!${RESET}] $rdphosts does not exist. Skipping RDP enumeration.\n"
fi

# file check and msfconsole ipmi scanner

echo -e "[${BLUE}*${RESET}] Running MSF IPMI Scan...\n"
ipmihosts=${varOutPath}ipmi_hosts.txt
if [ -f "$ipmihosts" ]; then
    msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS file:${varWorkingDir}/${clientcode}/scans/${clientcode}_parsed/ipmi_hosts.txt; run; exit" | tee ${varWorkingDir}/${clientcode}/other/ipmi_scan.out
    echo -e "\n[${BLUE}*${RESET}] MSF IPMI scan completed. Check other directory for results.\n"
else 
    echo -e "[${RED}!${RESET}] $ipmihosts does not exist. Skipping IPMI scanning.\n"
fi

# file check and eyewitness

echo -e "[${BLUE}*${RESET}] Running EyeWitness Scan...\n"
webhosts=${varOutPath}web-urls.txt
if [ -f "$webhosts" ]; then
    chmod 777 -R ${varWorkingDir}/${clientcode}
    currentuser=$(who | cut -d " " -f 1 | head -1)
    runuser -l $currentuser -c "eyewitness -f ${varWorkingDir}/${clientcode}/scans/${clientcode}_parsed/web-urls.txt -d ${varWorkingDir}/${clientcode}/other/EyeWitness_output --no-prompt --threads 10 --delay 15"    
    echo -e "\n[${BLUE}*${RESET}] EyeWitness scan completed. Check other directory for results.\n"
else 
    echo -e "[${RED}!${RESET}] ${webhosts} does not exist. Skipping web url scanning.\n"
fi
