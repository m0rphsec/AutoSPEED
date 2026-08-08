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

# ---- tunables ----------------------------------------------------------
# override from the environment, e.g.  IPMI_THREADS=64 ./AutoSPEEDv1.1.sh ...
IPMI_THREADS=${IPMI_THREADS:-128}
IPMI_MAX_ATTEMPTS=${IPMI_MAX_ATTEMPTS:-2}
IPMI_RETRY_DELAY=${IPMI_RETRY_DELAY:-2}
SNMP_CHECK_COUNT=${SNMP_CHECK_COUNT:-5}
EYEWITNESS_THREADS=${EYEWITNESS_THREADS:-10}
EYEWITNESS_DELAY=${EYEWITNESS_DELAY:-15}
NMAP_MAX_RETRIES=${NMAP_MAX_RETRIES:-5}
# ------------------------------------------------------------------------

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
echo -e "#${BLUE2}▓▓▓▓▓▓▓▓▓▓▓▓                    Script Version 1.1                    ▓▓▓▓▓▓▓▓▓▓▓▓${RED}#"
echo -e "#${BLUE}▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                                      ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒${RED}#"
echo -e "#${BLUE2}░░░░░░░░░░░░░░░░░░░░░░    by Chris McMahon and Kyle Hoehn   ░░░░░░░░░░░░░░░░░░░░░░${RED}#"
echo -e "#${BLUE}░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░${RED}#"
echo -e " ##################################################################################"
echo -e "${RESET}"

# ---- logging -----------------------------------------------------------
# every phase is timestamped so scan activity can be proven to fall inside
# a client's authorized scanning window.

LOGFILE=""

log() {
  local m="[$(date -Is)] [*] $*"
  echo -e "[${BLUE}*${RESET}] $*"
  [ -n "$LOGFILE" ] && echo "$m" >> "$LOGFILE"
  return 0
}

ok() {
  local m="[$(date -Is)] [+] $*"
  echo -e "[${BLUE}+${RESET}] $*"
  [ -n "$LOGFILE" ] && echo "$m" >> "$LOGFILE"
  return 0
}

err() {
  local m="[$(date -Is)] [!] $*"
  echo -e "[${RED}!${RESET}] $*"
  [ -n "$LOGFILE" ] && echo "$m" >> "$LOGFILE"
  return 0
}

# ---- temp file cleanup -------------------------------------------------

CLEANUP_FILES=()
cleanup() {
  local f
  for f in "${CLEANUP_FILES[@]}"; do
    [ -n "$f" ] && [ -f "$f" ] && rm -f "$f"
  done
}
trap cleanup EXIT

# root check

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo -e "[${RED}!${RESET}] Must be running with sudo. Quitting.\n"
    exit 1
fi

# DEPENDENCIES Declarations
declare -A DEPS=(
  [nmap]="apt-get install -y nmap"
  [netexec]="apt-get install -y netexec"
  [eyewitness]="apt-get install -y eyewitness"
)

# INSTALL FUNCTION
install_dependencies() {
  echo -e "[${BLUE}+${RESET}] Verifying required tools..."

  local need_update=0

  # Check simple deps
  for cmd in "${!DEPS[@]}"; do
    if command -v "$cmd" &>/dev/null; then
      echo -e "[${BLUE}+${RESET}] $cmd is already installed."
    else
      echo -e "[${RED}!${RESET}] $cmd is missing."
      need_update=1
    fi
  done

  # If any simple deps are missing, update once and install them
  if (( need_update )); then
    echo -e "[${BLUE}+${RESET}] Installing missing packages..."
    apt-get update
    for cmd in "${!DEPS[@]}"; do
      if ! command -v "$cmd" &>/dev/null; then
        echo -e "[${BLUE}+${RESET}] Installing $cmd..."
        ${DEPS[$cmd]}
        echo -e "[${BLUE}+${RESET}] $cmd installation complete."
      fi
    done
  fi

  # Handle msfconsole separately
  if command -v msfconsole &>/dev/null; then
    echo -e "[${BLUE}+${RESET}] msfconsole is already installed."
  else
    echo -e "[${RED}!${RESET}] msfconsole is missing. Installing Metasploit Framework..."
    curl -sSL \
      https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
      -o /tmp/msfinstall.erb
    chmod +x /tmp/msfinstall.erb
    /tmp/msfinstall.erb
    rm /tmp/msfinstall.erb
    echo -e "[${BLUE}+${RESET}] msfconsole installation complete."
  fi

  echo -e "[${BLUE}+${RESET}] All dependencies are satisfied."
}

# check and install dependencies
install_dependencies

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
      echo -e "              -o:  optional scan skipping (combine letters, e.g. -o eur)"
      echo -e "                   e:  skip egress scanning"
      echo -e "                   u:  skip UDP scanning"
      echo -e "                   r:  skip reverse DNS lookups (much faster on large scopes)"
      echo -e "              -e:  specify exclusions file\n"
      echo -e "         Environment tunables:"
      echo -e "              IPMI_THREADS (default 128)      SNMP_CHECK_COUNT (default 5)"
      echo -e "              IPMI_MAX_ATTEMPTS (default 2)   EYEWITNESS_THREADS (default 10)"
      echo -e "              IPMI_RETRY_DELAY (default 2)    EYEWITNESS_DELAY (default 15)"
      echo -e "              NMAP_MAX_RETRIES (default 5)\n"
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

# client code is used to build every output path - keep it to safe characters
if [[ ! "$clientcode" =~ ^[A-Za-z0-9_-]+$ ]]; then
        echo -e "[${RED}!${RESET}] Client code must contain only letters, numbers, dashes and underscores.\n"
        exit 1
fi

# checking for wrong scan argument (moved ahead of any directory creation)

if [[ "$scantype" != "default" ]] && [[ "$scantype" != "allports" ]] && [[ "$scantype" != "nodisc" ]] && [[ "$scantype" != "seg" ]] && [[ "$scantype" != "egress" ]]; then
        echo -e "[${RED}!${RESET}] .....just kidding. Wrong scan type.\n"
        exit 1
fi

# reverse DNS toggle - '-o r' drops -R, which is a large win on big scopes
if [[ "$options" == *"r"* ]]; then
        rdns=""
else
        rdns="-R"
fi

# make directory structure

echo -e "[${BLUE}*${RESET}] Creating directory structure..."

  mkdir -p "./${clientcode}"
  mkdir -p "./${clientcode}/scans"
  mkdir -p "./${clientcode}/other"
  LOGFILE="$(pwd)/${clientcode}/${clientcode}_autospeed.log"
  echo -e "[${BLUE}*${RESET}] Directory structure created successfully. Continuing.\n"

log "AutoSPEED v1.1 run started (client=${clientcode} scantype=${scantype} options=${options})"

sleep 2

if [[ "$scantype" == "egress" ]]; then
        log "Starting egress scans..."
        sudo nmap -Pn -p- egadz.metasploit.com -oA "./${clientcode}/scans/${clientcode}_egress_fullport"
        sudo nmap -Pn --top-ports 40 egadz.metasploit.com -oN "./${clientcode}/scans/${clientcode}_egress_top_40"
        log "Egress scans completed!"
        exit 0
fi

if [ -z "$targetfile" ]; then
        echo -e "[${RED}!${RESET}] .....just kidding. Missing required target file.\n\n    For usage, use $(basename $0) -h"
        exit 1
fi

if [ ! -f "$targetfile" ]; then
        echo -e "[${RED}!${RESET}] Target file '$targetfile' does not exist.\n"
        exit 1
fi

sleep 2

# check for exclusions file, creating temporary one if it doesn't exist

if [ -z "$exclusions" ]; then
        exclusions="$(mktemp)"
        CLEANUP_FILES+=("$exclusions")
fi

# start scanning

if [[ "$scantype" == "allports" ]]; then
        log "Starting full port TCP nmap scan..."
        tcpscanoutput="./${clientcode}/scans/${clientcode}_tcp_fullport"
        tcpgreppable="./${clientcode}/scans/${clientcode}_tcp_fullport.gnmap"
        sudo nmap -iL "$targetfile" $rdns -p- --max-retries="${NMAP_MAX_RETRIES}" --stats-every=2m --excludefile "${exclusions}" -oA "${tcpscanoutput}"
        log "Full port TCP nmap completed!"
fi

if [[ "$scantype" == "default" ]]; then
        log "Starting top 1000 TCP nmap scan..."
        tcpscanoutput="./${clientcode}/scans/${clientcode}_tcp_top1000"
        tcpgreppable="./${clientcode}/scans/${clientcode}_tcp_top1000.gnmap"
        sudo nmap -iL "$targetfile" $rdns --top-ports 1000 --max-retries="${NMAP_MAX_RETRIES}" --stats-every=2m --excludefile "${exclusions}" -oA "${tcpscanoutput}"
        log "TCP top 1000 ports nmap scan completed!"
fi

if [[ "$scantype" == "nodisc" ]]; then
        log "Starting top 1000 TCP nmap scan with no host discovery..."
        tcpscanoutput="./${clientcode}/scans/${clientcode}_tcp_top1000_nodisc"
        tcpgreppable="./${clientcode}/scans/${clientcode}_tcp_top1000_nodisc.gnmap"
        sudo nmap -iL "$targetfile" $rdns --top-ports 1000 --max-retries="${NMAP_MAX_RETRIES}" --stats-every=2m -Pn --excludefile "${exclusions}" -oA "${tcpscanoutput}"
        log "TCP top 1000 ports nmap scan completed!"
fi

if [[ "$scantype" == "seg" ]]; then
        log "Starting segmentation TCP nmap scan..."
        tcpscanoutput="./${clientcode}/scans/${clientcode}_tcp_seg"
        sudo nmap -iL "$targetfile" -Pn -p- --max-retries="${NMAP_MAX_RETRIES}" --stats-every=2m --excludefile "${exclusions}" -oA "${tcpscanoutput}"
        log "Segmentation TCP nmap scan completed!"
        log "Starting segmentation UDP nmap scan..."
        udpscanoutput="./${clientcode}/scans/${clientcode}_udp_CDE"
        sudo nmap -iL "$targetfile" -sU -Pn --top-ports 100 --max-retries="${NMAP_MAX_RETRIES}" --excludefile "${exclusions}" --stats-every=2m -oA "${udpscanoutput}"
        log "UDP nmap scan completed!"
        exit 0
fi

# varying variables

varDoSummary="Y"
varDoSplit="Y"
varRenameSplit="Y"
varDoWebUrl="Y"
varDoSmbUrl="Y"
varDoLiveHosts="Y"
varInFile="$tcpgreppable"
varCustomOut="./${clientcode}/scans/${clientcode}_parsed"
varOutPath="${varCustomOut}/"
varWorkingDir="$(pwd)"
currentuser="${SUDO_USER:-$USER}"

# parsing function
# originally derived from https://github.com/actuated/nmap-grep/blob/master/nmap-grep.sh
# v1.1: rewritten as single-pass awk. The previous implementation forked
# grep/awk/tr/sed several times per host and created a temp file per host,
# which cost ~40s per 2,000 hosts. Output is byte-identical.

parsing() {

  log "Parsing nmap output: ${varInFile}"

  mkdir -p "$varCustomOut"

  if [ ! -f "$varInFile" ]; then
    err "Greppable nmap file '${varInFile}' not found. Skipping parsing."
    return 1
  fi

  # clear previously generated artifacts so re-runs don't append duplicates
  rm -f "${varOutPath}up-hosts.txt" "${varOutPath}summary.txt" \
        "${varOutPath}web-urls.txt" "${varOutPath}smb-urls.txt" \
        "${varOutPath}open-ports.csv" "${varOutPath}"*-hosts.txt 2>/dev/null

  sleep 1

  local csv="${varOutPath}open-ports.csv"

  # ---- live hosts ----
  if [ "$varDoLiveHosts" = "Y" ]; then
    awk -F'\t' '/Status: Up/{split($1,h," "); print h[2]}' "$varInFile" \
      | sort -V -u > "${varOutPath}up-hosts.txt"
  fi

  # ---- open ports -> host,port,proto,service,version ----
  awk -F'\t' '
    /\/open\// {
      split($1, h, " "); host = h[2]
      sub(/^Ports: /, "", $2)
      n = split($2, p, ", ")
      for (i = 1; i <= n; i++) {
        if (p[i] !~ /\/open\//) continue
        split(p[i], f, "/")
        print host "," f[1] "," f[3] "," f[5] "," f[7]
      }
    }' "$varInFile" | sort -V -u > "$csv"

  if [ ! -s "$csv" ]; then
    err "No open ports found in ${varInFile}."
    return 0
  fi

  # ---- summary table ----
  if [ "$varDoSummary" = "Y" ]; then
    awk -F',' -v sep="+------------------+--------------+-----------------------------------------------------+" '
      BEGIN {
        print sep
        printf "%-18s %-14s %-52.52s %-2s \n", "| HOST ", "| OPEN PORT ", "| PROTOCOL - SERVICE", " |"
      }
      {
        if ($1 != last) print sep
        svc = ($5 == "" ? "" : "- " $5)
        printf "%-18s %-14s %-52.52s %-2s \n", "| " $1 " ", "| " $2 " / " $3 " ", "| " $4 " " svc, " |"
        last = $1
      }
      END { print sep }' "$csv" > "${varOutPath}summary.txt"
  fi

  # ---- per-port host files ----
  # sorted by port/proto so only one output file is open at a time
  if [ "$varDoSplit" = "Y" ]; then
    sort -t',' -k2,2n -k3,3 "$csv" | awk -F',' -v p="$varOutPath" '
      {
        f = p $2 "-" $3 "-hosts.txt"
        if (f != prev) { if (prev != "") close(prev); prev = f }
        print $1 >> f
      }
      END { if (prev != "") close(prev) }'
  fi

  # ---- rename common protocol files ----
  if [ "$varRenameSplit" = "Y" ]; then
    rename_port() {
      [ -f "${varOutPath}$1" ] && mv "${varOutPath}$1" "${varOutPath}$2"
      return 0
    }
    rename_port 21-tcp-hosts.txt   ftp-hosts.txt
    rename_port 22-tcp-hosts.txt   ssh-hosts.txt
    rename_port 23-tcp-hosts.txt   telnet-hosts.txt
    rename_port 25-tcp-hosts.txt   smtp-hosts.txt
    rename_port 53-tcp-hosts.txt   dns-tcp-hosts.txt
    rename_port 53-udp-hosts.txt   dns-udp-hosts.txt
    rename_port 69-udp-hosts.txt   tftp-hosts.txt
    rename_port 80-tcp-hosts.txt   http-hosts.txt
    rename_port 110-tcp-hosts.txt  pop3-hosts.txt
    rename_port 123-udp-hosts.txt  ntp-hosts.txt
    rename_port 143-tcp-hosts.txt  imap-hosts.txt
    rename_port 161-udp-hosts.txt  snmp-hosts.txt
    rename_port 162-udp-hosts.txt  snmptrap-hosts.txt
    rename_port 179-tcp-hosts.txt  bgp-hosts.txt
    rename_port 389-tcp-hosts.txt  ldap-hosts.txt
    rename_port 443-tcp-hosts.txt  https-hosts.txt
    rename_port 445-tcp-hosts.txt  smb-hosts.txt
    rename_port 465-tcp-hosts.txt  smtps-hosts.txt
    rename_port 500-udp-hosts.txt  ike-hosts.txt
    rename_port 513-tcp-hosts.txt  rlogin-hosts.txt
    rename_port 514-tcp-hosts.txt  remoteshell-hosts.txt
    rename_port 636-tcp-hosts.txt  ldaps-hosts.txt
    rename_port 873-tcp-hosts.txt  rsync-hosts.txt
    rename_port 989-tcp-hosts.txt  ftps-data-hosts.txt
    rename_port 990-tcp-hosts.txt  ftps-hosts.txt
    rename_port 992-tcp-hosts.txt  telnets-hosts.txt
    rename_port 993-tcp-hosts.txt  imaps-hosts.txt
    rename_port 995-tcp-hosts.txt  pop3s-hosts.txt
    rename_port 1433-tcp-hosts.txt mssql-hosts.txt
    rename_port 3389-tcp-hosts.txt rdp-hosts.txt
    rename_port 5432-tcp-hosts.txt postgresql-hosts.txt
    rename_port 8080-tcp-hosts.txt http-8080-hosts.txt
    rename_port 8443-tcp-hosts.txt http-8443-hosts.txt
  fi

  # ---- web-urls.txt ----
  if [ "$varDoWebUrl" = "Y" ]; then
    awk -F',' '
      $2 == 80   { print "http://"  $1 "/" }
      $2 == 443  { print "https://" $1 "/" }
      $2 == 8080 { print "http://"  $1 ":8080/" }
      $2 == 8443 { print "https://" $1 ":8443/" }' "$csv" > "${varOutPath}web-urls.txt"
  fi

  # ---- smb-urls.txt ----
  if [ "$varDoSmbUrl" = "Y" ]; then
    awk -F',' '$2 == 445 { print "smb://" $1 "/" }' "$csv" > "${varOutPath}smb-urls.txt"
  fi

  log "TCP parsing complete!"
  return 0
}

parsing

# more varying variables

parsedtargetfile="${varOutPath}up-hosts.txt"

# UDP scan and parse

if [[ "$options" != *"u"* ]]; then
      if [ -s "$parsedtargetfile" ]; then
        log "Starting UDP nmap scan..."
        udpscanoutput="./${clientcode}/scans/${clientcode}_udp"
        udpgreppable="./${clientcode}/scans/${clientcode}_udp.gnmap"
        # --script ipmi-version actively solicits an RMCP reply so real BMCs get
        # classified 'open' instead of 'open|filtered' and are not silently dropped
        sudo nmap -iL "$parsedtargetfile" -sU $rdns -p53,161,623 --script ipmi-version \
             --max-retries="${NMAP_MAX_RETRIES}" --excludefile "${exclusions}" --stats-every=2m -oA "${udpscanoutput}"
        log "UDP nmap scan completed!"

        if [ -f "$udpgreppable" ]; then
          awk '/53\/open/  {print $2}' "$udpgreppable" | sort -V -u > "${varOutPath}dns_hosts.txt"
          awk '/161\/open/ {print $2}' "$udpgreppable" | sort -V -u > "${varOutPath}snmp_hosts.txt"
          # match 623/open AND 623/open|filtered - the module bails immediately on
          # hosts that never answer, so including maybes is cheap at high THREADS
          awk '/623\/open/ {print $2}' "$udpgreppable" | sort -V -u > "${varOutPath}ipmi_hosts.txt"
        fi

        log "UDP parsing complete!"
      else
        err "No live hosts file at ${parsedtargetfile}. Skipping UDP scan."
      fi
fi

# cleanup of blank files (runs regardless of whether UDP was skipped)
find "${varCustomOut}" -type f -size 0 -print -delete 2>/dev/null
log "Empty output file cleanup complete."

if [[ "$options" != *"e"* ]]; then
        log "Starting egress scans..."
        sudo nmap -Pn -vv --reason -p- egadz.metasploit.com -oA "./${clientcode}/scans/${clientcode}_egress_fullport"
        sudo nmap -Pn -vv --reason --top-ports 40 egadz.metasploit.com -oN "./${clientcode}/scans/${clientcode}_egress_top_40"
        log "Egress scans completed!"
fi

sleep 2

# SMB Time!

log "Starting SMB Enumeration!"

smbdir="./${clientcode}/smb"
mkdir -p "$smbdir"

sleep 2

# chown/chmod all directories/files in case $currentuser is used for running tools against scan data
sudo chown -R "${currentuser}:${currentuser}" "${varWorkingDir}/${clientcode}"
sudo chmod -R u+rwX,go-rX "${varWorkingDir}/${clientcode}"

# netexec time!
# v1.1: target the hosts with 445 open rather than the entire scope. On a large
# engagement this is the difference between thousands of hosts and millions.

nxctargets="${varOutPath}smb-hosts.txt"
if [ -s "$nxctargets" ]; then
    log "Running Netexec against $(wc -l < "$nxctargets") SMB hosts..."
    netexec smb "$nxctargets" --gen-relay-list "${smbdir}/nxc_relay_hosts.txt" | tee "${smbdir}/nxc.out"

    if [ -f "${smbdir}/nxc_relay_hosts.txt" ]; then
        numRelay=$(wc -l < "${smbdir}/nxc_relay_hosts.txt")
        ok "SMB relay targets list generated. ${numRelay} hosts can be relayed to."
    else
        err "No targets can be relayed to, but still parsing NXC output."
    fi

    # strip ANSI colour codes before field extraction - positional cut breaks
    # as soon as hostname lengths change
    sed -r 's/\x1B\[[0-9;]*[mK]//g' "${smbdir}/nxc.out" > "${smbdir}/nxc_clean.out"
    grep -a "signing:False" "${smbdir}/nxc_clean.out" > "${smbdir}/no_signing.out"
    grep -a "SMBv1:True"    "${smbdir}/nxc_clean.out" > "${smbdir}/smbv1.out"
    awk '{print $2}' "${smbdir}/smbv1.out"      | sort -V -u > "${smbdir}/smbv1_hosts.txt"
    awk '{print $2}' "${smbdir}/no_signing.out" | sort -V -u > "${smbdir}/no_signing_hosts.txt"
    log "Netexec parsing complete."
else
    err "${nxctargets} does not exist or is empty. Skipping SMB enumeration."
fi

# ---- combined msfconsole run (RDP + IPMI) ------------------------------
# v1.1: one msfconsole invocation instead of two. 'spool' keeps per-module
# output in separate files. IPMI now sets THREADS, disables inline cracking
# and writes hashcat/john files for offline GPU cracking.

rdphosts="${varOutPath}rdp-hosts.txt"
ipmihosts="${varOutPath}ipmi_hosts.txt"
msfrc=""

if [ -s "$rdphosts" ] || [ -s "$ipmihosts" ]; then
    msfrc="$(mktemp)"
    CLEANUP_FILES+=("$msfrc")

    if [ -s "$rdphosts" ]; then
        log "Queueing MSF RDP check against $(wc -l < "$rdphosts") hosts..."
        cat >> "$msfrc" <<EOF
spool ${varWorkingDir}/${clientcode}/other/rdp_scan.out
use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS file:${varWorkingDir}/${varOutPath#./}rdp-hosts.txt
run
spool off
EOF
    else
        err "$rdphosts does not exist. Skipping RDP enumeration."
    fi

    if [ -s "$ipmihosts" ]; then
        ipmicount=$(wc -l < "$ipmihosts")
        # msf scanners cap at one thread per host - don't request more than we have
        if [ "$ipmicount" -lt "$IPMI_THREADS" ]; then
            ipmithreads="$ipmicount"
        else
            ipmithreads="$IPMI_THREADS"
        fi
        [ "$ipmithreads" -lt 1 ] && ipmithreads=1

        log "Queueing MSF IPMI scan against ${ipmicount} hosts using ${ipmithreads} threads..."
        cat >> "$msfrc" <<EOF
spool ${varWorkingDir}/${clientcode}/other/ipmi_scan.out
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS file:${varWorkingDir}/${varOutPath#./}ipmi_hosts.txt
set THREADS ${ipmithreads}
set CRACK_COMMON false
set OUTPUT_HASHCAT_FILE ${varWorkingDir}/${clientcode}/other/ipmi_hashcat.txt
set OUTPUT_JOHN_FILE ${varWorkingDir}/${clientcode}/other/ipmi_john.txt
set SESSION_MAX_ATTEMPTS ${IPMI_MAX_ATTEMPTS}
set SESSION_RETRY_DELAY ${IPMI_RETRY_DELAY}
run
spool off
EOF
    else
        err "$ipmihosts does not exist. Skipping IPMI scanning."
    fi

    echo "exit" >> "$msfrc"

    log "Running msfconsole..."
    msfconsole -q -r "$msfrc" | tee "${varWorkingDir}/${clientcode}/other/msf_combined.out"

    # RDP post-processing
    if [ -f "${varWorkingDir}/${clientcode}/other/rdp_scan.out" ]; then
        grep -a "NLA: No" "${varWorkingDir}/${clientcode}/other/rdp_scan.out" > "./${clientcode}/other/rdp_nla.out"
        awk '{print $2}' "./${clientcode}/other/rdp_nla.out" | cut -d ':' -f 1 | sort -V -u > "./${clientcode}/other/rdp_nla_hosts.txt"
    fi

    if [ -s "./${clientcode}/other/ipmi_hashcat.txt" ]; then
        ok "IPMI hashes captured. Crack with: hashcat -m 7300 ${clientcode}/other/ipmi_hashcat.txt <wordlist>"
    fi

    log "msfconsole modules completed. Check the 'other' directory for results."
else
    err "Neither RDP nor IPMI host lists exist. Skipping msfconsole run."
fi

# file check and snmp-check

log "Running SNMP checks on first ${SNMP_CHECK_COUNT} hosts..."
snmphosts="${varOutPath}snmp_hosts.txt"

if [ -s "$snmphosts" ]; then
    head -n "${SNMP_CHECK_COUNT}" "$snmphosts" | while IFS= read -r host; do
        if [ -n "$host" ]; then
            log "snmp-check against ${host}..."
            snmp-check "${host}" | tee -a "${varWorkingDir}/${clientcode}/other/snmp_check_${host}.out"
        fi
    done
    log "SNMP checks completed. Check other directory for results."
else
    err "${snmphosts} does not exist. Skipping SNMP checks."
fi

# file check and eyewitness

log "Running EyeWitness Scan..."
webhosts="${varOutPath}web-urls.txt"
if [ -s "$webhosts" ]; then
    runuser -l "$currentuser" -c "eyewitness -f ${varWorkingDir}/${varOutPath#./}web-urls.txt -d ${varWorkingDir}/${clientcode}/other/EyeWitness_output --no-prompt --threads ${EYEWITNESS_THREADS} --delay ${EYEWITNESS_DELAY}"
    log "EyeWitness scan completed. Check other directory for results."
else
    err "${webhosts} does not exist. Skipping web url scanning."
fi

# add any new tools/checks here or before

# final chown/chmod operation on all directories/files - post ops to allow the current user to move/modify any file/directory in the $clientcode directory structure
sudo chown -R "${currentuser}:${currentuser}" "${varWorkingDir}/${clientcode}"
sudo chmod -R u+rwX,go-rX "${varWorkingDir}/${clientcode}"

log "AutoSPEED run complete. Log: ${LOGFILE}"
