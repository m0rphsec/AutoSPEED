#Installing AutoSPEED dependencies if not already installed

echo -e "[${BLUE}+${RESET}] Checking for application dependencies."

if command -v nmap &> /dev/null
then
    echo -e "[${GREEN}+${RESET}] nmap is installed."
else
echo -e "[${RED}!${RESET}] Installing nmap."
apt update && apt install nmap -y
fi

if command -v crackmapexec &> /dev/null
then
    echo -e "[${GREEN}+${RESET}] Crackmapexec is installed."
else
echo -e "[${RED}!${RESET}] Installing crackmapexec."
apt update && apt install crackmapexec -y
fi

if command -v msfconsole &> /dev/null
then
    echo -e "[${GREEN}+${RESET}] Metasploit framework installed."
else
echo -e "[${RED}!${RESET}] Installing Metasploit framework."
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
fi

if command -v eyewitness &> /dev/null
then
    echo -e "[${GREEN}+${RESET}] EyeWitness is installed."
else
echo -e "[${RED}!${RESET}] Installing EyeWitness."
apt update && apt install eyewitness -y
fi

