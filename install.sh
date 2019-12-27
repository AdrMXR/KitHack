#!/usr/bin
# Installer KitHack

# Check root 
if [ "$(id -u)" != "0" ] > /dev/null 2>&1; then
echo ""
echo -e '\e[0;31m【x】Este script necesita permisos root.\e[0m' 1>&2
sleep 2
exit
fi

# Banner 
clear
sleep 2
echo -e "\e[0;33m_________ .__                   __   .__                            "
echo -e "\e[0;33m\_   ___ \|  |__   ____   ____ |  | _|__| ____    ____              "
echo -e "\e[0;33m/    \  \/|  |  \_/ __ \_/ ___\|  |/ /  |/    \  / ___\             "
echo -e "\e[0;33m\     \___|   Y  \  ___/\  \___|    <|  |   |  \/ /_/  >            "
echo -e "\e[0;33m \______  /___|  /\___  >\___  >__|_ \__|___|  /\___  / /\  /\  /\  "
echo -e "\e[0;33m        \/     \/     \/     \/     \/       \//_____/  \/  \/  \/  "
echo -e ""
echo -e "                   \e[38;5;166m Installer for KitHack v1.0                  "
echo -e ""
echo "                            By:AdrMXR                                          "

echo -e "\e[0;33m"
echo -n [*] Checando dependencias...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done 
echo ""

# check if postgresql exists 
which /etc/init.d/postgresql > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo ""
echo -e "\e[0;34m[✔][Postgresql]:    OK"
sleep 1.5
else
echo -e "\e[0;34m[!][Postgresql]:   \e[0;31m NOT FOUND"
xterm -T "INSTALLER POSTGRESQL" -geometry 100x50 -e "sudo apt-get install -y postgresql"
fi 

# Check if msfvenom exists 
which msfvenom > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "\e[0;34m[✔][Msfvenom]:      OK"
sleep 1.5
else
echo -e "\e[0;34m[!][Msfvenom]:     \e[0;31m NOT FOUND"
xterm -T "INSTALLER METASPLOIT FRAMEWORK" -geometry 100x50 -e "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall && sudo apt-get update && apt-get upgrade"
fi

# Check if msfconsole exists 
which msfconsole > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "\e[0;34m[✔][Msfconsole]:    OK "
sleep 1.5
else
echo -e "\e[0;34m[!][Msfvenom]:     \e[0;31m NOT FOUND"
xterm -T "INSTALLER METASPLOIT FRAMEWORK" -geometry 100x50 -e "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall && sudo apt-get update && apt-get upgrade"
fi
echo ""

## Configuring folders
path=$(pwd)
echo -e "\e[0;33m"
echo -n [*] Configurando carpetas...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done
mkdir output 
echo ""
echo -e "\e[0;34m"
echo -e "$path/output"
sleep 0.2
mkdir -p tools/Android
echo -e "$path/tools/Android"
sleep 0.2
mkdir -p tools/Windows
echo -e "$path/tools/Windows"
sleep 0.2
mkdir -p tools/Phishing
echo -e "$path/tools/Phishing"
sleep 0.2
mkdir -p tools/Wifi
echo -e "$path/tools/Wifi"
sleep 0.2
mkdir -p tools/Passwords
echo -e "$path/tools/Passwords"
sleep 0.2
mkdir -p tools/Web
echo -e "$path/tools/Web"
sleep 0.2
mkdir -p tools/Spoofing
echo -e "$path/tools/Spoofing"
sleep 0.2
mkdir -p tools/InformationGathering
echo -e "$path/tools/InformationGathering"
sleep 0.2
mkdir -p tools/Others
echo -e "$path/tools/Others"
sleep 0.2
echo ""

# Installing requirements
echo -e "\e[0;33m"
echo -n [*] Instalando requerimientos de python...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done
echo ""
echo -e "\e[0;34m"
pip install py-getch 
apt-get install python-tk
