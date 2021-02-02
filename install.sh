#!/usr/bin
#Copyright 2021 KITHACK
#Written by: Adrian Guillermo
#Facebook: https://facebook.com/adrian.guillermo.22
#Github: https://github.com/AdrMXR

# Installer KitHack

# Colors
red='\e[1;31m'
default='\e[0m'
yellow='\e[0;33m'
orange='\e[38;5;166m'
green='\033[92m'

# Location
path=$(pwd)

# Check root 
if [ "$(id -u)" != "0" ] > /dev/null 2>&1; then
echo -e '\n$red[x] Este script necesita permisos root.' 1>&2
exit
fi

# Banner 
clear
sleep 2
echo -e "$yellow  ___                 __         .__  .__                            "
echo -e "$yellow |   | ____   _______/  |______  |  | |  |   ___________             "    
echo -e "$yellow |   |/    \ /  ___/\   __\__  \ |  | |  | _/ __ \_  __ \            "    
echo -e "$yellow |   |   |  \___  \  |  |  / __ \|  |_|  |_\  ___/|  | \/            "    
echo -e "$yellow |___|___|  /____  > |__| (____  /____/____/\___  >__|   /\  /\  /\  "
echo -e "$yellow          \/     \/            \/               \/       \/  \/  \/  "
echo -e "                                                                            "
echo -e "$orange                        Setup KitHack v1.3.2                         "
echo -e "                                                                            "
echo -e "$orange                             By:AdrMXR                               "
 
# Check if there is an internet connection
ping -c 1 google.com > /dev/null 2>&1
if [[ "$?" == 0 ]]; then
echo ""
echo -e "$green[✔][Internet Connection]............[ OK ]"
sleep 1.5
else
echo ""
echo -e "$red[!][Internet Connection].........[ NOT FOUND ]"
echo ""
exit
fi

# Check dependencies
echo -e $yellow
echo -n [*] Checando dependencias...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done 
echo ""

# Check if xterm exists
which xterm > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo ""
echo -e "$green[✔][Xterm]..........................[ OK ]"
sleep 1.5
else
echo ""
echo -e "$red[x][Xterm].......................[ NOT FOUND ]"
sleep 1.5
echo -e "$yellow[!][Installing Xterm...]"
sudo apt-get install -y xterm > /dev/null
fi

# Check if postgresql exists
which /etc/init.d/postgresql > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "$green[✔][Postgresql].....................[ OK ]"
sleep 1.5
else
echo -e "$red[x][Postgresql]..................[ NOT FOUND ]"
sleep 1.5
echo -e "$yellow[!][Installing Postgresql...]"
xterm -T "INSTALLER POSTGRESQL" -geometry 100x30 -e "sudo apt-get install -y postgresql"
fi 

# Check if metasploit framework exists 
which msfconsole > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "$green[✔][Metasploit Framework]...........[ OK ]"
sleep 1.5
else
echo -e "$red[x][Metasploit Framework]........[ NOT FOUND ]"
sleep 1.5
echo -e "$yellow[!][Installing Metasploit-Framework...]"
xterm -T "INSTALLER METASPLOIT FRAMEWORK" -geometry 100x30 -e "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall && sudo apt-get update && apt-get upgrade"
fi

# Check if apktool exists 
which apktool > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "$green[✔][Apktool]........................[ OK ]"
sleep 1.5
else
echo -e "$red[x][Apktool].....................[ NOT FOUND ]"
sleep 1.5
echo -e "$yellow[!][Installing Apktool...]"
xterm -T "INSTALLER APKTOOL" -geometry 100x30 -e "wget -O apktool.jar https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.4.0.jar && wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool && mv apktool* /usr/local/bin && chmod +x /usr/local/bin/apktool*"
fi

# Check if aapt exists
which aapt > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "$green[✔][Aapt]...........................[ OK ]"
sleep 1.5
else
echo -e "$red[x][Aapt]........................[ NOT FOUND ]"
sleep 1.5
echo -e "$yellow[!][Installing Aapt...]"
xterm -T "INSTALLER AAPT" -geometry 100x30 -e "sudo apt-get install -y aapt && sudo apt-get install -y android-framework-res"
fi

# Check if jarsigner exists
which jarsigner > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "$green[✔][Jarsigner]......................[ OK ]"
sleep 1.5
else
echo -e "$red[x][Jarsigner]...................[ NOT FOUND ]"
sleep 1.5
echo -e "$yellow[!][Installing Jarsigner...]"
xterm -T "INSTALLER JARSIGNER" -geometry 100x30 -e "sudo apt-get install default-jdk"
fi

# Check if zipalign exists
which zipalign > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "$green[✔][Zipalign].......................[ OK ]"
sleep 1.5
else
echo -e "$red[x][Zipalign]....................[ NOT FOUND ]"
sleep 1.5
echo -e "$yellow[!][Installing Zipalign...]"
xterm -T "INSTALLER ZIPALIGN" -geometry 100x30 -e "sudo apt-get install -y zipalign"
fi

# Check if pwgen exists
which pwgen > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "$green[✔][Pwgen]..........................[ OK ]"
sleep 1.5
else
echo -e "$red[x][Pwgen].......................[ NOT FOUND ]"
sleep 1.5
echo -e "$yellow[!][Installing Pwgen...]"
xterm -T "INSTALLER PWGEN" -geometry 100x30 -e "sudo apt-get install pwgen"
fi

# Check if ngrok exists
arch=`arch`
if [ -f "ngrok" ]; then
echo -e "$green[✔][Ngrok]..........................[ OK ]"
sleep 1.5
else
echo -e "$red[x][Ngrok]........................[ NOT FOUND ]"
sleep 1.5
echo -e "$yellow[!][Downloading ngrok...]"
if [ "$arch" ==  "x86_64" ]; then
xterm -T "DOWNLOAD NGROK" -geometry 100x30 -e "wget https://bin.equinox.io/a/kpRGfBMYeTx/ngrok-2.2.8-linux-amd64.zip && unzip ngrok-2.2.8-linux-amd64.zip"
rm ngrok-2.2.8-linux-amd64.zip
else
xterm -T "DOWNLOAD NGROK" -geometry 100x30 -e "wget https://bin.equinox.io/a/4hREUYJSmzd/ngrok-2.2.8-linux-386.zip && unzip ngrok-2.2.8-linux-386.zip"
rm ngrok-2.2.8-linux-386.zip
fi
fi

# Configuring folders
echo -e $yellow
echo -n [*] Configurando carpetas...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done
echo ""
echo -e $green

if [ -d output ]; then
echo -e "[✔]Ya existe $path/output"
sleep 0.2
else
mkdir output
echo -e "[✔]$path/output"
sleep 0.2
fi

if [ -d tools/Android ]; then
echo -e "[✔]Ya existe $path/tools/Android"
sleep 0.2
else
mkdir -p tools/Android
echo -e "[✔]$path/tools/Android"
sleep 0.2
fi

if [ -d tools/Windows ]; then
echo -e "[✔]Ya existe $path/tools/Windows"
sleep 0.2
else
mkdir -p tools/Windows
echo -e "[✔]$path/tools/Windows"
sleep 0.2
fi

if [ -d tools/Phishing ]; then
echo -e "[✔]Ya existe $path/tools/Phishing"
sleep 0.2
else
mkdir -p tools/Phishing
echo -e "[✔]$path/tools/Phishing"
sleep 0.2
fi

if [ -d tools/Wifi ]; then
echo -e "[✔]Ya existe $path/tools/Wifi"
sleep 0.2
else
mkdir -p tools/Wifi
echo -e "[✔]$path/tools/Wifi"
sleep 0.2
fi

if [ -d tools/Passwords ]; then
echo -e "[✔]Ya existe $path/tools/Passwords"
sleep 0.2
else
mkdir -p tools/Passwords
echo -e "[✔]$path/tools/Passwords"
sleep 0.2
fi

if [ -d tools/Web ]; then
echo -e "[✔]Ya existe $path/tools/Web"
sleep 0.2
else
mkdir -p tools/Web
echo -e "[✔]$path/tools/Web"
sleep 0.2
fi

if [ -d tools/Spoofing ]; then
echo -e "[✔]Ya existe $path/tools/Spoofing"
sleep 0.2
else
mkdir -p tools/Spoofing
echo -e "[✔]$path/tools/Spoofing"
sleep 0.2
fi

if [ -d tools/InformationGathering ]; then
echo -e "[✔]Ya existe $path/tools/InformationGathering"
sleep 0.2
else
mkdir -p tools/InformationGathering
echo -e "[✔]$path/tools/InformationGathering"
sleep 0.2
fi

if [ -d tools/Others ]; then
echo -e "[✔]Ya existe $path/tools/Others"
sleep 0.2
else
mkdir -p tools/Others
echo -e "[✔]$path/tools/Others"
sleep 0.2
fi

if [ -d .config ]; then
echo -e "[✔]Ya existe $path/.config"
sleep 0.2
else
mkdir -p .config
echo -e "[✔]$path/.config"
sleep 0.2
fi

# Installing requirements
echo -e $yellow
echo -n [*] Instalando requerimientos de python...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done
echo ""
echo -e $green
pip3 install requests
pip3 install py-getch
apt-get install python3-tk
pip3 install pathlib
pip3 install zenipy
pip3 install pgrep
apt-get install libatk-adaptor libgail-common
sudo apt-get purge fcitx-module-dbus

# Shortcut for kithack
echo -e $yellow
echo -n [*] Configuración de acceso directo...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done
echo ""
echo ""
echo -e "$green[!] ¿Desea poder ejecutar kithack desde cualquier lugar de su terminal? (y/n)"
echo -e "$red"
echo -ne "KitHack >> $default"
read -r option
case "$option" in

y|Y)
lnk=$?
if [ "$lnk" ==  "0" ];then
run="cd $path && sudo python3 KitHack.py"
touch /usr/local/bin/kithack
echo "#!/bin/bash" > /usr/local/bin/kithack
echo "$run" >> /usr/local/bin/kithack
chmod +x /usr/local/bin/kithack
cp images/kithack.desktop /usr/share/applications/kithack.desktop
cp images/kithack.png /usr/share/icons/kithack.png
sleep 2
echo -e $green
echo -e "╔──────────────────────────────────────────────────────────╗"
echo -e "|[✔] Installation complete. Type 'kithack' to run the tool.|"
echo -e "┖──────────────────────────────────────────────────────────┙"
fi
;;

n|N)
sleep 2
echo -e $green
echo -e "╔──────────────────────────╗"
echo -e "|[✔] Installation complete.|"
echo -e "┖──────────────────────────┙"
;;
esac
exit
