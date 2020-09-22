#!/usr/bin
#Copyright 2020 KITHACK
#Written by: Adrian Guillermo
#Facebook: https://facebook.com/adrian.guillermo.22
#Github: https://github.com/AdrMXR

#Update KitHack

path=$(pwd)

# Check root 
if [ "$(id -u)" != "0" ] > /dev/null 2>&1; then
echo ""
echo -e '\e[1;31m[x] Este script necesita permisos root.\e[0m' 1>&2
sleep 2
exit
fi

# Banner
clear
sleep 2
echo -e "\e[0;33m ____ ___            .___                                 "
echo -e "\e[0;33m|    |   \______   __| _/____ _/  |_  ____                "
echo -e "\e[0;33m|    |   /\____ \ / __ |\__  \\   __\/ __ \               "
echo -e "\e[0;33m|    |  / |  |_> > /_/ | / __ \|  | \  ___/               "
echo -e "\e[0;33m|______/  |   __/\____ |(____  /__|  \___  > /\  /\  /\   "
echo -e "\e[0;33m          |__|        \/     \/          \/  \/  \/  \/   "
echo -e ""
echo -e "                \e[38;5;166m Update KitHack v1.3.0                "
echo -e ""
echo -e "                      By:AdrMXR                                   "

# Check if there is an internet connection
ping -c 1 google.com > /dev/null 2>&1
if [[ "$?" == 0 ]]; then
echo ""
echo -e "\033[92m[✔][Internet Connection]............[ OK ]"
sleep 1.5
else
echo ""
echo -e "\e[1;31m[!][Internet Connection].........[ NOT FOUND ]"
echo ""
exit
fi

# Check if git exists
echo -e "\e[0;33m"
echo -n [*] Checando git...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done 
echo ""
which git > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo ""
echo -e "\033[92m[✔][GIT]............................[ OK ]"
sleep 1.5
else
echo -e "\e[1;31m[!][GIT].........................[ NOT FOUND ]"
sleep 1.5
echo -e "\e[0;33m[!][Installing GIT...]"
xterm -T "INSTALLER GIT" -geometry 100x30 -e "apt-get install git -y"
fi 

# Checking python requirements
echo -e "\e[0;33m"
echo -n [*] Verificando requerimientos de python...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done
echo ""
echo -e "\033[92m"
pip3 install requests
pip3 install py-getch
apt-get install python3-tk
pip3 install pathlib
pip3 install zenipy
pip3 install pgrep
apt-get install libatk-adaptor libgail-common
sudo apt-get purge fcitx-module-dbus

# Creating temporary directory...
echo -e "\e[0;33m"
echo -n [*] Creando directorio temporal...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done 
echo ""
temp="$HOME/hacktemp"
mkdir "$temp"
mv "$path/output" "$temp/output" 
mv "$path/tools" "$temp/tools"
echo ""
echo -e "\033[92m[✔] Done."
sleep 1.5

# Updating KitHack...
echo -e "\e[0;33m"
echo -n [*] Actualizando repositorio KitHack desde Github...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done 
echo -e "\033[92m"
echo ""
git reset HEAD --hard
git pull
echo ""
sleep 1.5

# Moving the files in the temporary directory again
echo -e "\e[0;33m"
echo -n [*] Moviendo de nuevo los archivos del directorio temporal...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done 
echo ""
mv "$temp/output" "$path/output"
mv "$temp/tools" "$path/tools"
rm -rf "$temp"
echo ""
echo -e "\033[92m[✔] Done. Update complete."
sleep 1.5
exit 0
