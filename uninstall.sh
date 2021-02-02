#!/usr/bin
#Copyright 2021 KITHACK
#Written by: Adrian Guillermo
#Facebook: https://facebook.com/adrian.guillermo.22
#Github: https://github.com/AdrMXR

#Uninstaller KitHack 

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
echo -e "$yellow  ____ ___      .__                 __         .__  .__     "
echo -e "$yellow |    |   \____ |__| ____   _______/  |______  |  | |  |    "
echo -e "$yellow |    |   /    \|  |/    \ /  ___/\   __\__  \ |  | |  |    "
echo -e "$yellow |    |  /   |  \  |   |  \\___ \   |  |  / __ \|  |_|  |__ "
echo -e "$yellow |______/|___|  /__|___|  /____  > |__| (____  /____/____/  "
echo -e "$yellow              \/        \/     \/            \/             "
echo -e "$yellow                                                            "
echo -e "$orange                     Setup KitHack v1.3.2                   "
echo -e "                                                                   "
echo -e "$orange                           By:AdrMXR                        "

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

# Uninstalling kithack
echo -e $yellow
echo -n [*] Desinstalando KitHack...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done 
echo ""
echo -e "$green"

if [ -f "/usr/local/bin/kithack" ]; then
rm /usr/local/bin/kithack
echo -e "[✔]/usr/local/bin/kithack"
sleep 0.2
fi

if [ -f "/usr/share/applications/kithack.desktop" ]; then
rm /usr/share/applications/kithack.desktop
echo -e "[✔]/usr/share/applications/kithack.desktop"
sleep 0.2
fi

if [ -f "/usr/share/icons/kithack.png" ]; then
rm /usr/share/icons/kithack.png
echo -e "[✔]/usr/share/icons/kithack.png"
sleep 0.2
fi

if [ -f "/tmp/data.txt" ]; then
rm /tmp/data.txt
echo -e "[✔]/tmp/data.txt"
sleep 0.2
fi

rm -rf $path
echo -e "[✔]$path"
sleep 0.2

echo -e "╔───────────────────────╗"
echo -e "|[✔] Uninstall complete.|"
echo -e "┖───────────────────────┙"
exit 
