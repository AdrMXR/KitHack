#!/usr/bin
#Copyright 2020 KITHACK
#Written by: Adrian Guillermo
#Facebook: https://facebook.com/adrian.guillermo.22
#Github: https://github.com/AdrMXR

#Installer KitHack

path=$(pwd)

# Check root 
if [ "$(id -u)" != "0" ] > /dev/null 2>&1; then
echo ""
echo -e '\e[1;31m【x】Este script necesita permisos root.\e[0m' 1>&2
sleep 2
exit
fi

# Banner 
clear
sleep 2
echo -e "\e[0;33m ___                 __         .__  .__                              "
echo -e "\e[0;33m|   | ____   _______/  |______  |  | |  |   ___________               "    
echo -e "\e[0;33m|   |/    \ /  ___/\   __\__  \ |  | |  | _/ __ \_  __ \              "    
echo -e "\e[0;33m|   |   |  \___  \  |  |  / __ \|  |_|  |_\  ___/|  | \/              "    
echo -e "\e[0;33m|___|___|  /____  > |__| (____  /____/____/\___  >__|   /\  /\  /\    "
echo -e "\e[0;33m         \/     \/            \/               \/       \/  \/  \/    "
echo -e ""
echo -e "                        \e[38;5;166m Setup KitHack v1.2.0                     "
echo -e ""
echo -e "                            By:AdrMXR                                         "
 
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

# Check dependencies
echo -e "\e[0;33m"
echo -n [*] Checando dependencias...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done 
echo ""

# Check if xterm exists
which xterm > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo ""
echo -e "\033[92m[✔][Xterm]..........................[ OK ]"
sleep 1.5
else
echo ""
echo -e "\e[1;31m[!][Xterm].......................[ NOT FOUND ]"
sudo apt-get install -y xterm > /dev/null
fi

# Check if postgresql exists
which /etc/init.d/postgresql > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "\033[92m[✔][Postgresql].....................[ OK ]"
sleep 1.5
else
echo -e "\e[1;31m[!][Postgresql]..................[ NOT FOUND ]"
xterm -T "INSTALLER POSTGRESQL" -geometry 100x30 -e "sudo apt-get install -y postgresql"
fi 

# Check if metasploit framework exists 
which msfconsole > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "\033[92m[✔][Metasploit Framework]...........[ OK ]"
sleep 1.5
else
echo -e "\e[1;31m[!][Metasploit Framework]........[ NOT FOUND ]"
xterm -T "INSTALLER METASPLOIT FRAMEWORK" -geometry 100x30 -e "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall && sudo apt-get update && apt-get upgrade"
fi

# Check if apktool exists 
which apktool > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "\033[92m[✔][Apktool]........................[ OK ]"
sleep 1.5
else
echo -e "\e[1;31m[!][Apktool].....................[ NOT FOUND ]"
xterm -T "INSTALLER APKTOOL" -geometry 100x30 -e "echo -e "" && echo [*] Añadiendo Apktool... && sleep 2 && echo -e "" && cp apktoolv2.4.0/apktool /usr/local/bin/apktool && echo [✔]/usr/local/bin/apktool && sleep 2 && cp apktoolv2.4.0/apktool.jar /usr/local/bin/apktool.jar && echo [✔]/usr/local/bin/apktool.jar && echo "" && sleep 2 && echo Instalación completa. && sleep 1"
fi

# Check if aapt exists
which aapt > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "\033[92m[✔][Aapt]...........................[ OK ]"
sleep 1.5
else
echo -e "\e[1;31m[!][Aapt]........................[ NOT FOUND ]"
xterm -T "INSTALLER AAPT" -geometry 100x30 -e "sudo apt-get install -y aapt && sudo apt-get install -y android-framework-res"
fi

# Check if jarsigner exists
which jarsigner > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "\033[92m[✔][Jarsigner]......................[ OK ]"
sleep 1.5
else
echo -e "\e[1;31m[!][Jarsigner]...................[ NOT FOUND ]"
xterm -T "INSTALLER JARSIGNER" -geometry 100x30 -e "sudo apt-get install default-jdk"
fi

# Check if zipalign exists
which zipalign > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "\033[92m[✔][Zipalign].......................[ OK ]"
sleep 1.5
else
echo -e "\e[1;31m[!][Zipalign]...................[ NOT FOUND ]"
xterm -T "INSTALLER ZIPALIGN" -geometry 100x30 -e "sudo apt-get install -y zipalign"
fi

# Check if pip2 exists
which pip2 > /dev/null 2>&1
if [ "$?" -eq "0" ]; then
echo -e "\033[92m[✔][Pip2]...........................[ OK ]"
sleep 1.5
else
echo -e "\e[1;31m[!][Pip2].......................[ NOT FOUND ]"
xterm -T "INSTALLER PIP2" -geometry 100x30 -e "wget https://bootstrap.pypa.io/get-pip.py && sudo python2.7 get-pip.py"
rm get-pip.py
fi

## Configuring folders and icon
path=$(pwd)
echo -e "\e[0;33m"
echo -n [*] Configurando carpetas e icono...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done
mkdir output 
echo ""
echo -e "\033[92m"
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
sed -i "4i\Exec=sh -c 'cd $path && python KitHack.py'" icons/kithack.desktop
cp icons/kithack.desktop /usr/share/applications/kithack.desktop
cp icons/kithack.png /usr/share/icons/kithack.png
echo -e "/usr/share/applications/kithack.desktop"
sleep 0.2

# Installing requirements
echo -e "\e[0;33m"
echo -n [*] Instalando requerimientos de python...= ;
sleep 3 & while [ "$(ps a | awk '{print $1}' | grep $!)" ] ; do for X in '-' '\' '|' '/'; do echo -en "\b$X"; sleep 0.1; done; done
echo ""
echo -e "\033[92m"
pip2 install py-getch 
apt-get install python-tk
exit 0

