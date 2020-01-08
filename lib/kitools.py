#!/usr/bin/env python 
# -*- coding: utf-8 -*-
#Copyright 2019 KITHACK
#Written by: Adrian Guillermo
#Facebook: https://facebook.com/adrian.guillermo.22
#Github: https://github.com/AdrMXR

BLUE, RED, WHITE, CYAN, DEFAULT, YELLOW, MAGENTA, GREEN, END, BOLD = '\33[94m', '\033[91m', '\33[97m', '\033[36m', '\033[0m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m', '\033[1m'

import os
import time
import sys
from sys import exit
from getch import pause 
sys.path.insert(0,"..")
import KitHack
sys.dont_write_bytecode = True

#Tools Android 
def BackdoorApk():
	location = os.getcwd()
	os.system('cd tools && cd Android && git clone https://github.com/dana-at-cp/backdoor-apk.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Android/backdoor-apk".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >>{1} ".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Android && cd backdoor-apk && cd backdoor-apk && ./backdoor-apk.sh')

def EvilDroid():
	location = os.getcwd()
	os.system('cd tools && cd Android && git clone https://github.com/M4sc3r4n0/Evil-Droid.git && cd Evil-Droid && chmod +x evil-droid')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Android/Evil-Droid".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >>{1} ".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Android && cd Evil-Droid && ./evil-droid')

def ApkTool():
	os.system('cd tools && cd Android && mkdir ApkTool && cd ApkTool && wget http://download1491.mediafire.com/7ga50yx9roqg/he4vdj2wea7abbv/apktool.zip && unzip apktool.zip && chmod +x * && cp apktool /usr/local/bin/apktool && cp apktool.jar /usr/local/bin/apktool.jar')
	time.sleep(2)
	print("\n{}Herramienta guardada en /usr/local/bin/apktool".format(GREEN))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >>{1} ".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()		
	else:
		os.system('apktool')	

def AhMyth():
	os.system('cd tools && cd Android && mkdir AhMyth && cd AhMyth && wget http://download1581.mediafire.com/yda7cvfrnesg/ifxzqonwvff2wir/AhMyth_linux64.deb && dpkg -i AhMyth_linux64.deb && apt --fix-broken install')
	time.sleep(2)
	print("\n{}Herramienta guardada en /usr/local/bin/ahmyth".format(GREEN))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >>{1} ".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('ahmyth')

def Andspoilt():
	location = os.getcwd()
	os.system('cd tools && cd Android && git clone https://github.com/sundaysec/Andspoilt.git && cd Andspoilt && python ./setup.py install')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Android/Andspoilt".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >>{1} ".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()			
	else:
		os.system('andspoilt')

def Kwetza():
	location = os.getcwd()
	os.system('cd tools && cd Android && git clone https://github.com/sensepost/kwetza.git && cd kwetza && pip install beautifulsoup4')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Android/kwetza".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >>{1} ".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()			
	else:
		os.system('cd tools && cd Android && cd kwetza && python kwetza.py')

def Termux():
	location = os.getcwd()
	os.system('cd tools && cd Android && mkdir Termux && cd Termux && wget http://download2224.mediafire.com/s9uwtov68psg/nfgoac46i4xvre0/Termux_v0.73.apk')
	print("\n{0}Aplicacion guardada en {1}/tools/Android/Termux".format(GREEN, location))
	time.sleep(2)
	pause("\n{}Presione una tecla para continuar...".format(GREEN))
	os.system('clear')
	KitHack.banner(), KitHack.menu(), KitHack.options()

def DroidTracker():
	location = os.getcwd()
	os.system('cd tools && cd Android && git clone https://github.com/thelinuxchoice/DroidTracker.git && cd DroidTracker && bash install.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Android/DroidTracker".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >>{1} ".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Android && cd DroidTracker && bash droidtracker.sh')

def Droidcam():
	location = os.getcwd()
	os.system('cd tools && cd Android && git clone https://github.com/thelinuxchoice/droidcam.git && cd droidcam && bash install.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Android/droidcam".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >>{1} ".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('tools && cd Android && cd droidcam && bash droidcam.sh')

def Crydroid():
	location = os.getcwd()
	os.system('cd tools && cd Android && git clone https://github.com/thelinuxchoice/crydroid.git && cd crydroid && bash install.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Android/crydroid".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >>{1} ".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()			
	else:
		os.system('cd tools && cd Android && cd crydroid && bash crydroid.sh')

def KeyDroid():
	location = os.getcwd()
	os.system('cd {} && cd tools && cd Android && git clone https://github.com/thelinuxchoice/keydroid.git && cd keydroid && bash install.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Android/keydroid".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >>{1} ".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()			
	else:
		os.system('cd tools && cd Android && cd keydroid && bash keydroid.sh')	

def AndroidExploits():
	location = os.getcwd()
	os.system('cd tools && cd Android && git clone https://github.com/sundaysec/Android-Exploits.git')
	print("\n{0}Exploits guardados en {1}/tools/Android/Android-Exploits".format(GREEN, location))
	time.sleep(2)
	pause("\n{}Presione una tecla para continuar...".format(GREEN))
	os.system('clear')
	KitHack.banner(), KitHack.menu(), KitHack.options()	

#Tools Windows 
def Winpayloads():
	location = os.getcwd()
	os.system('cd tools && cd Windows && git clone https://github.com/nccgroup/Winpayloads.git && cd Winpayloads && chmod +x setup.sh && ./setup.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Windows/Winpayloads".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Windows && cd Winpayloads && python WinPayloads.py')	

def sAINT():
	location = os.getcwd()
	os.system('apt install maven default-jdk default-jre openjdk-8-jdk openjdk-8-jre -y && apt install maven default-jdk default-jre openjdk-8-jdk openjdk-8-jre -y && cd tools && cd Windows && git clone https://github.com/tiagorlampert/sAINT.git && cd sAINT && chmod +x configure.sh && ./configure.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Windows/sAINT".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Windows && cd sAINT && java -jar sAINT.jar')

def BeeLogger():
	location = os.getcwd()
	os.system('cd tools && cd Windows && git clone https://github.com/4w4k3/BeeLogger.git && cd BeeLogger && sudo su && chmod +x install.sh && ./install.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Windows/BeeLogger".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Windows && cd BeeLogger && python bee.py')

def FakeImageExploiter():
	location = os.getcwd()
	os.system('cd tools && cd Windows && git clone https://github.com/r00t-3xp10it/FakeImageExploiter.git && cd FakeImageExploiter && chmod +x *.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Windows/FakeImageExploiter".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Windows && cd FakeImageExploiter && sudo ./FakeImageExploiter.sh')	

def Koadic():
	location = os.getcwd()
	os.system('cd tools && cd Windows && git clone https://github.com/zerosum0x0/koadic.git && cd koadic && pip install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Windows/koadic".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Windows && cd koadic && ./koadic.py')	

def PhantomEvasion():
	location = os.getcwd()
	os.system('cd tools && cd Windows && git clone https://github.com/oddcod3/Phantom-Evasion.git && cd Phantom-Evasion && sudo chmod +x phantom-evasion.py')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Windows/Phantom-Evasion".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Windows && cd Phantom-Evasion && sudo ./phantom-evasion.py')

def Ps1encode():
	location = os.getcwd()
	os.system('cd tools && cd Windows && git clone https://github.com/CroweCybersecurity/ps1encode.git')
	time.sleep(2)	
	print("\n{0}Herramienta guardada en {1}/tools/Windows/ps1encode".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Windows && cd ps1encode && ./ps1encode.rb')

def DKMC():
	location = os.getcwd()
	os.system('cd tools && cd Windows && git clone https://github.com/Mr-Un1k0d3r/DKMC.git && cd DKMC && mkdir output')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Windows/DKMC".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Windows && cd DKMC && python dkmc.py')

def Cromos():
	location = os.getcwd()
	os.system('cd tools && cd Windows && git clone https://github.com/6IX7ine/cromos.git && sudo chmod -R 777 cromos/ && cd cromos && python setup.py')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Windows/cromos".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Windows && cd cromos && python cromos.py')		

def EternalScanner():
	location = os.getcwd()
	os.system('cd tools && cd Windows && git clone https://github.com/peterpt/eternal_scanner.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Windows/EternalScanner".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Windows && cd eternal_scanner && ./escan')	

def EternalblueDoublepulsarMetasploit():
	location = os.getcwd()
	os.system('cd tools && cd Windows && git clone https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit.git && cd Eternalblue-Doublepulsar-Metasploit && cp eternalblue_doublepulsar.rb /usr/share/metasploit-framework/modules/exploits/windows/smb/')
	print("\n{0}Modulo guardado en /usr/share/metasploit-framework/modules/exploits/windows/smb/".format(GREEN))
	time.sleep(2)
	pause("\n{}Presione una tecla para continuar...".format(GREEN))
	os.system('clear')
	KitHack.banner(), KitHack.menu(), KitHack.options()	
	
def MS17010EternalBlueWinXPWin10():
	location = os.getcwd()
	os.system('cd tools && cd Windows && git clone https://github.com/hanshaze/MS17-010-EternalBlue-WinXP-Win10.git && cd MS17-010-EternalBlue-WinXP-Win10 && cp ms17_010_eternalblue_winXP-win10.rb /usr/share/metasploit-framework/modules/exploits/windows/smb/')
	print("\n{0}Modulo guardado en /usr/share/metasploit-framework/modules/exploits/windows/smb/".format(GREEN))
	time.sleep(2)
	pause("\n{}Presione una tecla para continuar...".format(GREEN))
	os.system('clear')
	KitHack.banner(), KitHack.menu(), KitHack.options()		

def Spykey():
	location = os.getcwd()
	os.system('cd tools && cd Windows && git clone https://github.com/thelinuxchoice/spykey.git')	
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Windows/spykey".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()		
	else:
		os.system('cd tools && cd Windows && cd spykey && bash spykey.sh')

def WindowsExploits():
	location = os.getcwd()
	os.system('cd tools && cd Windows && git clone https://github.com/WindowsExploits/Exploits.git')
	print("\n{0}Exploits guardados en {1}/tools/Windows/Exploits".format(GREEN, location))
	time.sleep(2)
	pause("\n{}Presione una tecla para continuar...".format(GREEN))
	os.system('clear')
	KitHack.banner(), KitHack.menu(), KitHack.options()		

#Tools Phishing
def HiddenEye():
	location = os.getcwd()
	os.system('cd tools && cd Phishing && git clone https://github.com/DarkSecDevelopers/HiddenEye.git && sudo apt install python3-pip && cd HiddenEye && sudo pip3 install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Phishing/HiddenEye".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()		
	else:
		os.system('cd {} && cd tools && cd Phishing && cd HiddenEye && python3 HiddenEye.py')
		os.system('cd {} && cd tools && cd Phishing && cd HiddenEye && python3 HiddenEye.py') #Segunda Ejecucion de HiddenEye para evitar el problema de conexiòn de internet.

def PhishX():
	location = os.getcwd()
	os.system('cd tools && cd Phishing && git clone https://github.com/Userphish/PhishX.git && cd PhishX && chmod +x installer.sh && bash ./installer.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Phishing/PhishX".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Phishing && cd PhishX && python3 PhishX.py')		

def SocialPhish():
	location = os.getcwd()
	os.system('cd tools && cd Phishing && git clone https://github.com/xHak9x/SocialPhish.git && cd SocialPhish && chmod +x socialphish.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Phishing/SocialPhish".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()			
	else:
		os.system('clear && cd tools && cd Phishing && cd SocialPhish && ./socialphish.sh')	

def SocialFish():
	location = os.getcwd()
	os.system('cd tools && cd Phishing && git clone https://github.com/UndeadSec/SocialFish.git && sudo apt-get install python3 python3-pip python3-dev -y && cd SocialFish && python3 -m pip install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Phishing/SocialFish".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()			
	else:
		os.system('cd tools && cd Phishing && cd SocialFish && python3 SocialFish.py')

def PhisherMan():
	location = os.getcwd()
	os.system('cd tools && cd Phishing && git clone https://github.com/FDX100/Phisher-man.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Phishing/Phisher-man".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Phishing && cd Phisher-man && python phisherman.py')

def Shellphish():
	location = os.getcwd()
	os.system('cd tools && cd Phishing && git clone https://github.com/thelinuxchoice/shellphish.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Phishing/shellphish".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('clear && cd tools && cd Phishing && cd shellphish && bash shellphish.sh')	

def Spectre():
	location = os.getcwd()
	os.system('cd tools && cd Phishing && git clone https://github.com/Pure-L0G1C/Spectre.git && cd Spectre && chmod +x install.sh && ./install.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Phishing/Spectre".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Phishing && cd Spectre && python spectre.py --help')	

def Blackeye():
	location = os.getcwd()
	os.system('cd tools && cd Phishing && git clone https://github.com/An0nUD4Y/blackeye.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Phishing/blackeye".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('clear && cd tools && cd Phishing && cd blackeye && bash blackeye.sh')	

def PhEmail():
	location = os.getcwd()
	os.system('cd tools && cd Phishing && git clone https://github.com/Dionach/PhEmail.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Phishing/PhEmail".format(GREEN, location))
	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Phishing && cd PhEmail && python phemail.py')	

def Weeman():
	location = os.getcwd()
	os.system('cd tools && cd Phishing && git clone https://github.com/evait-security/weeman.git')
	time.sleep(2)	
  	print("\n{0}Herramienta guardada en {1}/tools/Phishing/weeman".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Phishing && cd weeman && python weeman.py')	 	

#Tools Wifi 
def Fluxion():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/FluxionNetwork/fluxion.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/fluxion".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Wifi && cd fluxion && ./fluxion.sh -i')	

def Wifiphisher():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/wifiphisher/wifiphisher.git && cd wifiphisher && sudo python setup.py install')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/wifiphisher".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('wifiphisher')

def Wifibroot():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/hash3liZer/WiFiBroot.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/WiFiBroot".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Wifi && cd WiFiBroot && python wifibroot.py -h')

def Wifite():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/derv82/wifite.git && cd wifite && chmod +x wifite.py')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/wifite".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Wifi && cd wifite && ./wifite.py')

def Ettercap():
	os.system('sudo apt-get install zlib1g zlib1g-dev && sudo apt-get install build-essential && sudo apt-get install ettercap && sudo apt-get install ettercap-graphical')
	time.sleep(2)
	print("\n{}Herramienta guardada en /usr/bin/ettercap".format(GREEN))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()		
	else:
		os.system('sudo ettercap -G')

def Linset():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/chunkingz/linsetmv1-2.git && cd linsetmv1-2 && chmod a+x linsetmv1-2 && mv linset /')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/linsetmv1-2".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Wifi && cd linsetmv1-2 && ./linsetmv1-2.sh')

def WiFiPumpkin():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/P0cL4bs/WiFi-Pumpkin.git && cd WiFi-Pumpkin && ./installer.sh --install')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/WiFi-Pumpkin".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Wifi && cd WiFi-Pumpkin && python wifi-pumpkin.py')

def Wifresti():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/LionSec/wifresti.git && cd wifresti && cp wifresti.py /usr/bin/wifresti && chmod +x /usr/bin/wifresti')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/wifresti".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('sudo wifresti')

def EvilLimiter():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/bitbrute/evillimiter.git && cd evillimiter && sudo python3 setup.py install')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/evillimiter".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('evillimiter')

def NetoolToolkit():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/r00t-3xp10it/netool-toolkit.git && cd netool-toolkit && sudo chmod +x INSTALL.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/netool-toolkit".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Wifi && cd netool-toolkit && sudo ./netool.sh')	

def Dracnmap():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/Screetsec/Dracnmap.git && cd Dracnmap && chmod +x Dracnmap.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/Dracnmap".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Wifi && cd Dracnmap && sudo ./Dracnmap.sh')					

def Airgeddon():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git && cd airgeddon && chmod +x airgeddon.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/airgeddon".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Wifi && cd airgeddon && ./airgeddon.sh')	

def Routersploit():
	location = os.getcwd()
	os.system('apt-get install python3-pip && cd tools && cd Wifi && git clone https://www.github.com/threat9/routersploit.git && cd routersploit && python3 -m pip install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/routersploit".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Wifi && cd routersploit && python3 rsf.py')		

def Eaphammer():
	location = os.getcwd()
	os.system('apt-get install python3-pip && cd tools && cd Wifi && git clone https://github.com/s0lst1c3/eaphammer.git && cd eaphammer && ./kali-setup')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/eaphammer".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		os.system('cd tools && cd Wifi && cd eaphammer && ./eaphammer')	

def VMRMDK():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/chunkingz/VMR-MDK-K2-2017R-012x4.git && cd VMR-MDK-K2-2017R-012x4 && chmod +x VMR-MDK-K2-2017R-012x4.sh && mkdir VARMAC_CONFIG /root/ && mkdir VARMAC_LOGS /root/ && mkdir VARMAC_WASH /root/')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/VMR-MDK-K2-2017R-012x4".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Wifi && cd VMR-MDK-K2-2017R-012x4 && ./VMR-MDK-K2-2017R-012x4.sh')	

def FakeAP():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/thelinuxchoice/fakeap.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/fakeap".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Wifi && cd fakeap && bash fakeap.sh')		

def Wirespy():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/aress31/wirespy.git && cd wirespy && chmod +x wirespy.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/wirespy".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Wifi && cd wirespy && sudo ./wirespy.sh')	

def Wireshark():
	os.system('sudo apt-get install wireshark && sudo setcap CAP_NET_RAW+eip CAP_NET_ADMIN+eip /usr/bin/dumpcap')	
	time.sleep(2)
	print("\n{0}Herramienta guardada en /usr/bin/wireshark".format(GREEN))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('wireshark')

def SniffAir():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/Tylous/SniffAir.git && cd SniffAir && sudo ./setup.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/SniffAir".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Wifi && cd SniffAir && python SniffAir.py')			

def WifiJammer():
	location = os.getcwd()
	os.system('cd tools && cd Wifi && git clone https://github.com/DanMcInerney/wifijammer.git && cd wifijammer && python ./setup.py install')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Wifi/wifijammer".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('sudo wifijammer')		

#Tools passwords 
def Cupp():
	location = os.getcwd()
	os.system('cd tools && cd Passwords && git clone https://github.com/Mebus/cupp.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Passwords/cupp".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Passwords && cd cupp && ./cupp.py')

def Facebooker():
	location = os.getcwd()
	os.system('cd tools && cd Passwords && git clone https://github.com/FakeFBI/Facebooker.git')
	time.sleep(2)
 	print("\n{0}Herramienta guardada en {1}/tools/Passwords/Facebooker".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Passwords && cd Facebooker && perl Facebooker.pl')		

def InstaInsane():
	location = os.getcwd()
	os.system('cd tools && cd Passwords && git clone https://github.com/thelinuxchoice/instainsane.git && cd instainsane && chmod +x instainsane.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Passwords/instainsane".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Passwords && cd instainsane && sudo ./instainsane.sh')		

def BluForceFB():
	location = os.getcwd()
	os.system('cd tools && cd Passwords && git clone https://github.com/AngelSecurityTeam/BluForce-FB.git && cd BluForce-FB && pip2 install mechanize')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Passwords/BluForce-FB".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Passwords && cd BluForce-FB && python2 bluforcefb.py')	

def Brut3k1t():
	location = os.getcwd()
	os.system('cd tools && cd Passwords && git clone https://github.com/ex0dus-0x/brut3k1t.git && cd brut3k1t && python setup.py install')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Passwords/brut3k1t".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('brut3k1t -h')

def SocialBox():
	location = os.getcwd()
	os.system('cd tools && cd Passwords && git clone https://github.com/TunisianEagles/SocialBox.git && cd SocialBox && chmod +x SocialBox.sh && chmod +x install-sb.sh && ./install-sb.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Passwords/SocialBox".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Passwords && cd SocialBox && ./SocialBox.sh')		

def Crunch():
	location = os.getcwd()
	os.system('cd tools && cd Passwords && git clone http://git.code.sf.net/p/crunch-wordlist/code crunch-wordlist-code && cd crunch-wordlist-code && sudo make && sudo make install')
	time.sleep(2)					
	print("\n{0}Herramienta guardada en {1}/tools/Passwords/crunch-wordlist-code".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('crunch')

def JohnTheRipper():
	location = os.getcwd()
	os.system('cd tools && cd Passwords && mkdir JohnTheRipper && cd JohnTheRipper && wget http://www.openwall.com/john/j/john-1.8.0.tar.gz && tar -xzvf john-1.8.0.tar.gz && cd john-1.8.0/src/ && make clean generic')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Passwords/JohnTheRipper".format(GREEN, location))
 	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('john')

def Hashcat():
	location = os.getcwd()
	os.system('cd tools && cd Passwords && git clone https://github.com/hashcat/hashcat.git && cd hashcat && make && sudo make install')
 	time.sleep(2)
 	print("\n{0}Herramienta guardada en {1}/tools/passwords/hashcat".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('hashcat -h')	

def Brutedum():
	location = os.getcwd()
	os.system('sudo apt install python3 && cd tools && cd Passwords && git clone https://github.com/GitHackTools/BruteDum.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/passwords/Brutedum".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Passwords && cd Brutedum && python3 brutedum.py')		

#Tools Web
def SQLmap():
	location = os.getcwd()
	os.system('cd tools && cd Web && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Web/sqlmap".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Web && cd sqlmap && python sqlmap.py -h')

def XAttacker():
	location = os.getcwd()
	os.system('cd tools && cd Web && git clone https://github.com/Moham3dRiahi/XAttacker.git')
	time.sleep(2)  	
	print("\n{0}Herramienta guardada en {1}/tools/Web/XAttacker".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Web && cd XAttacker && perl XAttacker.pl')

def Fuxploider():
	location = os.getcwd()
	os.system('sudo apt-get install python3-pip && cd tools && cd Web && git clone https://github.com/almandin/fuxploider.git && cd fuxploider && pip3 install -r requirements.txt')	
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Web/fuxploider".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Web && cd fuxploider && python3 fuxploider.py -h')			

def Wordpresscan():
	location = os.getcwd()
	os.system('cd tools && cd Web && git clone https://github.com/swisskyrepo/Wordpresscan.git && cd Wordpresscan && pip install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Web/Wordpresscan".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Web && cd Wordpresscan && python wordpresscan.py -h')

def SiteBroker():
	location = os.getcwd()
	os.system('cd tools && cd Web && git clone https://github.com/Anon-Exploiter/SiteBroker.git && cd SiteBroker && pip install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Web/SiteBroker".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Web && cd SiteBroker && python3 SiteBroker.py')

def NoSQLMap():
	location = os.getcwd()
	os.system('cd tools && cd Web && git clone https://github.com/codingo/NoSQLMap.git && cd NoSQLMap && python setup.py install')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Web/NoSQLMap".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Web && cd NoSQLMap && python nosqlmap.py')		

def SqliScanner():
	location = os.getcwd()
	os.system('cd tools && cd Web && git clone https://github.com/the-c0d3r/sqli-scanner.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Web/sqli-scanner".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Web && cd sqli-scanner && python sqli-scanner.py -h')

def Joomscan():
	os.system('cd tools && cd Web && git clone https://github.com/rezasp/joomscan.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Web/joomscan".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Web && cd joomscan && perl joomscan.pl')	

def Metagoofil():
	location = os.getcwd()
	os.system('cd tools && cd Web && git clone https://github.com/laramies/metagoofil.git')
  	time.sleep(2)
  	print("\n{0}Herramienta guardada en {1}/tools/Web/metagoofil".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Web && cd metagoofil && python metagoofil.py')

def Sublist3r():
	location = os.getcwd()
	os.system('cd tools && cd Web && git clone https://github.com/aboul3la/Sublist3r.git && cd Sublist3r && sudo pip install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Web/Sublist3r".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Web && cd Sublist3r && python sublist3r.py -h')		

def WAFNinja():
	location = os.getcwd()
	os.system('cd tools && cd Web && git clone https://github.com/khalilbijjou/WAFNinja.git && cd WAFNinja && pip install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Web/WAFNinja".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Web && cd WAFNinja && python wafninja.py -h')			

def Dirsearch():
	location = os.getcwd()
	os.system('sudo apt-get install python3.7 && cd tools && cd Web && git clone https://github.com/maurosoria/dirsearch.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Web/dirsearch".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Web && cd dirsearch && python3 dirsearch.py -h')

def XSStrike():
	location = os.getcwd()
	os.system('cd tools && cd Web && git clone https://github.com/s0md3v/XSStrike.git && cd XSStrike && pip install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Web/XSStrike".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Web && cd XSStrike && python xsstrike.py')		

def LinksF1nd3r():
	location = os.getcwd()
	os.system('cd tools && cd Web && git clone https://github.com/ihebski/LinksF1nd3r.git && cd LinksF1nd3r && pip install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Web/LinksF1nd3r".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Web && cd LinksF1nd3r && python linksF1nd3r.py')		

#Tools Spoofing
def SpoofMAC():
	location = os.getcwd()
	os.system('cd tools && cd Spoofing && git clone git://github.com/feross/SpoofMAC.git && cd SpoofMAC && python setup.py install')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Spoofing/SpoofMAC".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Spoofing && cd SpoofMAC && cd scripts && ./spoof-mac.py')		

def IpSpoofing():
	location = os.getcwd()
	os.system('cd tools && cd Spoofing && git clone https://github.com/pankajmore/ip_spoofing.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Spoofing/ip_spoofing".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Spoofing && cd ip_spoofing && python dos_attack.py')	

def Arpspoof():
	location = os.getcwd()
	os.system('cd tools && cd Spoofing && git clone https://github.com/ickerwx/arpspoof.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Spoofing/arpspoof".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Spoofing && cd arpspoof && python arpspoof.py -h')

def DerpNSpoof():
	location = os.getcwd()
	os.system('sudo apt install python3-pip && cd tools && cd Spoofing && git clone https://github.com/Trackbool/DerpNSpoof.git && cd DerpNSpoof && pip install -r requirements.txt')	
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Spoofing/DerpNSpoof".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Spoofing && cd DerpNSpoof && python3 DerpNSpoof.py')

def EmailSpoof():
	location = os.getcwd()
	os.system('cd tools && cd Spoofing && git clone https://github.com/MatiasTilerias/email-spoof.git && cd email-spoof && chmod +x ./emailspoof.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Spoofing/email-spoof".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Spoofing && cd email-spoof && ./emailspoof.sh')		

def DrSpoof():
	location = os.getcwd()
	os.system('cd tools && cd Spoofing && git clone https://github.com/Enixes/Dr.Spoof.git && cd Dr.Spoof && chmod +x DrSpoof.sh')
	time.sleep(2)			
	print("\n{0}Herramienta guardada en {1}/tools/Spoofing/Dr.spoof".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Spoofing && cd Dr.Spoof && ./DrSpoof.sh -h')	

def Smslistattack():
	location = os.getcwd()
	os.system('cd tools && cd Spoofing && git clone https://github.com/Firestormhacker/smslistattack.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Spoofing/smslistattack".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Spoofing && cd smslistattack && python sms_attack.py')		

#Tools Information Gathering
def NMAP():
	os.system('cd tools && cd InformationGathering && git clone https://github.com/nmap/nmap.git && cd nmap && ./configure && make && make install')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/nmap".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('nmap')

def Th3inspector():
	location = os.getcwd()
	os.system('cd tools && cd InformationGathering && git clone https://github.com/Moham3dRiahi/Th3inspector.git && cd Th3inspector && chmod +x install.sh && ./install.sh')
	time.sleep(2)		
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/Th3inspector".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd Th3inspector && perl Th3inspector.pl -h')	

def FBI():
	location = os.getcwd()
	os.system('cd tools && cd InformationGathering && git clone https://github.com/xHak9x/fbi.git && cd fbi && pip install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/fbi".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd fbi && python2 fbi.py')	

def Infoga():
	location = os.getcwd()
	os.system('cd tools && cd InformationGathering && git clone https://github.com/m4ll0k/Infoga.git && cd Infoga && python setup.py install')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/Infoga".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd Infoga && python infoga.py')	

def Crips():
	location = os.getcwd()
	os.system('cd tools && cd InformationGathering && git clone https://github.com/Manisso/Crips.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/Crips".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd Crips && python Crips.py')

def BillCipher():
	location = os.getcwd()
	os.system('sudo apt update && sudo apt install ruby python python-pip python3 python3-pip && sudo apt install httrack whatweb && cd tools && cd InformationGathering && git clone https://github.com/GitHackTools/BillCipher.git && cd BillCipher && pip install -r requirements.txt && pip3 install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/BillCipher".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd BillCipher && python3 billcipher.py')

def RedHawk():
	location = os.getcwd()
	os.system('sudo apt-get install php7.2 && cd tools && cd InformationGathering && git clone https://github.com/Tuhinshubhra/RED_HAWK.git')	
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/RED_HAWK".format(GREEN, location))
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd RED_HAWK && php redh.php')				

def ReconNg():
	location = os.getcwd()
	os.system('sudo apt-get install python3.6 && cd tools && cd InformationGathering && git clone https://github.com/lanmaster53/recon-ng.git && cd recon-ng && pip install -r REQUIREMENTS')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/recon-ng".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd recon-ng && python3 recon-ng')		

def theHarvester():
	location = os.getcwd()
	os.system('cd tools && cd InformationGathering && git clone https://github.com/alanchavez88/theHarvester.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/theHarvester".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd theHarvester && python theHarvester.py')

def PhoneInfoga():
	location = os.getcwd()
	os.system('sudo apt install python3-pip && cd tools && cd InformationGathering && git clone https://github.com/sundowndev/PhoneInfoga.git && cd PhoneInfoga && python3 -m pip install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/PhoneInfoga".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd PhoneInfoga && python3 phoneinfoga.py -h')

def Gasmask():
	location = os.getcwd()
	os.system('cd tools && cd InformationGathering && git clone https://github.com/twelvesec/gasmask.git && cd gasmask && pip install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/gasmask".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd gasmask && python gasmask.py')		

def Infog():
	location = os.getcwd()
	os.system('cd tools && cd InformationGathering && git clone https://github.com/thelinuxchoice/infog.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/infog".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd infog && bash infog.sh')

def Locator():
	location = os.getcwd()
	os.system('cd tools && cd InformationGathering && git clone https://github.com/thelinuxchoice/locator.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/locator".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd locator && bash locator.sh')	

def Userrecon():
	location = os.getcwd()
	os.system('cd tools && cd InformationGathering && git clone https://github.com/thelinuxchoice/userrecon.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/userrecon".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd userrecon && bash userrecon.sh')		

def Excuseme():
	location = os.getcwd()
	os.system('cd tools && cd InformationGathering && git clone https://github.com/thelinuxchoice/excuseme.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/excuseme".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd excuseme && bash excuseme.sh')	

def URLextractor():
	location = os.getcwd()
	os.system('cd tools && cd InformationGathering && git clone https://github.com/eschultze/URLextractor.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/URLextractor".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd URLextractor && bash extractor.sh')	

def Devploit():
	location = os.getcwd()
	os.system('cd tools && cd InformationGathering && git clone https://github.com/GhettoCole/Devploit.git && cd Devploit && chmod +x install && ./install')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/Devploit".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('Devploit')

def ReconDog():
	location = os.getcwd()
	os.system('cd tools && cd InformationGathering && git clone https://github.com/s0md3v/ReconDog.git && cd ReconDog && pip install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/ReconDog".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd ReconDog && python dog')	

def Webkiller():
	locatiom = os.getcwd()
	os.system('cd tools && cd InformationGathering && git clone https://github.com/ultrasecurity/webkiller.git && cd webkiller && pip install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/webkiller".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd webkiller && python webkiller.py')	

def Quasar():
	location = os.getcwd()
	os.system('cd tools && cd InformationGathering && git clone https://github.com/Cyb0r9/quasar.git && cd quasar && chmod +x * && sudo ./install.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/InformationGathering/quasar".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd InformationGathering && cd quasar && sudo ./quasar.sh')		

#Tools Others
def TheFatRat():
	location = os.getcwd()
	os.system('cd tools && cd Others && git clone https://github.com/Screetsec/TheFatRat.git && cd TheFatRat && chmod +x setup.sh && ./setup.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/TheFatRat".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('fatrat')

def Msfpc():
	location = os.getcwd()
	os.system('cd tools && cd Others && git clone https://github.com/g0tmi1k/msfpc.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/msfpc".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Others && cd msfpc && bash msfpc.sh')

def Fcrackzip():
	os.system('apt-get install fcrackzip')
	time.sleep(2)	
	print("\n{0}Herramienta guardada en /usr/bin/fcrackzip".format(GREEN))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('fcrackzip --help')

def QRLjacker():
	location = os.getcwd()
	os.system('sudo apt-get install python3.7 && cd tools && cd Others && git clone https://github.com/OWASP/QRLJacking.git && cd QRLJacking && cd QRLJacker && pip install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/QRLJacking".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Others && cd QRLJacking && cd QRLJacker && python3 QrlJacker.py')

def Lazy():
	location = os.getcwd()
	os.system('cd tools && cd Others && git clone https://github.com/arismelachroinos/lscript.git && cd lscript && chmod +x install.sh && ./install.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/lscript".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('l')	

def BlueThunderIPLocator():
	location = os.getcwd()
	os.system('apt-get install liblocal-lib-perl && apt-get install libjson-perl && apt-get upgrade libjson-perl && cd tools && cd Others && git clone https://github.com/the-shadowbrokers/Blue-Thunder-IP-Locator-.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/Blue-Thunder-IP-Locator-".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Others && cd Blue-Thunder-IP-Locator- && perl blue_thunder.pl')

def HTBINVITE():
	location = os.getcwd()
	os.system('cd tools && cd Others && git clone https://github.com/nycto-hackerone/HTB-INVITE.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/HTB-INVITE".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Others && cd HTB-INVITE && python HTB.py')

def Ngrok():
	location = os.getcwd()
	os.system('cd tools && cd Others && mkdir Ngrok && cd Ngrok && wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip && unzip ngrok-stable-linux-amd64.zip && chmod +x *')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/ngrok".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Others && cd Ngrok && ./ngrok')

def TheChoice():
	location = os.getcwd()
	os.system('cd tools && cd Others && git clone https://github.com/thelinuxchoice/thechoice.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/thechoice".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Others && cd thechoice && bash thechoice.sh')

def Ransomware():
	location = os.getcwd()
	os.system('cd tools && cd Others && mkdir ransomware && cd ransomware && wget http://download2268.mediafire.com/gn2lgzwcjcag/dwb2prgxqcd7jiq/ransomware.zip && unzip ransomware.zip')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/ransomware".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Others && cd ransomware && python ransomware.py -v')	 

def Bluepot():
	location = os.getcwd()
	os.system('sudo apt-get install default-jdk && cd tools && cd Others && mkdir Bluepot && cd Bluepot && wget https://github.com/andrewmichaelsmith/bluepot/raw/master/bin/bluepot-0.1.tar.gz && tar xfz bluepot-0.1.tar.gz')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/bluepot".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Others && cd Bluepot && sudo java -jar bluepot/BluePot-0.1.jar')

def Setoolkit():
	location = os.getcwd()
	os.system('cd tools && cd Others && git clone https://github.com/trustedsec/social-engineer-toolkit/ set/ && cd set && pip install -r requirements')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/set".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('setoolkit')

def A2sv():
	location = os.getcwd()
	os.system('pip install argparse && pip install netaddr && apt-get install openssl && cd tools && cd Others && git clone https://github.com/hahwul/a2sv.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/a2sv".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Others && cd a2sv && python a2sv.py -h')

def Fornonimizer():
	location = os.getcwd()
	os.system('cd tools && cd Others && git clone https://github.com/Hackplayers/4nonimizer.git && cd 4nonimizer && ./4nonimizer install')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/4nonimizer".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('4nonimizer help')				

def Saycheese():
	location = os.getcwd()
	os.system('cd tools && cd Others && git clone https://github.com/thelinuxchoice/saycheese.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/saycheese".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Others && cd saycheese && bash saycheese.sh')	

def Easysploit():
	location = os.getcwd()
	os.system('cd tools && cd Others && git clone https://github.com/KALILINUXTRICKSYT/easysploit.git && cd easysploit && bash installer.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/easysploit".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('easysploit')		

def NXcrypt():
	location = os.getcwd()
	os.system('cd tools && cd Others && git clone https://github.com/Hadi999/NXcrypt.git')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/NXcrypt".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Others && cd NXcrypt && python NXcrypt.py --help')

def KnockMail():
	location = os.getcwd()
	os.system('cd tools && cd Others && git clone https://github.com/4w4k3/KnockMail.git && cd KnockMail && sudo su && pip install -r requeriments.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/KnockMail".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Others && cd KnockMail && python knock.py')		

def RkHunter():
	location = os.getcwd()
	os.system('cd tools && cd Others && git clone https://github.com/installation/rkhunter.git && cd rkhunter && chmod +x install.sh && bash install.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/rkhunter".format(GREEN, location))		
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('rkhunter')

def HeraKeylogger():
	location = os.getcwd()
	os.system('sudo apt-get install python3-pip -y && cd tools && cd Others && git clone https://github.com/UndeadSec/HeraKeylogger.git && cd HeraKeylogger && sudo pip3 install -r requirements.txt')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/HeraKeylogger".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Others && cd HeraKeylogger && python3 hera.py')		

def ZLogger():
	location = os.getcwd()
	os.system('cd tools && cd Others && git clone https://github.com/z00z/ZLogger.git && cd ZLogger && bash install.sh')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/ZLogger".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('cd tools && cd Others && cd ZLogger && python zlogger.py')		

def Xerosploit():
	location = os.getcwd()
	os.system('cd tools && cd Others && git clone https://github.com/LionSec/xerosploit.git && cd xerosploit && sudo python install.py')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/xerosploit".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('sudo xerosploit')

def Slacksec():
	location = os.getcwd()
	os.system('cd tools && cd Others && sudo git clone https://github.com/franc205/Slacksec.git && cp Slacksec/slacksec.py /usr/bin/slacksec && sudo chmod +x /usr/bin/slacksec')
	time.sleep(2)
	print("\n{0}Herramienta guardada en {1}/tools/Others/Slacksec".format(GREEN, location))	
  	if raw_input("\n¿Desea ejecutarla? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		os.system('sudo slacksec')
