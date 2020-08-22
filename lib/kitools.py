#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Copyright 2020 KITHACK
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
	if not os.path.isdir('tools/Android/backdoor-apk'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && git clone https://github.com/dana-at-cp/backdoor-apk.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/backdoor-apk".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Android && cd backdoor-apk && cd backdoor-apk && ./backdoor-apk.sh')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def EvilDroid():
	location = os.getcwd()
	if not os.path.isdir('tools/Android/Evil-Droid'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && git clone https://github.com/M4sc3r4n0/Evil-Droid.git && cd Evil-Droid && chmod +x evil-droid')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/Evil-Droid".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Android && cd Evil-Droid && ./evil-droid')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Spade():
	location = os.getcwd()
	if not os.path.isdir('tools/Android/spade'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Android && git clone https://github.com/turksiberguvenlik/spade.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/spade".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()		
		else:
			os.system('cd tools && cd Android && cd spade && python spade.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def AhMyth():
	if not os.path.isdir('tools/Android/AhMyth'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && mkdir AhMyth && cd AhMyth && wget http://download1581.mediafire.com/yda7cvfrnesg/ifxzqonwvff2wir/AhMyth_linux64.deb && dpkg -i AhMyth_linux64.deb && apt --fix-broken install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en /usr/local/bin/ahmyth".format(GREEN, DEFAULT))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('ahmyth')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Andspoilt():
	location = os.getcwd()
	if not os.path.isdir('tools/Android/Andspoilt'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && git clone https://github.com/sundaysec/Andspoilt.git && cd Andspoilt && python ./setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/Andspoilt".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()			
		else:
			os.system('andspoilt')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Kwetza():
	location = os.getcwd()
	if not os.path.isdir('tools/Android/kwetza'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && git clone https://github.com/sensepost/kwetza.git && cd kwetza && pip install beautifulsoup4')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/kwetza".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()			
		else:
			os.system('cd tools && cd Android && cd kwetza && python kwetza.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Termux():
	location = os.getcwd()
	if not os.path.isdir('tools/Android/Termux'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && mkdir Termux && cd Termux && wget https://f-droid.org/repo/com.termux_96.apk')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/Termux".format(GREEN, DEFAULT, location))
		pause("\n{}Presione una tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def AndroidExploits():
	location = os.getcwd()
	if not os.path.isdir('tools/Android/Android-Exploits'):	
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && git clone https://github.com/sundaysec/Android-Exploits.git')
		print("\n{0}[✔] Done.{1}\nExploits guardados en {2}/tools/Android/Android-Exploits".format(GREEN, DEFAULT, location))
		pause("\n{}Presione una tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Grabcam():
	location = os.getcwd()
	if not os.path.isdir('tools/Android/grabcam'):	
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && git clone https://github.com/noob-hackers/grabcam.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/grabcam".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()			
		else:
			os.system('cd tools && cd Android && cd grabcam && sudo bash grabcam.sh')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def AndroidPatternLock():
	location = os.getcwd()
	if not os.path.isdir('tools/Android/androidpatternlock'):	
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && git clone https://github.com/sch3m4/androidpatternlock.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/androidpatternlock".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()			
		else:
			os.system('cd tools && cd Android && cd androidpatternlock && python aplc.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

#Tools Windows 
def Winpayloads():
	location = os.getcwd()
	if not os.path.isdir('tools/Windows/Winpayloads'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/nccgroup/Winpayloads.git && cd Winpayloads && chmod +x setup.sh && ./setup.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/Winpayloads".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Windows && cd Winpayloads && python WinPayloads.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def sAINT():
	location = os.getcwd()
	if not os.path.isdir('tools/Windows/sAINT'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt install maven default-jdk default-jre openjdk-8-jdk openjdk-8-jre -y && apt install maven default-jdk default-jre openjdk-8-jdk openjdk-8-jre -y && cd tools && cd Windows && git clone https://github.com/tiagorlampert/sAINT.git && cd sAINT && chmod +x configure.sh && ./configure.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/sAINT".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Windows && cd sAINT && java -jar sAINT.jar')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def BeeLogger():
	location = os.getcwd()
	if not os.path.isdir('tools/Windows/BeeLogger'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/4w4k3/BeeLogger.git && cd BeeLogger && sudo su && chmod +x install.sh && ./install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/BeeLogger".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Windows && cd BeeLogger && python bee.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def FakeImageExploiter():
	location = os.getcwd()
	if not os.path.isdir('tools/Windows/FakeImageExploiter'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/r00t-3xp10it/FakeImageExploiter.git && cd FakeImageExploiter && chmod +x *.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/FakeImageExploiter".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Windows && cd FakeImageExploiter && sudo ./FakeImageExploiter.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Koadic():
	location = os.getcwd()
	if not os.path.isdir('tools/Windows/koadic'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/zerosum0x0/koadic.git && cd koadic && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/koadic".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Windows && cd koadic && ./koadic.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def PhantomEvasion():
	location = os.getcwd()
	if not os.path.isdir('tools/Windows/Phantom-Evasion'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/oddcod3/Phantom-Evasion.git && cd Phantom-Evasion && sudo chmod +x phantom-evasion.py')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/Phantom-Evasion".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Windows && cd Phantom-Evasion && sudo ./phantom-evasion.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Ps1encode():
	location = os.getcwd()
	if not os.path.isdir('tools/Windows/ps1encode'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/CroweCybersecurity/ps1encode.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/ps1encode".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Windows && cd ps1encode && ./ps1encode.rb')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def DKMC():
	location = os.getcwd()
	if not os.path.isdir('tools/Windows/DKMC'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/Mr-Un1k0d3r/DKMC.git && cd DKMC && mkdir output')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/DKMC".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Windows && cd DKMC && python dkmc.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Cromos():
	location = os.getcwd()
	if not os.path.isdir('tools/Windows/cromos'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/6IX7ine/cromos.git && sudo chmod -R 777 cromos/ && cd cromos && python setup.py')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/cromos".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Windows && cd cromos && python cromos.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def EternalScanner():
	location = os.getcwd()
	if not os.path.isdir('tools/Windows/eternal_scanner'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/peterpt/eternal_scanner.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/eternal_scanner".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Windows && cd eternal_scanner && ./escan')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def EternalblueDoublepulsarMetasploit():
	location = os.getcwd()
	if not os.path.isdir('tools/Windows/Eternalblue-Doublepulsar-Metasploit'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit.git && cd Eternalblue-Doublepulsar-Metasploit && cp eternalblue_doublepulsar.rb /usr/share/metasploit-framework/modules/exploits/windows/smb/')
		print("\n{0}[✔] Done.{1}\nModulo guardado en /usr/share/metasploit-framework/modules/exploits/windows/smb/".format(GREEN, DEFAULT))
		pause("\n{}Presione una tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def MS17010EternalBlueWinXPWin10():
	location = os.getcwd()
	if not os.path.isdir('tools/Windows/MS17-010-EternalBlue-WinXP-Win10'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/hanshaze/MS17-010-EternalBlue-WinXP-Win10.git && cd MS17-010-EternalBlue-WinXP-Win10 && cp ms17_010_eternalblue_winXP-win10.rb /usr/share/metasploit-framework/modules/exploits/windows/smb/')
		print("\n{0}[✔] Done.{1}\nModulo guardado en /usr/share/metasploit-framework/modules/exploits/windows/smb/".format(GREEN, DEFAULT))
		pause("\n{}Presione una tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def WindowsExploits():
	location = os.getcwd()
	if not os.path.isdir('tools/Windows/Exploits'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/WindowsExploits/Exploits.git')
		print("\n{0}[✔] Done.{1}\nExploits guardados en {2}/tools/Windows/Exploits".format(GREEN, DEFAULT, location))
		pause("\n{}Presione una tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

#Tools Phishing
def HiddenEye():
	location = os.getcwd()
	if not os.path.isdir('tools/Phishing/HiddenEye'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/DarkSecDevelopers/HiddenEye.git && sudo apt install python3-pip && cd HiddenEye && sudo pip3 install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/HiddenEye".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()		
		else:
			os.system('cd tools && cd Phishing && cd HiddenEye && python3 HiddenEye.py')
			os.system('cd tools && cd Phishing && cd HiddenEye && python3 HiddenEye.py') #Segunda Ejecucion de HiddenEye para evitar el problema de conexiòn de internet.
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def PhishX():
	location = os.getcwd()
	if not os.path.isdir('tools/Phishing/PhishX'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/Userphish/PhishX.git && cd PhishX && chmod +x installer.sh && bash ./installer.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/PhishX".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Phishing && cd PhishX && python3 PhishX.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def SocialPhish():
	location = os.getcwd()
	if not os.path.isdir('tools/Phishing/SocialPhish'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/xHak9x/SocialPhish.git && cd SocialPhish && chmod +x socialphish.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/SocialPhish".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()			
		else:
			os.system('clear && cd tools && cd Phishing && cd SocialPhish && ./socialphish.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def SocialFish():
	location = os.getcwd()
	if not os.path.isdir('tools/Phishing/SocialFish'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/UndeadSec/SocialFish.git && sudo apt-get install python3 python3-pip python3-dev -y && cd SocialFish && python3 -m pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/SocialFish".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()			
		else:
			os.system('cd tools && cd Phishing && cd SocialFish && python3 SocialFish.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def PhisherMan():
	location = os.getcwd()
	if not os.path.isdir('tools/Phishing/Phisher-man'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/FDX100/Phisher-man.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/Phisher-man".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Phishing && cd Phisher-man && python phisherman.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Spectre():
	location = os.getcwd()
	if not os.path.isdir('tools/Phishing/Spectre'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/Pure-L0G1C/Spectre.git && cd Spectre && chmod +x install.sh && ./install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/Spectre".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Phishing && cd Spectre && python spectre.py --help')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Blackeye():
	location = os.getcwd()
	if not os.path.isdir('tools/Phishing/blackeye'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/An0nUD4Y/blackeye.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/blackeye".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('clear && cd tools && cd Phishing && cd blackeye && bash blackeye.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def PhEmail():
	location = os.getcwd()
	if not os.path.isdir('tools/Phishing/PhEmail'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/Dionach/PhEmail.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/PhEmail".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Phishing && cd PhEmail && python phemail.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Weeman():
	location = os.getcwd()
	if not os.path.isdir('tools/Phishing/weeman'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/evait-security/weeman.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/weeman".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Phishing && cd weeman && python weeman.py')	 	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Zphisher():
	location = os.getcwd()
	if not os.path.isdir('tools/Phishing/zphisher'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/htr-tech/zphisher.git && cd zphisher && chmod +x zphisher.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/zphisher".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Phishing && cd zphisher && bash zphisher.sh')	 	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def AIOPhish():
	location = os.getcwd()
	if not os.path.isdir('tools/Phishing/AIOPhish'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/DeepSociety/AIOPhish.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/AIOPhish".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Phishing && cd AIOPhish && sudo bash aiophish.sh')	 	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()			

#Tools Wifi 
def Fluxion():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/fluxion'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/FluxionNetwork/fluxion.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/fluxion".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Wifi && cd fluxion && ./fluxion.sh -i')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Wifiphisher():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/wifiphisher'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/wifiphisher/wifiphisher.git && cd wifiphisher && sudo python setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/wifiphisher".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('wifiphisher')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Wifibroot():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/WiFiBroot'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/hash3liZer/WiFiBroot.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/WiFiBroot".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Wifi && cd WiFiBroot && python wifibroot.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Wifite():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/wifite'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/derv82/wifite.git && cd wifite && chmod +x wifite.py')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/wifite".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Wifi && cd wifite && ./wifite.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Ettercap():
	if not os.path.isfile('/usr/bin/ettercap'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt-get install zlib1g zlib1g-dev && sudo apt-get install build-essential && sudo apt-get install ettercap && sudo apt-get install ettercap-graphical')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en /usr/bin/ettercap".format(GREEN, DEFAULT))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()		
		else:
			os.system('sudo ettercap -G')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Linset():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/linsetmv1-2'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/chunkingz/linsetmv1-2.git && cd linsetmv1-2 && chmod a+x linsetmv1-2 && mv linset /')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/linsetmv1-2".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Wifi && cd linsetmv1-2 && ./linsetmv1-2.sh')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def WiFiPumpkin():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/wifipumpkin3'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt install python3.7-dev python3-pyqt5 libssl-dev libffi-dev build-essential python3.7 && cd tools && cd Wifi && git clone https://github.com/P0cL4bs/wifipumpkin3.git && cd wifipumpkin3 && sudo python3 setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/wifipumpkin3".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('sudo wifipumpkin3')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Wifresti():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/wifresti'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/LionSec/wifresti.git && cd wifresti && cp wifresti.py /usr/bin/wifresti && chmod +x /usr/bin/wifresti')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/wifresti".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('sudo wifresti')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def EvilLimiter():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/evillimiter'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/bitbrute/evillimiter.git && cd evillimiter && sudo python3 setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/evillimiter".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('evillimiter')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def NetoolToolkit():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/netool-toolkit'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/r00t-3xp10it/netool-toolkit.git && cd netool-toolkit && sudo chmod +x INSTALL.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/netool-toolkit".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Wifi && cd netool-toolkit && sudo ./netool.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Dracnmap():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/Dracnmap'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/Screetsec/Dracnmap.git && cd Dracnmap && chmod +x Dracnmap.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/Dracnmap".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Wifi && cd Dracnmap && sudo ./Dracnmap.sh')					
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Airgeddon():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/airgeddon'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git && cd airgeddon && chmod +x airgeddon.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/airgeddon".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Wifi && cd airgeddon && ./airgeddon.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Routersploit():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/routersploit'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt-get install python3-pip && cd tools && cd Wifi && git clone https://www.github.com/threat9/routersploit.git && cd routersploit && python3 -m pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/routersploit".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Wifi && cd routersploit && python3 rsf.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Eaphammer():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/eaphammer'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt-get install python3-pip && cd tools && cd Wifi && git clone https://github.com/s0lst1c3/eaphammer.git && cd eaphammer && ./kali-setup')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/eaphammer".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()	
		else:
			os.system('cd tools && cd Wifi && cd eaphammer && ./eaphammer')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def VMRMDK():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/VMR-MDK-K2-2017R-012x4'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/chunkingz/VMR-MDK-K2-2017R-012x4.git && cd VMR-MDK-K2-2017R-012x4 && chmod +x VMR-MDK-K2-2017R-012x4.sh && mkdir VARMAC_CONFIG /root/ && mkdir VARMAC_LOGS /root/ && mkdir VARMAC_WASH /root/')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/VMR-MDK-K2-2017R-012x4".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Wifi && cd VMR-MDK-K2-2017R-012x4 && ./VMR-MDK-K2-2017R-012x4.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Wirespy():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/wirespy'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/aress31/wirespy.git && cd wirespy && chmod +x wirespy.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/wirespy".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Wifi && cd wirespy && sudo ./wirespy.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Wireshark():
	if not os.path.isfile('/usr/bin/wireshark'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt-get install wireshark && sudo setcap CAP_NET_RAW+eip CAP_NET_ADMIN+eip /usr/bin/dumpcap')	
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en /usr/bin/wireshark".format(GREEN, DEFAULT))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('wireshark')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def SniffAir():
	location = os.getcwd()
	if not os.path.isdir('tools/Wifi/SniffAir'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/Tylous/SniffAir.git && cd SniffAir && sudo ./setup.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/SniffAir".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Wifi && cd SniffAir && python SniffAir.py')			
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def WifiJammer():
	location = os.getcwd()
	if not os.path.isfile('tools/Wifi/wifijammer'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/DanMcInerney/wifijammer.git && cd wifijammer && python ./setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/Wifijammer".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Wifi && cd WifiJammer && sudo python wifijammer')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def KawaiiDeauther():
	location = os.getcwd()
	if not os.path.isfile('tools/Wifi/KawaiiDeauther'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/aryanrtm/KawaiiDeauther.git && cd KawaiiDeauther && sudo ./install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/KawaiiDeauther".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Wifi && cd KawaiiDeauther && sudo bash KawaiiDeauther.sh')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

#Tools passwords 
def Cupp():
	location = os.getcwd()
	if not os.path.isdir('tools/Passwords/cupp'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/Mebus/cupp.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/cupp".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Passwords && cd cupp && ./cupp.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Facebooker():
	location = os.getcwd()
	if not os.path.isdir('tools/Passwords/Facebooker'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/FakeFBI/Facebooker.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/Facebooker".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Passwords && cd Facebooker && perl facebooker.pl')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def BluForceFB():
	location = os.getcwd()
	if not os.path.isdir('tools/Passwords/BluForce-FB'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/AngelSecurityTeam/BluForce-FB.git && cd BluForce-FB && pip2 install mechanize')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/BluForce-FB".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Passwords && cd BluForce-FB && python2 bluforcefb.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Brut3k1t():
	location = os.getcwd()
	if not os.path.isdir('tools/Passwords/brut3k1t'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/ex0dus-0x/brut3k1t.git && cd brut3k1t && python setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/brut3k1t".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('brut3k1t -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def SocialBox():
	location = os.getcwd()
	if not os.path.isdir('tools/Passwords/SocialBox'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/TunisianEagles/SocialBox.git && cd SocialBox && chmod +x SocialBox.sh && chmod +x install-sb.sh && ./install-sb.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/SocialBox".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Passwords && cd SocialBox && ./SocialBox.sh')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def JohnTheRipper():
	location = os.getcwd()
	if not os.path.isdir('tools/Passwords/JohnTheRipper'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && mkdir JohnTheRipper && cd JohnTheRipper && wget http://www.openwall.com/john/j/john-1.8.0.tar.gz && tar -xzvf john-1.8.0.tar.gz && cd john-1.8.0/src/ && make clean generic')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/JohnTheRipper".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('john')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Hashcat():
	location = os.getcwd()
	if not os.path.isdir('tools/Passwords/hashcat'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/hashcat/hashcat.git && cd hashcat && make && sudo make install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/hashcat".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('hashcat -h')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Brutedum():
	location = os.getcwd()
	if not os.path.isdir('tools/Passwords/Brutedum'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt install python3 && cd tools && cd Passwords && git clone https://github.com/GitHackTools/BruteDum.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/Brutedum".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Passwords && cd Brutedum && python3 brutedum.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Facebash():
	location = os.getcwd()
	if not os.path.isdir('tools/Passwords/facebash'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/thelinuxchoice/facebash && cd facebash && chmod +x * && sudo bash install.sh && service tor start')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/facebash".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Passwords && cd facebash && sudo ./facebash.sh')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Brutespray():
	location = os.getcwd()
	if not os.path.isdir('tools/Passwords/brutespray'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/x90skysn3k/brutespray.git && cd brutespray && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/brutespray".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Passwords && cd brutespray && python brutespray.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Pupi():
	location = os.getcwd()
	if not os.path.isdir('tools/Passwords/PUPI'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt install python3 && cd tools && cd Passwords && git clone https://github.com/mIcHyAmRaNe/PUPI.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/PUPI".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Passwords && cd PUPI && python3 pupi.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def B4rbrute():
	location = os.getcwd()
	if not os.path.isdir('tools/Passwords/b4r-brute'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/b4rc0d37/b4r-brute.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/b4r-brute".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Passwords && cd b4r-brute && python b4r-brute.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def FbHack():
	location = os.getcwd()
	if not os.path.isdir('tools/Passwords/fb-hack'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/mirzaaltaf/fb-hack.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/fb-hack".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Passwords && cd fb-hack && python fb.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()							

#Tools Web
def SQLmap():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/sqlmap-dev'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/sqlmap-dev".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd sqlmap-dev && python sqlmap.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def XAttacker():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/XAttacker'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/Moham3dRiahi/XAttacker.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/XAttacker".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd XAttacker && perl XAttacker.pl')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Fuxploider():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/fuxploider'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt-get install python3-pip && cd tools && cd Web && git clone https://github.com/almandin/fuxploider.git && cd fuxploider && pip3 install -r requirements.txt')	
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/fuxploider".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd fuxploider && python3 fuxploider.py -h')			
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Wordpresscan():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/Wordpresscan'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/swisskyrepo/Wordpresscan.git && cd Wordpresscan && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/Wordpresscan".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd Wordpresscan && python wordpresscan.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def SiteBroker():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/SiteBroker'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/Anon-Exploiter/SiteBroker.git && cd SiteBroker && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/SiteBroker".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd SiteBroker && python3 SiteBroker.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def NoSQLMap():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/NoSQLMap'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/codingo/NoSQLMap.git && cd NoSQLMap && python setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/NoSQLMap".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd NoSQLMap && python nosqlmap.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def SqliScanner():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/sqli-scanner'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/the-c0d3r/sqli-scanner.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/sqli-scanner".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd sqli-scanner && python sqli-scanner.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Joomscan():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/joomscan'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Web && git clone https://github.com/rezasp/joomscan.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/joomscan".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd joomscan && perl joomscan.pl')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Metagoofil():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/metagoofil'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/laramies/metagoofil.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/metagoofil".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd metagoofil && python metagoofil.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Sublist3r():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/Sublist3r'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/aboul3la/Sublist3r.git && cd Sublist3r && sudo pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/Sublist3r".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd Sublist3r && python sublist3r.py -h')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def WAFNinja():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/WAFNinja'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/khalilbijjou/WAFNinja.git && cd WAFNinja && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/WAFNinja".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd WAFNinja && python wafninja.py -h')			
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Dirsearch():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/dirsearch'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt-get install python3.7 && cd tools && cd Web && git clone https://github.com/maurosoria/dirsearch.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/dirsearch".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd dirsearch && python3 dirsearch.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def XSStrike():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/XSStrike'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/s0md3v/XSStrike.git && cd XSStrike && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/XSStrike".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd XSStrike && python xsstrike.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def LinksF1nd3r():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/LinksF1nd3r'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/ihebski/LinksF1nd3r.git && cd LinksF1nd3r && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/linksF1nd3r".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd LinksF1nd3r && python linksF1nd3r.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def DTECH():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/D-Tech'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/bibortone/D-Tech.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/D-Tech".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd D-Tech && python d-tect.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

def Phpsploit():
	location = os.getcwd()
	if not os.path.isdir('tools/Web/phpsploit'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt install python3 python3-pip && cd tools && cd Web && git clone https://github.com/nil0x42/phpsploit.git && cd phpsploit && pip3 install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/phpsploit".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Web && cd phpsploit && ./phpsploit --interactive --eval "help help"')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

#Tools Spoofing
def SpoofMAC():
	location = os.getcwd()
	if not os.path.isdir('tools/Spoofing/SpoofMAC'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Spoofing && git clone git://github.com/feross/SpoofMAC.git && cd SpoofMAC && python setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Spoofing/SpoofMAC".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Spoofing && cd SpoofMAC && cd scripts && ./spoof-mac.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()		

def IpSpoofing():
	location = os.getcwd()
	if not os.path.isdir('tools/Spoofing/ip_spoofing'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Spoofing && git clone https://github.com/pankajmore/ip_spoofing.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Spoofing/ip_spoofing".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Spoofing && cd ip_spoofing && python dos_attack.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()		

def Arpspoof():
	location = os.getcwd()
	if not os.path.isdir('tools/Spoofing/arpspoof'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Spoofing && git clone https://github.com/ickerwx/arpspoof.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Spoofing/arpspoof".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Spoofing && cd arpspoof && python arpspoof.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def DerpNSpoof():
	location = os.getcwd()
	if not os.path.isdir('tools/Spoofing/DerpNSpoof'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt install python3-pip && cd tools && cd Spoofing && git clone https://github.com/Trackbool/DerpNSpoof.git && cd DerpNSpoof && pip install -r requirements.txt')	
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Spoofing/DerpNSpoof".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Spoofing && cd DerpNSpoof && python3 DerpNSpoof.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def DrSpoof():
	location = os.getcwd()
	if not os.path.isdir('tools/Spoofing/Dr.Spoof'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Spoofing && git clone https://github.com/Enixes/Dr.Spoof.git && cd Dr.Spoof && chmod +x DrSpoof.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Spoofing/Dr.Spoof".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Spoofing && cd Dr.Spoof && ./DrSpoof.sh -h')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def GODKILLER():
	location = os.getcwd()
	if not os.path.isdir('tools/Spoofing/GOD-KILLER'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Spoofing && git clone https://github.com/FDX100/GOD-KILLER.git && cd GOD-KILLER && python install.py')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Spoofing/GOD-KILLER".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('GOD-KILLER')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()

#Tools Information Gathering
def NMAP():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/nmap'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/nmap/nmap.git && cd nmap && ./configure && make && make install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/nmap".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('nmap')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Th3inspector():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/Th3inspector'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/Moham3dRiahi/Th3inspector.git && cd Th3inspector && chmod +x install.sh && ./install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/Th3inspector".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd Th3inspector && perl Th3inspector.pl -h')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def FBI():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/fbi'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/xHak9x/fbi.git && cd fbi && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/fbi".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd fbi && python2 fbi.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Infoga():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/Infoga'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/m4ll0k/Infoga.git && cd Infoga && python setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/Infoga".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd Infoga && python infoga.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Crips():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/Crips'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/Manisso/Crips.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/Crips".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd Crips && python Crips.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def BillCipher():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/billcipher'):	
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt update && sudo apt install ruby python python-pip python3 python3-pip && sudo apt install httrack whatweb && cd tools && cd InformationGathering && git clone https://github.com/GitHackTools/BillCipher.git && cd BillCipher && pip install -r requirements.txt && pip3 install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/BillCipher".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd BillCipher && python3 billcipher.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def RedHawk():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/RED_HAWK'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt-get install php7.2 && cd tools && cd InformationGathering && git clone https://github.com/Tuhinshubhra/RED_HAWK.git')	
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/RED_HAWK".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd RED_HAWK && php redh.php')				
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def ReconNg():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/recon-ng'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt-get install python3.6 && cd tools && cd InformationGathering && git clone https://github.com/lanmaster53/recon-ng.git && cd recon-ng && pip install -r REQUIREMENTS')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/recon-ng".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd recon-ng && python3 recon-ng')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def theHarvester():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/theHarvester'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/alanchavez88/theHarvester.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/theHarvester".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd theHarvester && python theHarvester.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def PhoneInfoga():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/PhoneInfoga'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt install python3-pip && cd tools && cd InformationGathering && git clone https://github.com/sundowndev/PhoneInfoga.git && cd PhoneInfoga && python3 -m pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/PhoneInfoga".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd PhoneInfoga && python3 phoneinfoga.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Gasmask():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/gasmask'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/twelvesec/gasmask.git && cd gasmask && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/gasmask".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd gasmask && python gasmask.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def URLextractor():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/URLextractor'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/eschultze/URLextractor.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/URLextractor".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd URLextractor && bash extractor.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Devploit():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/Devploit'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/GhettoCole/Devploit.git && cd Devploit && chmod +x install && ./install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/Devploit".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('Devploit')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def ReconDog():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/ReconDog'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/s0md3v/ReconDog.git && cd ReconDog && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/ReconDog".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd ReconDog && python dog')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Webkiller():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/webkiller'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/ultrasecurity/webkiller.git && cd webkiller && pip3 install -r requirments.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/webkiller".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd webkiller && python3 webkiller.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Quasar():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/quasar'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/Cyb0r9/quasar.git && cd quasar && chmod +x * && sudo ./install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/quasar".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd quasar && sudo ./quasar.sh')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def InfoInstagramIphone():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/info-instagram-iphone'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt install python3 python3-pip && pip3 install quidam && cd tools && cd InformationGathering && git clone https://github.com/0xfff0800/info-instagram-iphone.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/info-instagram-iphone".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd info-instagram-iphone && python3 FaLaH-iphone.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def UserScan():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/userscan'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/JoeTech-Studio/UserScan.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/userscan".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd userscan && sudo bash userscan.sh')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def XCTRHackingTools():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/XCTR-Hacking-Tools'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt install python3 python3-pip && cd tools && cd InformationGathering && git clone https://github.com/capture0x/XCTR-Hacking-Tools.git && cd XCTR-Hacking-Tools && pip3 install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/XCTR-Hacking-Tools".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd InformationGathering && cd XCTR-Hacking-Tools && python3 xctr.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def DeadTrap():
	location = os.getcwd()
	if not os.path.isdir('tools/InformationGathering/DeadTrap'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt install python3-pip firefox-geckodriver && cd tools && cd InformationGathering && git clone https://github.com/Chr0m0s0m3s/DeadTrap.git && cd DeadTrap && pip3 install .')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/DeadTrap".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('deadtrap')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()			

#Tools Others
def TheFatRat():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/TheFatRat'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/Screetsec/TheFatRat.git && cd TheFatRat && chmod +x setup.sh && ./setup.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/TheFatRat".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('fatrat')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Msfpc():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/msfpc'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/g0tmi1k/msfpc.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/msfpc".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd msfpc && bash msfpc.sh')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Fcrackzip():
	if not os.path.isfile('/usr/bin/fcrackzip'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt-get install fcrackzip')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en /usr/bin/fcrackzip".format(GREEN, DEFAULT))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('fcrackzip --help')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def QRLjacker():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/QRLJacking'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt-get install python3.7 && cd tools && cd Others && git clone https://github.com/OWASP/QRLJacking.git && cd QRLJacking && cd QRLJacker && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/QRLJacking".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd QRLJacking && cd QRLJacker && python3 QrlJacker.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Lazy():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/lscript'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/arismelachroinos/lscript.git && cd lscript && chmod +x install.sh && ./install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/lscript ".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('l')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def HTBINVITE():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/HTB-INVITE'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/nycto-hackerone/HTB-INVITE.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/HTB-INVITE".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd HTB-INVITE && python HTB.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Ngrok():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/Ngrok'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && mkdir Ngrok && cd Ngrok && wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip && unzip ngrok-stable-linux-amd64.zip && chmod +x *')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/Ngrok".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd Ngrok && ./ngrok')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Bluepot():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/Bluepot'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt-get install default-jdk && cd tools && cd Others && mkdir Bluepot && cd Bluepot && wget https://github.com/andrewmichaelsmith/bluepot/raw/master/bin/bluepot-0.1.tar.gz && tar xfz bluepot-0.1.tar.gz')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/Bluepot".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd Bluepot && sudo java -jar bluepot/BluePot-0.1.jar')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Setoolkit():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/set'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/trustedsec/social-engineer-toolkit/ set/ && cd set && pip install -r requirements')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/set".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('setoolkit')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def A2sv():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/a2sv'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('pip install argparse && pip install netaddr && apt-get install openssl && cd tools && cd Others && git clone https://github.com/hahwul/a2sv.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/a2sv".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd a2sv && python a2sv.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Fornonimizer():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/4nonimizer'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/Hackplayers/4nonimizer.git && cd 4nonimizer && ./4nonimizer install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/4nonimizer".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('4nonimizer help')				
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	
	
def Easysploit():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/easysploit'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/KALILINUXTRICKSYT/easysploit.git && cd easysploit && bash installer.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/easysploit".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('easysploit')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def NXcrypt():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/NXcrypt'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/Hadi999/NXcrypt.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/NXcrypt".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd NXcrypt && python NXcrypt.py --help')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def KnockMail():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/KnockMail'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/4w4k3/KnockMail.git && cd KnockMail && sudo su && pip install -r requeriments.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/KnockMail".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd KnockMail && python knock.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def RkHunter():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/rkhunter'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/installation/rkhunter.git && cd rkhunter && chmod +x install.sh && bash install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/rkhunter".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('rkhunter')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def HeraKeylogger():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/HeraKeylogger'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('sudo apt-get install python3-pip -y && cd tools && cd Others && git clone https://github.com/UndeadSec/HeraKeylogger.git && cd HeraKeylogger && sudo pip3 install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/HeraKeylogger".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd HeraKeylogger && python3 hera.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def ZLogger():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/ZLogger'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/z00z/ZLogger.git && cd ZLogger && bash install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/ZLogger".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd ZLogger && python zlogger.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Xerosploit():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/xerosploit'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/LionSec/xerosploit.git && cd xerosploit && sudo python install.py')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/xerosploit".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('sudo xerosploit')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Slacksec():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/Slacksec'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && sudo git clone https://github.com/franc205/Slacksec.git && cp Slacksec/slacksec.py /usr/bin/slacksec && sudo chmod +x /usr/bin/slacksec')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/Slacksec".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('sudo slacksec')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Katana():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/KatanaFramework'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Others && git clone https://github.com/PowerScript/KatanaFramework && cd KatanaFramework && sudo sh dependencies && sudo python install')		
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/KatanaFramework".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd KatanaFramework && ktf.console')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()			

def Z0172CKTools():	
	location = os.getcwd()
	if not os.path.isdir('tools/Others/Z0172CK-Tools'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('sudo apt install python3 python3-pip && cd tools && cd Others && git clone https://github.com/Erik172/Z0172CK-Tools.git && cd Z0172CK-Tools && bash install.sh && pip3 install -r requirements.txt')		
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/Z0172CK-Tools".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd Z0172CK-Tools && python3 index.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def CamHack():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/Cam-Hack'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Others && git clone https://github.com/Hack-The-World-With-Tech/Cam-Hack.git && cd Cam-Hack && chmod +x *')		
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/Cam-Hack".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd Cam-Hack && sudo bash camhack.sh')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Onex():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/onex'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Others && git clone https://github.com/rajkumardusad/onex.git && cd onex && sudo bash install')		
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/onex".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd onex && sudo bash onex')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Ransom0():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/Ransom0'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Others && git clone https://github.com/HugoLB0/Ransom0.git && cd Ransom0 && pip2 install requirementx.txt')		
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/Ransom0".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd Ransom0 && python ransom0.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Morpheus():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/morpheus'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Others && git clone https://github.com/r00t-3xp10it/morpheus.git')		
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/morpheus".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd morpheus && sudo bash morpheus.sh')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()		

def FBTOOL():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/FBTOOL'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Others && git clone https://github.com/mkdirlove/FBTOOL.git')		
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/FBTOOL".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()
		else:
			os.system('cd tools && cd Others && cd FBTOOL && sudo python2 fbtool.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()	

def Venom():
	location = os.getcwd()
	if not os.path.isdir('tools/Others/venom'):	
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/r00t-3xp10it/venom.git && cd venom && chmod +x * && sudo bash setup.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/venom".format(GREEN, DEFAULT, location))
		if raw_input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			KitHack.banner(), KitHack.menu(), KitHack.options()			
		else:
			os.system('cd tools && cd Others && cd venom && sudo bash venom.sh')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		KitHack.banner(), KitHack.menu(), KitHack.options()


