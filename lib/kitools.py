#!/usr/bin/python3
# -*- coding: utf-8 -*-
#Copyright 2021 KITHACK
#Written by: Adrian Guillermo
#Facebook: https://facebook.com/adrian.guillermo.22
#Github: https://github.com/AdrMXR

BLUE, RED, WHITE, CYAN, DEFAULT, YELLOW, MAGENTA, GREEN, END, BOLD = '\33[94m', '\033[91m', '\33[97m', '\033[36m', '\033[0m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m', '\033[1m'

import os
import time
import sys
from sys import exit
from getch import pause
from KitHack import main

location = os.getcwd()

#Tools Android 
def BackdoorApk():
	if not os.path.isdir('tools/Android/backdoor-apk'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && git clone https://github.com/dana-at-cp/backdoor-apk.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/backdoor-apk".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Android && cd backdoor-apk && cd backdoor-apk && bash backdoor-apk.sh')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Android && cd backdoor-apk && cd backdoor-apk && bash backdoor-apk.sh')

def EvilDroid():
	if not os.path.isdir('tools/Android/Evil-Droid'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && git clone https://github.com/M4sc3r4n0/Evil-Droid.git && cd Evil-Droid && chmod +x evil-droid')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/Evil-Droid".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Android && cd Evil-Droid && bash evil-droid')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Android && cd Evil-Droid && bash evil-droid')

def Spade():
	if not os.path.isdir('tools/Android/spade'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Android && git clone https://github.com/turksiberguvenlik/spade.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/spade".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()		
		else:
			os.system('cd tools && cd Android && cd spade && python spade.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Android && cd spade && python spade.py')

def AhMyth():
	if not os.path.isdir('tools/Android/AhMyth'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && mkdir AhMyth && cd AhMyth && wget http://download1581.mediafire.com/yda7cvfrnesg/ifxzqonwvff2wir/AhMyth_linux64.deb && dpkg -i AhMyth_linux64.deb && apt --fix-broken install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en /usr/local/bin/ahmyth".format(GREEN, DEFAULT))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('ahmyth')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('ahmyth')

def Andspoilt():
	if not os.path.isdir('tools/Android/Andspoilt'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && git clone https://github.com/sundaysec/Andspoilt.git && cd Andspoilt && python setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/Andspoilt".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()			
		else:
			os.system('andspoilt')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('andspoilt')	

def Kwetza():
	if not os.path.isdir('tools/Android/kwetza'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && git clone https://github.com/sensepost/kwetza.git && cd kwetza && pip install beautifulsoup4')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/kwetza".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()			
		else:
			os.system('cd tools && cd Android && cd kwetza && python kwetza.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Android && cd kwetza && python kwetza.py')

def Termux():
	if not os.path.isdir('tools/Android/Termux'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && mkdir Termux && cd Termux && wget https://f-droid.org/repo/com.termux_96.apk')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/Termux".format(GREEN, DEFAULT, location))
		pause("\n{}Presione una tecla para continuar...".format(GREEN))
		os.system('clear')
		main()
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		main()

def AndroidExploits():
	if not os.path.isdir('tools/Android/Android-Exploits'):	
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && git clone https://github.com/sundaysec/Android-Exploits.git')
		print("\n{0}[✔] Done.{1}\nExploits guardados en {2}/tools/Android/Android-Exploits".format(GREEN, DEFAULT, location))
		pause("\n{}Presione una tecla para continuar...".format(GREEN))
		os.system('clear')
		main()	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		main()

def Grabcam():
	if not os.path.isdir('tools/Android/grabcam'):	
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && git clone https://github.com/noob-hackers/grabcam.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/grabcam".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()			
		else:
			os.system('cd tools && cd Android && cd grabcam && bash grabcam.sh')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Android && cd grabcam && bash grabcam.sh')

def AndroidPatternLock():
	if not os.path.isdir('tools/Android/androidpatternlock'):	
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Android && git clone https://github.com/sch3m4/androidpatternlock.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Android/androidpatternlock".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()			
		else:
			os.system('cd tools && cd Android && cd androidpatternlock && python aplc.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Android && cd androidpatternlock && python aplc.py')

#Tools Windows 
def Winpayloads():
	if not os.path.isdir('tools/Windows/Winpayloads'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/nccgroup/Winpayloads.git && cd Winpayloads && chmod +x setup.sh && bash setup.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/Winpayloads".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd Winpayloads && python WinPayloads.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd Winpayloads && python WinPayloads.py')

def sAINT():
	if not os.path.isdir('tools/Windows/sAINT'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt install maven default-jdk default-jre openjdk-8-jdk openjdk-8-jre -y && apt install maven default-jdk default-jre openjdk-8-jdk openjdk-8-jre -y && cd tools && cd Windows && git clone https://github.com/tiagorlampert/sAINT.git && cd sAINT && chmod +x configure.sh && bash configure.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/sAINT".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd sAINT && java -jar sAINT.jar')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd sAINT && java -jar sAINT.jar')

def BeeLogger():
	if not os.path.isdir('tools/Windows/BeeLogger'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/4w4k3/BeeLogger.git && cd BeeLogger && su && chmod +x install.sh && bash install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/BeeLogger".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd BeeLogger && python bee.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd BeeLogger && python bee.py')

def FakeImageExploiter():
	if not os.path.isdir('tools/Windows/FakeImageExploiter'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/r00t-3xp10it/FakeImageExploiter.git && cd FakeImageExploiter && chmod +x *.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/FakeImageExploiter".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd FakeImageExploiter && bash FakeImageExploiter.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd FakeImageExploiter && bash FakeImageExploiter.sh')

def Koadic():
	if not os.path.isdir('tools/Windows/koadic'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/zerosum0x0/koadic.git && cd koadic && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/koadic".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd koadic && python koadic.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd koadic && python koadic.py')

def PhantomEvasion():
	if not os.path.isdir('tools/Windows/Phantom-Evasion'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/oddcod3/Phantom-Evasion.git && cd Phantom-Evasion && chmod +x phantom-evasion.py')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/Phantom-Evasion".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd Phantom-Evasion && python phantom-evasion.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd Phantom-Evasion && python phantom-evasion.py')

def Ps1encode():
	if not os.path.isdir('tools/Windows/ps1encode'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/CroweCybersecurity/ps1encode.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/ps1encode".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd ps1encode && ruby ps1encode.rb')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd ps1encode && ruby ps1encode.rb')

def DKMC():
	if not os.path.isdir('tools/Windows/DKMC'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/Mr-Un1k0d3r/DKMC.git && cd DKMC && mkdir output')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/DKMC".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd DKMC && python dkmc.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd DKMC && python dkmc.py')

def Cromos():
	if not os.path.isdir('tools/Windows/cromos'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/6IX7ine/cromos.git && chmod -R 777 cromos/ && cd cromos && python setup.py')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/cromos".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd cromos && python cromos.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd cromos && python cromos.py')

def EternalScanner():
	if not os.path.isdir('tools/Windows/eternal_scanner'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/peterpt/eternal_scanner.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Windows/eternal_scanner".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Windows && cd eternal_scanner && bash escan')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Windows && cd eternal_scanner && bash escan')

def EternalblueDoublepulsarMetasploit():
	if not os.path.isdir('tools/Windows/Eternalblue-Doublepulsar-Metasploit'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit.git && cd Eternalblue-Doublepulsar-Metasploit && cp eternalblue_doublepulsar.rb /usr/share/metasploit-framework/modules/exploits/windows/smb/')
		print("\n{0}[✔] Done.{1}\nModulo guardado en /usr/share/metasploit-framework/modules/exploits/windows/smb/".format(GREEN, DEFAULT))
		pause("\n{}Presione una tecla para continuar...".format(GREEN))
		os.system('clear')
		main()	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		main()

def MS17010EternalBlueWinXPWin10():
	if not os.path.isdir('tools/Windows/MS17-010-EternalBlue-WinXP-Win10'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/hanshaze/MS17-010-EternalBlue-WinXP-Win10.git && cd MS17-010-EternalBlue-WinXP-Win10 && cp ms17_010_eternalblue_winXP-win10.rb /usr/share/metasploit-framework/modules/exploits/windows/smb/')
		print("\n{0}[✔] Done.{1}\nModulo guardado en /usr/share/metasploit-framework/modules/exploits/windows/smb/".format(GREEN, DEFAULT))
		pause("\n{}Presione una tecla para continuar...".format(GREEN))
		os.system('clear')
		main()		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		main()

def WindowsExploits():
	if not os.path.isdir('tools/Windows/Exploits'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Windows && git clone https://github.com/WindowsExploits/Exploits.git')
		print("\n{0}[✔] Done.{1}\nExploits guardados en {2}/tools/Windows/Exploits".format(GREEN, DEFAULT, location))
		pause("\n{}Presione una tecla para continuar...".format(GREEN))
		os.system('clear')
		main()		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
		os.system('clear')
		main()

#Tools Phishing
def HiddenEye():
	if not os.path.isdir('tools/Phishing/HiddenEye'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/AdrMXR/HiddenEye.git && apt install python3-pip && cd HiddenEye && pip3 install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/HiddenEye".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()		
		else:
			os.system('cd tools && cd Phishing && cd HiddenEye && python3 HiddenEye.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Phishing && cd HiddenEye && python3 HiddenEye.py')

def PhishX():
	if not os.path.isdir('tools/Phishing/PhishX'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/Userphish/PhishX.git && cd PhishX && chmod +x installer.sh && bash installer.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/PhishX".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Phishing && cd PhishX && python3 PhishX.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Phishing && cd PhishX && python3 PhishX.py')

def SocialPhish():
	if not os.path.isdir('tools/Phishing/SocialPhish'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/xHak9x/SocialPhish.git && cd SocialPhish && chmod +x socialphish.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/SocialPhish".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()			
		else:
			os.system('clear && cd tools && cd Phishing && cd SocialPhish && bash socialphish.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('clear && cd tools && cd Phishing && cd SocialPhish && bash socialphish.sh')

def SocialFish():
	if not os.path.isdir('tools/Phishing/SocialFish'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/UndeadSec/SocialFish.git && apt-get install python3 python3-pip python3-dev -y && cd SocialFish && python3 -m pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/SocialFish".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()			
		else:
			os.system('cd tools && cd Phishing && cd SocialFish && python3 SocialFish.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Phishing && cd SocialFish && python3 SocialFish.py')

def PhisherMan():
	if not os.path.isdir('tools/Phishing/Phisher-man'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/FDX100/Phisher-man.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/Phisher-man".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Phishing && cd Phisher-man && python phisherman.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Phishing && cd Phisher-man && python phisherman.py')

def Spectre():
	if not os.path.isdir('tools/Phishing/Spectre'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/Pure-L0G1C/Spectre.git && cd Spectre && chmod +x install.sh && bash install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/Spectre".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Phishing && cd Spectre && python spectre.py --help')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Phishing && cd Spectre && python spectre.py --help')

def Blackeye():
	if not os.path.isdir('tools/Phishing/blackeye'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/An0nUD4Y/blackeye.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/blackeye".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('clear && cd tools && cd Phishing && cd blackeye && bash blackeye.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('clear && cd tools && cd Phishing && cd blackeye && bash blackeye.sh')

def PhEmail():
	if not os.path.isdir('tools/Phishing/PhEmail'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/Dionach/PhEmail.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/PhEmail".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Phishing && cd PhEmail && python phemail.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Phishing && cd PhEmail && python phemail.py')

def Weeman():
	if not os.path.isdir('tools/Phishing/weeman'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/evait-security/weeman.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/weeman".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Phishing && cd weeman && python weeman.py')	 	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Phishing && cd weeman && python weeman.py')

def Zphisher():
	if not os.path.isdir('tools/Phishing/zphisher'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/htr-tech/zphisher.git && cd zphisher && chmod +x zphisher.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/zphisher".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Phishing && cd zphisher && bash zphisher.sh')	 	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Phishing && cd zphisher && bash zphisher.sh')

def AIOPhish():
	if not os.path.isdir('tools/Phishing/AIOPhish'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Phishing && git clone https://github.com/DeepSociety/AIOPhish.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Phishing/AIOPhish".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Phishing && cd AIOPhish && bash aiophish.sh')	 	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Phishing && cd AIOPhish && bash aiophish.sh')		

#Tools Wifi 
def Fluxion():
	if not os.path.isdir('tools/Wifi/fluxion'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/FluxionNetwork/fluxion.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/fluxion".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd fluxion && bash fluxion.sh -i')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd fluxion && bash fluxion.sh -i')

def Wifiphisher():
	if not os.path.isdir('tools/Wifi/wifiphisher'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/wifiphisher/wifiphisher.git && cd wifiphisher && python setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/wifiphisher".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('wifiphisher')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('wifiphisher')

def Wifibroot():
	if not os.path.isdir('tools/Wifi/WiFiBroot'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/hash3liZer/WiFiBroot.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/WiFiBroot".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd WiFiBroot && python wifibroot.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd WiFiBroot && python wifibroot.py -h')

def Wifite():
	if not os.path.isdir('tools/Wifi/wifite'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/derv82/wifite.git && cd wifite && chmod +x wifite.py')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/wifite".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd wifite && python wifite.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd wifite && python wifite.py')

def Ettercap():
	if not os.path.isfile('/usr/bin/ettercap'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt-get install zlib1g zlib1g-dev && apt-get install build-essential && apt-get install ettercap && apt-get install ettercap-graphical')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en /usr/bin/ettercap".format(GREEN, DEFAULT))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()		
		else:
			os.system('ettercap -G')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('ettercap -G')

def Linset():
	if not os.path.isdir('tools/Wifi/linsetmv1-2'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/chunkingz/linsetmv1-2.git && cd linsetmv1-2 && chmod a+x linsetmv1-2 && mv linset /')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/linsetmv1-2".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Wifi && cd linsetmv1-2 && bash linsetmv1-2.sh')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd linsetmv1-2 && bash linsetmv1-2.sh')

def WiFiPumpkin():
	if not os.path.isdir('tools/Wifi/wifipumpkin3'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt install python3.7-dev python3-pyqt5 libssl-dev libffi-dev build-essential python3.7 && cd tools && cd Wifi && git clone https://github.com/P0cL4bs/wifipumpkin3.git && cd wifipumpkin3 && python3 setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/wifipumpkin3".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('wifipumpkin3')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('wifipumpkin3')

def Wifresti():
	if not os.path.isdir('tools/Wifi/wifresti'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/LionSec/wifresti.git && cd wifresti && cp wifresti.py /usr/bin/wifresti && chmod +x /usr/bin/wifresti')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/wifresti".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('wifresti')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('wifresti')

def EvilLimiter():
	if not os.path.isdir('tools/Wifi/evillimiter'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/bitbrute/evillimiter.git && cd evillimiter && python3 setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/evillimiter".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('evillimiter')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('evillimiter')

def NetoolToolkit():
	if not os.path.isdir('tools/Wifi/netool-toolkit'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/r00t-3xp10it/netool-toolkit.git && cd netool-toolkit && chmod +x INSTALL.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/netool-toolkit".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Wifi && cd netool-toolkit && bash netool.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd netool-toolkit && bash netool.sh')

def Dracnmap():
	if not os.path.isdir('tools/Wifi/Dracnmap'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/Screetsec/Dracnmap.git && cd Dracnmap && chmod +x Dracnmap.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/Dracnmap".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Wifi && cd Dracnmap && bash Dracnmap.sh')					
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd Dracnmap && bash Dracnmap.sh')

def Airgeddon():
	if not os.path.isdir('tools/Wifi/airgeddon'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git && cd airgeddon && chmod +x airgeddon.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/airgeddon".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Wifi && cd airgeddon && bash airgeddon.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd airgeddon && bash airgeddon.sh')

def Routersploit():
	if not os.path.isdir('tools/Wifi/routersploit'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt-get install python3-pip && cd tools && cd Wifi && git clone https://www.github.com/threat9/routersploit.git && cd routersploit && python3 -m pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/routersploit".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Wifi && cd routersploit && python3 rsf.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd routersploit && python3 rsf.py')

def Eaphammer():
	if not os.path.isdir('tools/Wifi/eaphammer'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt-get install python3-pip && cd tools && cd Wifi && git clone https://github.com/s0lst1c3/eaphammer.git && cd eaphammer && python3 kali-setup')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/eaphammer".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()	
		else:
			os.system('cd tools && cd Wifi && cd eaphammer && python3 eaphammer')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd eaphammer && python3 eaphammer')

def VMRMDK():
	if not os.path.isdir('tools/Wifi/VMR-MDK-K2-2017R-012x4'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/chunkingz/VMR-MDK-K2-2017R-012x4.git && cd VMR-MDK-K2-2017R-012x4 && chmod +x VMR-MDK-K2-2017R-012x4.sh && mkdir VARMAC_CONFIG /root/ && mkdir VARMAC_LOGS /root/ && mkdir VARMAC_WASH /root/')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/VMR-MDK-K2-2017R-012x4".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd VMR-MDK-K2-2017R-012x4 && bash VMR-MDK-K2-2017R-012x4.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd VMR-MDK-K2-2017R-012x4 && bash VMR-MDK-K2-2017R-012x4.sh')

def Wirespy():
	if not os.path.isdir('tools/Wifi/wirespy'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/aress31/wirespy.git && cd wirespy && chmod +x wirespy.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/wirespy".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd wirespy && bash wirespy.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd wirespy && bash wirespy.sh')

def Wireshark():
	if not os.path.isfile('/usr/bin/wireshark'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt-get install wireshark && setcap CAP_NET_RAW+eip CAP_NET_ADMIN+eip /usr/bin/dumpcap')	
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en /usr/bin/wireshark".format(GREEN, DEFAULT))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('wireshark')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('wireshark')

def SniffAir():
	if not os.path.isdir('tools/Wifi/SniffAir'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/Tylous/SniffAir.git && cd SniffAir && bash setup.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/SniffAir".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd SniffAir && python SniffAir.py')			
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd SniffAir && python SniffAir.py')

def WifiJammer():
	if not os.path.isfile('tools/Wifi/wifijammer'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/DanMcInerney/wifijammer.git && cd wifijammer && python setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/Wifijammer".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd WifiJammer && python wifijammer')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd WifiJammer && python wifijammer')

def KawaiiDeauther():
	if not os.path.isfile('tools/Wifi/KawaiiDeauther'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Wifi && git clone https://github.com/aryanrtm/KawaiiDeauther.git && cd KawaiiDeauther && bash install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Wifi/KawaiiDeauther".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd KawaiiDeauther && bash KawaiiDeauther.sh')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Wifi && cd KawaiiDeauther && bash KawaiiDeauther.sh')

#Tools passwords 
def Cupp():
	if not os.path.isdir('tools/Passwords/cupp'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/Mebus/cupp.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/cupp".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd cupp && python3 cupp.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd cupp && python3 cupp.py')

def Facebooker():
	if not os.path.isdir('tools/Passwords/Facebooker'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/FakeFBI/Facebooker.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/Facebooker".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd Facebooker && perl facebooker.pl')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd Facebooker && perl facebooker.pl')	

def BluForceFB():
	if not os.path.isdir('tools/Passwords/BluForce-FB'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/AngelSecurityTeam/BluForce-FB.git && cd BluForce-FB && pip2 install mechanize')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/BluForce-FB".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd BluForce-FB && python2 bluforcefb.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd BluForce-FB && python2 bluforcefb.py')

def Brut3k1t():
	if not os.path.isdir('tools/Passwords/brut3k1t'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/ex0dus-0x/brut3k1t.git && cd brut3k1t && python setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/brut3k1t".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('brut3k1t -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('brut3k1t -h')

def SocialBox():
	if not os.path.isdir('tools/Passwords/SocialBox'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/TunisianEagles/SocialBox.git && cd SocialBox && chmod +x SocialBox.sh && chmod +x install-sb.sh && bash install-sb.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/SocialBox".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd SocialBox && bash SocialBox.sh')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd SocialBox && bash SocialBox.sh')

def JohnTheRipper():
	if not os.path.isdir('tools/Passwords/JohnTheRipper'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && mkdir JohnTheRipper && cd JohnTheRipper && wget http://www.openwall.com/john/j/john-1.8.0.tar.gz && tar -xzvf john-1.8.0.tar.gz && cd john-1.8.0/src/ && make clean generic')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/JohnTheRipper".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('john')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('john')

def Hashcat():
	if not os.path.isdir('tools/Passwords/hashcat'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/hashcat/hashcat.git && cd hashcat && make && make install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/hashcat".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('hashcat -h')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('hashcat -h')

def Brutedum():
	if not os.path.isdir('tools/Passwords/Brutedum'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt install python3 && cd tools && cd Passwords && git clone https://github.com/GitHackTools/BruteDum.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/Brutedum".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd Brutedum && python3 brutedum.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd Brutedum && python3 brutedum.py')		

def Facebash():
	if not os.path.isdir('tools/Passwords/facebash'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/thelinuxchoice/facebash && cd facebash && chmod +x * && bash install.sh && service tor start')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/facebash".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd facebash && bash facebash.sh')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd facebash && bash facebash.sh')	

def Brutespray():
	if not os.path.isdir('tools/Passwords/brutespray'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/x90skysn3k/brutespray.git && cd brutespray && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/brutespray".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd brutespray && python brutespray.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd brutespray && python brutespray.py')		

def Pupi():
	if not os.path.isdir('tools/Passwords/PUPI'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt install python3 && cd tools && cd Passwords && git clone https://github.com/mIcHyAmRaNe/PUPI.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/PUPI".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd PUPI && python3 pupi.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd PUPI && python3 pupi.py')		

def B4rbrute():
	if not os.path.isdir('tools/Passwords/b4r-brute'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/b4rc0d37/b4r-brute.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/b4r-brute".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd b4r-brute && python b4r-brute.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd b4r-brute && python b4r-brute.py')		

def FbHack():
	if not os.path.isdir('tools/Passwords/fb-hack'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Passwords && git clone https://github.com/mirzaaltaf/fb-hack.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Passwords/fb-hack".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd fb-hack && python fb.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Passwords && cd fb-hack && python fb.py')		

#Tools Web
def SQLmap():
	if not os.path.isdir('tools/Web/sqlmap-dev'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/sqlmap-dev".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd sqlmap-dev && python sqlmap.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd sqlmap-dev && python sqlmap.py -h')	

def XAttacker():
	if not os.path.isdir('tools/Web/XAttacker'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/Moham3dRiahi/XAttacker.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/XAttacker".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd XAttacker && perl XAttacker.pl')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd XAttacker && perl XAttacker.pl')

def Fuxploider():
	if not os.path.isdir('tools/Web/fuxploider'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt-get install python3-pip && cd tools && cd Web && git clone https://github.com/almandin/fuxploider.git && cd fuxploider && pip3 install -r requirements.txt')	
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/fuxploider".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd fuxploider && python3 fuxploider.py -h')			
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd fuxploider && python3 fuxploider.py -h')			

def Wordpresscan():
	if not os.path.isdir('tools/Web/Wordpresscan'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/swisskyrepo/Wordpresscan.git && cd Wordpresscan && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/Wordpresscan".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd Wordpresscan && python wordpresscan.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd Wordpresscan && python wordpresscan.py -h')

def SiteBroker():
	if not os.path.isdir('tools/Web/SiteBroker'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/Anon-Exploiter/SiteBroker.git && cd SiteBroker && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/SiteBroker".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd SiteBroker && python3 SiteBroker.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd SiteBroker && python3 SiteBroker.py')

def NoSQLMap():
	if not os.path.isdir('tools/Web/NoSQLMap'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/codingo/NoSQLMap.git && cd NoSQLMap && python setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/NoSQLMap".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd NoSQLMap && python nosqlmap.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd NoSQLMap && python nosqlmap.py')		

def SqliScanner():
	if not os.path.isdir('tools/Web/sqli-scanner'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/the-c0d3r/sqli-scanner.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/sqli-scanner".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd sqli-scanner && python sqli-scanner.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd sqli-scanner && python sqli-scanner.py -h')

def Joomscan():
	if not os.path.isdir('tools/Web/joomscan'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Web && git clone https://github.com/rezasp/joomscan.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/joomscan".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd joomscan && perl joomscan.pl')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd joomscan && perl joomscan.pl')	

def Metagoofil():
	if not os.path.isdir('tools/Web/metagoofil'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/laramies/metagoofil.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/metagoofil".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd metagoofil && python metagoofil.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd metagoofil && python metagoofil.py')

def Sublist3r():
	if not os.path.isdir('tools/Web/Sublist3r'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/aboul3la/Sublist3r.git && cd Sublist3r && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/Sublist3r".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd Sublist3r && python sublist3r.py -h')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd metagoofil && python metagoofil.py')

def WAFNinja():
	if not os.path.isdir('tools/Web/WAFNinja'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/khalilbijjou/WAFNinja.git && cd WAFNinja && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/WAFNinja".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd WAFNinja && python wafninja.py -h')			
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd WAFNinja && python wafninja.py -h')			

def Dirsearch():
	if not os.path.isdir('tools/Web/dirsearch'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt-get install python3.7 && cd tools && cd Web && git clone https://github.com/maurosoria/dirsearch.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/dirsearch".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd dirsearch && python3 dirsearch.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd dirsearch && python3 dirsearch.py -h')

def XSStrike():
	if not os.path.isdir('tools/Web/XSStrike'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/s0md3v/XSStrike.git && cd XSStrike && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/XSStrike".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd XSStrike && python xsstrike.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd XSStrike && python xsstrike.py')		

def LinksF1nd3r():
	if not os.path.isdir('tools/Web/LinksF1nd3r'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/ihebski/LinksF1nd3r.git && cd LinksF1nd3r && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/linksF1nd3r".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd LinksF1nd3r && python linksF1nd3r.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd LinksF1nd3r && python linksF1nd3r.py')		

def DTECH():
	if not os.path.isdir('tools/Web/D-Tech'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Web && git clone https://github.com/bibortone/D-Tech.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/D-Tech".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd D-Tech && python d-tect.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd D-Tech && python d-tect.py')		

def Phpsploit():
	if not os.path.isdir('tools/Web/phpsploit'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt install python3 python3-pip && cd tools && cd Web && git clone https://github.com/nil0x42/phpsploit.git && cd phpsploit && pip3 install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Web/phpsploit".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd phpsploit && python3 phpsploit --interactive --eval "help help"')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Web && cd phpsploit && python3 phpsploit --interactive --eval "help help"')		

#Tools Spoofing
def SpoofMAC():
	if not os.path.isdir('tools/Spoofing/SpoofMAC'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Spoofing && git clone git://github.com/feross/SpoofMAC.git && cd SpoofMAC && python setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Spoofing/SpoofMAC".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Spoofing && cd SpoofMAC && cd scripts && python spoof-mac.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Spoofing && cd SpoofMAC && cd scripts && python spoof-mac.py')		

def IpSpoofing():
	if not os.path.isdir('tools/Spoofing/ip_spoofing'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Spoofing && git clone https://github.com/pankajmore/ip_spoofing.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Spoofing/ip_spoofing".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Spoofing && cd ip_spoofing && python dos_attack.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Spoofing && cd ip_spoofing && python dos_attack.py')	

def Arpspoof():
	if not os.path.isdir('tools/Spoofing/arpspoof'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Spoofing && git clone https://github.com/ickerwx/arpspoof.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Spoofing/arpspoof".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Spoofing && cd arpspoof && python arpspoof.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Spoofing && cd arpspoof && python arpspoof.py -h')

def DerpNSpoof():
	if not os.path.isdir('tools/Spoofing/DerpNSpoof'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt install python3-pip && cd tools && cd Spoofing && git clone https://github.com/Trackbool/DerpNSpoof.git && cd DerpNSpoof && pip install -r requirements.txt')	
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Spoofing/DerpNSpoof".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Spoofing && cd DerpNSpoof && python3 DerpNSpoof.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Spoofing && cd DerpNSpoof && python3 DerpNSpoof.py')

def DrSpoof():
	if not os.path.isdir('tools/Spoofing/Dr.Spoof'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Spoofing && git clone https://github.com/Enixes/Dr.Spoof.git && cd Dr.Spoof && chmod +x DrSpoof.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Spoofing/Dr.Spoof".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Spoofing && cd Dr.Spoof && bash DrSpoof.sh -h')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Spoofing && cd Dr.Spoof && bash DrSpoof.sh -h')	

def GODKILLER():
	if not os.path.isdir('tools/Spoofing/GOD-KILLER'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Spoofing && git clone https://github.com/FDX100/GOD-KILLER.git && cd GOD-KILLER && python install.py')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Spoofing/GOD-KILLER".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('GOD-KILLER')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('GOD-KILLER')	

#Tools Information Gathering
def NMAP():
	if not os.path.isdir('tools/InformationGathering/nmap'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/nmap/nmap.git && cd nmap && bash configure && make && make install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/nmap".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('nmap')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('nmap')	

def Th3inspector():
	if not os.path.isdir('tools/InformationGathering/Th3inspector'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/Moham3dRiahi/Th3inspector.git && cd Th3inspector && chmod +x install.sh && bash install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/Th3inspector".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd Th3inspector && perl Th3inspector.pl -h')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd Th3inspector && perl Th3inspector.pl -h')	

def FBI():
	if not os.path.isdir('tools/InformationGathering/fbi'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/xHak9x/fbi.git && cd fbi && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/fbi".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd fbi && python2 fbi.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd fbi && python2 fbi.py')	

def Infoga():
	if not os.path.isdir('tools/InformationGathering/Infoga'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/m4ll0k/Infoga.git && cd Infoga && python setup.py install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/Infoga".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd Infoga && python infoga.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd Infoga && python infoga.py')	

def Crips():
	if not os.path.isdir('tools/InformationGathering/Crips'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/Manisso/Crips.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/Crips".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd Crips && python Crips.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd Crips && python Crips.py')

def BillCipher():
	if not os.path.isdir('tools/InformationGathering/billcipher'):	
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt update && apt install ruby python python-pip python3 python3-pip && apt install httrack whatweb && cd tools && cd InformationGathering && git clone https://github.com/GitHackTools/BillCipher.git && cd BillCipher && pip install -r requirements.txt && pip3 install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/BillCipher".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd BillCipher && python3 billcipher.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd BillCipher && python3 billcipher.py')

def RedHawk():
	if not os.path.isdir('tools/InformationGathering/RED_HAWK'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt-get install php7.2 && cd tools && cd InformationGathering && git clone https://github.com/Tuhinshubhra/RED_HAWK.git')	
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/RED_HAWK".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd RED_HAWK && php redh.php')				
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd RED_HAWK && php redh.php')				

def ReconNg():
	if not os.path.isdir('tools/InformationGathering/recon-ng'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt-get install python3.6 && cd tools && cd InformationGathering && git clone https://github.com/lanmaster53/recon-ng.git && cd recon-ng && pip install -r REQUIREMENTS')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/recon-ng".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd recon-ng && python3 recon-ng')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd recon-ng && python3 recon-ng')		

def theHarvester():
	if not os.path.isdir('tools/InformationGathering/theHarvester'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/alanchavez88/theHarvester.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/theHarvester".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd theHarvester && python theHarvester.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd theHarvester && python theHarvester.py')

def PhoneInfoga():
	if not os.path.isdir('tools/InformationGathering/PhoneInfoga'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt install python3-pip && cd tools && cd InformationGathering && git clone https://github.com/sundowndev/PhoneInfoga.git && cd PhoneInfoga && python3 -m pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/PhoneInfoga".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd PhoneInfoga && python3 phoneinfoga.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd PhoneInfoga && python3 phoneinfoga.py -h')

def Gasmask():
	if not os.path.isdir('tools/InformationGathering/gasmask'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/twelvesec/gasmask.git && cd gasmask && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/gasmask".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd gasmask && python gasmask.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd gasmask && python gasmask.py')		

def URLextractor():
	if not os.path.isdir('tools/InformationGathering/URLextractor'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/eschultze/URLextractor.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/URLextractor".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd URLextractor && bash extractor.sh')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd URLextractor && bash extractor.sh')	

def Devploit():
	if not os.path.isdir('tools/InformationGathering/Devploit'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/GhettoCole/Devploit.git && cd Devploit && chmod +x install && bash install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/Devploit".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('Devploit')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('Devploit')

def ReconDog():
	if not os.path.isdir('tools/InformationGathering/ReconDog'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/s0md3v/ReconDog.git && cd ReconDog && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/ReconDog".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd ReconDog && python dog')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd ReconDog && python dog')	

def Webkiller():
	if not os.path.isdir('tools/InformationGathering/webkiller'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/ultrasecurity/webkiller.git && cd webkiller && pip3 install -r requirments.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/webkiller".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd webkiller && python3 webkiller.py')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd webkiller && python3 webkiller.py')	

def Quasar():
	if not os.path.isdir('tools/InformationGathering/quasar'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/Cyb0r9/quasar.git && cd quasar && chmod +x * && bash install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/quasar".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd quasar && bash quasar.sh')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd quasar && bash quasar.sh')		

def InfoInstagramIphone():
	if not os.path.isdir('tools/InformationGathering/info-instagram-iphone'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt install python3 python3-pip && pip3 install quidam && cd tools && cd InformationGathering && git clone https://github.com/0xfff0800/info-instagram-iphone.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/info-instagram-iphone".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd info-instagram-iphone && python3 FaLaH-iphone.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd info-instagram-iphone && python3 FaLaH-iphone.py')		

def UserScan():
	if not os.path.isdir('tools/InformationGathering/userscan'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd InformationGathering && git clone https://github.com/JoeTech-Studio/UserScan.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/userscan".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd userscan && bash userscan.sh')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd userscan && bash userscan.sh')		

def XCTRHackingTools():
	if not os.path.isdir('tools/InformationGathering/XCTR-Hacking-Tools'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt install python3 python3-pip && cd tools && cd InformationGathering && git clone https://github.com/capture0x/XCTR-Hacking-Tools.git && cd XCTR-Hacking-Tools && pip3 install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/XCTR-Hacking-Tools".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd XCTR-Hacking-Tools && python3 xctr.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd InformationGathering && cd XCTR-Hacking-Tools && python3 xctr.py')		

def DeadTrap():
	if not os.path.isdir('tools/InformationGathering/DeadTrap'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt install python3-pip firefox-geckodriver && cd tools && cd InformationGathering && git clone https://github.com/Chr0m0s0m3s/DeadTrap.git && cd DeadTrap && pip3 install .')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/InformationGathering/DeadTrap".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('deadtrap')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('deadtrap')		

#Tools Others
def TheFatRat():
	if not os.path.isdir('tools/Others/TheFatRat'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/Screetsec/TheFatRat.git && cd TheFatRat && chmod +x setup.sh && bash setup.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/TheFatRat".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('fatrat')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('fatrat')

def Msfpc():
	if not os.path.isdir('tools/Others/msfpc'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/g0tmi1k/msfpc.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/msfpc".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd msfpc && bash msfpc.sh')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd msfpc && bash msfpc.sh')

def Fcrackzip():
	if not os.path.isfile('/usr/bin/fcrackzip'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt-get install fcrackzip')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en /usr/bin/fcrackzip".format(GREEN, DEFAULT))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('fcrackzip --help')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('fcrackzip --help')

def QRLjacker():
	if not os.path.isdir('tools/Others/QRLJacking'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt-get install python3.7 && cd tools && cd Others && git clone https://github.com/OWASP/QRLJacking.git && cd QRLJacking && cd QRLJacker && pip install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/QRLJacking".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd QRLJacking && cd QRLJacker && python3 QrlJacker.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd QRLJacking && cd QRLJacker && python3 QrlJacker.py')

def Lazy():
	if not os.path.isdir('tools/Others/lscript'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/arismelachroinos/lscript.git && cd lscript && chmod +x install.sh && bash install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/lscript ".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('l')	
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('l')

def HTBINVITE():
	if not os.path.isdir('tools/Others/HTB-INVITE'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/nycto-hackerone/HTB-INVITE.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/HTB-INVITE".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd HTB-INVITE && python HTB.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd HTB-INVITE && python HTB.py')

def Ngrok():
	if not os.path.isdir('tools/Others/Ngrok'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && mkdir Ngrok && cd Ngrok && wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip && unzip ngrok-stable-linux-amd64.zip && chmod +x *')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/Ngrok".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd Ngrok && ./ngrok')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd Ngrok && ./ngrok')

def Bluepot():
	if not os.path.isdir('tools/Others/Bluepot'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt-get install default-jdk && cd tools && cd Others && mkdir Bluepot && cd Bluepot && wget https://github.com/andrewmichaelsmith/bluepot/raw/master/bin/bluepot-0.1.tar.gz && tar xfz bluepot-0.1.tar.gz')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/Bluepot".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd Bluepot && java -jar bluepot/BluePot-0.1.jar')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd Bluepot && java -jar bluepot/BluePot-0.1.jar')

def Setoolkit():
	if not os.path.isdir('tools/Others/set'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/trustedsec/social-engineer-toolkit/ set/ && cd set && pip install -r requirements')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/set".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('setoolkit')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('setoolkit')

def A2sv():
	if not os.path.isdir('tools/Others/a2sv'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('pip install argparse && pip install netaddr && apt-get install openssl && cd tools && cd Others && git clone https://github.com/hahwul/a2sv.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/a2sv".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd a2sv && python a2sv.py -h')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd a2sv && python a2sv.py -h')

def Fornonimizer():
	if not os.path.isdir('tools/Others/4nonimizer'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/Hackplayers/4nonimizer.git && cd 4nonimizer && bash 4nonimizer install')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/4nonimizer".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('4nonimizer help')				
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('4nonimizer help')
	
def Easysploit():
	if not os.path.isdir('tools/Others/easysploit'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/KALILINUXTRICKSYT/easysploit.git && cd easysploit && bash installer.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/easysploit".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('easysploit')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('easysploit')		

def NXcrypt():
	if not os.path.isdir('tools/Others/NXcrypt'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/Hadi999/NXcrypt.git')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/NXcrypt".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd NXcrypt && python NXcrypt.py --help')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd NXcrypt && python NXcrypt.py --help')

def KnockMail():
	if not os.path.isdir('tools/Others/KnockMail'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/4w4k3/KnockMail.git && cd KnockMail && su && pip install -r requeriments.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/KnockMail".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd KnockMail && python knock.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd KnockMail && python knock.py')		

def RkHunter():
	if not os.path.isdir('tools/Others/rkhunter'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/installation/rkhunter.git && cd rkhunter && chmod +x install.sh && bash install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/rkhunter".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('rkhunter')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('rkhunter')

def HeraKeylogger():
	if not os.path.isdir('tools/Others/HeraKeylogger'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('apt-get install python3-pip -y && cd tools && cd Others && git clone https://github.com/UndeadSec/HeraKeylogger.git && cd HeraKeylogger && pip3 install -r requirements.txt')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/HeraKeylogger".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd HeraKeylogger && python3 hera.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd HeraKeylogger && python3 hera.py')		

def ZLogger():
	if not os.path.isdir('tools/Others/ZLogger'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/z00z/ZLogger.git && cd ZLogger && bash install.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/ZLogger".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd ZLogger && python zlogger.py')		
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd ZLogger && python zlogger.py')		

def Xerosploit():
	if not os.path.isdir('tools/Others/xerosploit'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/LionSec/xerosploit.git && cd xerosploit && python install.py')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/xerosploit".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('xerosploit')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('xerosploit')
	
def Slacksec():
	if not os.path.isdir('tools/Others/Slacksec'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/franc205/Slacksec.git && cp Slacksec/slacksec.py /usr/bin/slacksec && chmod +x /usr/bin/slacksec')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/Slacksec".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('slacksec')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('slacksec')

def Katana():
	if not os.path.isdir('tools/Others/KatanaFramework'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Others && git clone https://github.com/PowerScript/KatanaFramework && cd KatanaFramework && sh dependencies && python install')		
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/KatanaFramework".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd KatanaFramework && ktf.console')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd KatanaFramework && ktf.console')

def Z0172CKTools():	
	if not os.path.isdir('tools/Others/Z0172CK-Tools'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('apt install python3 python3-pip && cd tools && cd Others && git clone https://github.com/Erik172/Z0172CK-Tools.git && cd Z0172CK-Tools && bash install.sh && pip3 install -r requirements.txt')		
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/Z0172CK-Tools".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd Z0172CK-Tools && python3 index.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd Z0172CK-Tools && python3 index.py')

def CamHack():
	if not os.path.isdir('tools/Others/Cam-Hack'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Others && git clone https://github.com/Hack-The-World-With-Tech/Cam-Hack.git && cd Cam-Hack && chmod +x *')		
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/Cam-Hack".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd Cam-Hack && bash camhack.sh')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd Cam-Hack && bash camhack.sh')

def Onex():
	if not os.path.isdir('tools/Others/onex'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Others && git clone https://github.com/rajkumardusad/onex.git && cd onex && bash install')		
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/onex".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd onex && bash onex')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd onex && bash onex')

def Ransom0():
	if not os.path.isdir('tools/Others/Ransom0'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Others && git clone https://github.com/HugoLB0/Ransom0.git && cd Ransom0 && pip2 install requirementx.txt')		
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/Ransom0".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd Ransom0 && python ransom0.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd Ransom0 && python ransom0.py')

def Morpheus():
	if not os.path.isdir('tools/Others/morpheus'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Others && git clone https://github.com/r00t-3xp10it/morpheus.git')		
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/morpheus".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd morpheus && bash morpheus.sh')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd morpheus && bash morpheus.sh')

def FBTOOL():
	if not os.path.isdir('tools/Others/FBTOOL'):
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)	
		os.system('cd tools && cd Others && git clone https://github.com/mkdirlove/FBTOOL.git')		
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/FBTOOL".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd FBTOOL && python2 fbtool.py')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd FBTOOL && python2 fbtool.py')

def Venom():
	if not os.path.isdir('tools/Others/venom'):	
		print("\n{0}[*] Downloading tool...{1}".format(GREEN, DEFAULT))
		time.sleep(4)
		os.system('cd tools && cd Others && git clone https://github.com/r00t-3xp10it/venom.git && cd venom && chmod +x * && bash setup.sh')
		print("\n{0}[✔] Done.{1}\nHerramienta guardada en {2}/tools/Others/venom".format(GREEN, DEFAULT, location))
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()			
		else:
			os.system('cd tools && cd Others && cd venom && bash venom.sh')
	else:
		print("\n{}[X] Esta herramienta ya existe...".format(RED))
		time.sleep(2)
		if input("\n{0}[!] ¿Desea ejecutarla? (y/n)\n{1}KitHack >>{2} ".format(GREEN, RED, DEFAULT)).upper() != "Y":
			os.system('clear')
			main()
		else:
			os.system('cd tools && cd Others && cd venom && bash venom.sh')

