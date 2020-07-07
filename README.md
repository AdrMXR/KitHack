<p align="center">
<img src="https://github.com/AdrMXR/KitHack/blob/master/images/banner.png" title="KitHack">
</p>

<p align="center">
<a href="https://github.com/AdrMXR"><img title="Autor" src="https://img.shields.io/badge/Author-Adrián%20Guillermo-blue?style=for-the-badge&logo=github"></a>
<a href=""><img title="Version" src="https://img.shields.io/badge/Version-1.2.0-red?style=for-the-badge&logo="></a>
</p>

<p align="center">
<a href=""><img title="System" src="https://img.shields.io/badge/Supported%20OS-Linux-orange?style=for-the-badge&logo=linux"></a>
<a href=""><img title="Python" src="https://img.shields.io/badge/Python-2.7-yellow?style=for-the-badge&logo=python"></a>
<a href=""><img title="Lincencia" src="https://img.shields.io/badge/License-MIT-brightgreen?style=for-the-badge&logo="></a>
<a href="https://www.paypal.me/AdrMXR0"><img title="Paypal" src="https://img.shields.io/badge/Donate-PayPal-green.svg?style=for-the-badge&logo=paypal"></a>
</p>

<p align="center">
<a href="mailto:kithacking@gmail.com"><img title="Correo" src="https://img.shields.io/badge/Correo-kithacking%40gmail.com-blueviolet?style=for-the-badge&logo=gmail"></a>
<a href="https://t.me/AdrMXR"><img title="Chat" src="https://img.shields.io/badge/CHAT-TELEGRAM-blue?style=for-the-badge&logo=telegram"></a>
</p>

**Kithack** es un framework diseñado para automatizar el proceso de descarga e instalación de diferentes herramientas para pruebas de penetración, con una opción especial que permite generar puertas traseras mediante Metasploit Framework. 

## Distribuciones compatibles con KitHack:

| Distribución |   Estado      |
|--------------|---------------| 
| Kali Linux   | Compatible    |
| Ubuntu       | Compatible    |
| Xbuntu       | Compatible    |
| Debian       | Compatible    |
| Raspbian     | Compatible    |
| Deepin       | Compatible    |
| Parrot OS    | Compatible    |
| Arch Linux   | En desarrollo |
| Termux       | En desarrollo |

## Instalación:

```
sudo apt update
```

```
sudo apt install python2.7  
```

```
git clone https://github.com/AdrMXR/KitHack.git
```

```
cd KitHack
```

```
sudo bash install.sh 
```

```
sudo python KitHack.py
```

***Si acepta poder ejecutar KitHack desde cualquier lugar de su terminal, simplemente escriba:***
```
kithack
```
 
***Si desea actualizar en un futuro ejecute:***
```
sudo bash update.sh
```

## Dependencias

* sudo
* xterm
* postgresql
* Metasploit-Framework 
* apktool
* aapt
* jarsigner
* zipalign 
* pwgen
* pip2
* py-getch
* python-tk
* Cuenta autentificada de Ngrok 

## Nuevas funciones

Yo como desarrollador estoy comprometido con proporcionar a la comunidad entera del pentesting nuevas funciones que tengan una gran utilidad en sus actividades laborales, academicas o personales.
Es por ello que en esta nueva versión he incorporado algunas caracteriscas nuevas las cuales son las siguientes:

* Depuración de herramientas obsoletas en la antigua versión
* Integración de nuevas herramientas. 
* Refactorización del proceso de descarga de las herramientas.
* Unificación de los diferentes tipos de Payloads (por etapas y sin etapas).
* Incorporación de un nuevo metodo para la certificación de APKS maliciosas generadas con este proyecto.
* Utilización de la herramienta Ngrok para generar conexiones TCP (puerto 443 por default).
* Automatización de la configuración de Metasploit para ponerlo en escucha de nuevas sesiones.
* Planificación de puntos estrategicos para la evasión de antivirus.
* Elaboración de un nuevo metodo que permite modificar el nombre e icono de un payload generado por Metasploit.

## APKS que fueron probadas en el nuevo metodo de certificación 

|        APK          |   Versión    |
|---------------------|--------------| 
| FaceApp             | 1.00         |
| Pou                 | 1.4.79       |
| Google Now Launcher | 1.4.large    |
| Terminal Emulator   | 1.0.70       |
| Solitaire           | 3.6.0.3      |
| RAR                 | 5.60.build63 |
| WPSApp              | 1.6.7.3      |
| Phone Cleaner       | 1.0          |
| Ccleaner            | 1.19.74      |
| AVG Cleaner         | 2.0.2        |

## Método de modificación de nombre e icono

El unico requerimiento que se necesita para modificar el icono de un payload generado por Metasploit es una imagén en formato PNG con resolución de 48x48 pixeles. En la carpeta icons se encuentran algunas como ejemplo. 

## Screenshots 

| Menu principal | Generador de backdoors |	
| -------------- | ---------------------- |   
|![Index](https://github.com/AdrMXR/KitHack/blob/master/images/screenshot-1.png)|![f](https://github.com/AdrMXR/KitHack/blob/master/images/screenshot-2.png)

## Videos  

| Demo 1 | Demo 2 | 
| ------ | ------ | 
<a href="https://asciinema.org/a/LxJkuEWmJqWRwbUmj4nVm22Ye" target="_blank"><img src="https://asciinema.org/a/LxJkuEWmJqWRwbUmj4nVm22Ye.svg" /></a>|<a href="https://asciinema.org/a/ADXLN5f1MogAqSdMBohlNIdsa" target="_blank"><img src="https://asciinema.org/a/ADXLN5f1MogAqSdMBohlNIdsa.svg" /></a>
<p align="center">

## Tutorial

<a href="https://www.youtube.com/watch?v=Wsdn158PH50">
  <img src="https://github.com/AdrMXR/KitHack/blob/master/images/youtube.png" />
</a></p>

### Menu

- Android
- Windows 
- Phishing
- Wifi Attacks 
- Passwords Attacks 
- Web Attacks
- Spoofing
- Information Gathering 
- Others
- Backdoors with msfvenom

### Android:

- [Backdoor-apk](https://github.com/dana-at-cp/backdoor-apk)
- [Evil-Droid](https://github.com/M4sc3r4n0/Evil-Droid)
- [Spade](https://github.com/turksiberguvenlik/spade)
- [AhMyth](https://github.com/AhMyth/AhMyth-Android-RAT)
- [Andspoilt](https://github.com/sundaysec/Andspoilt)
- [kwetza](https://github.com/sensepost/kwetza)
- [Termux](https://termux.com)
- [DroidTracker](https://github.com/thelinuxchoice/DroidTracker)
- [Droidcam](https://github.com/thelinuxchoice/droidcam)
- [Crydroid](https://github.com/thelinuxchoice/crydroid)
- [Keydroid](https://github.com/thelinuxchoice/keydroid)
- [Android-Exploits](https://github.com/sundaysec/Android-Exploits)

### Windows:

- [Winpayloads](https://github.com/nccgroup/Winpayloads)
- [sAINT](https://github.com/tiagorlampert/sAINT)
- [BeeLogger](https://github.com/4w4k3/BeeLogger)
- [FakeImageExploiter](https://github.com/r00t-3xp10it/FakeImageExploiter)
- [Koadic](https://github.com/zerosum0x0/koadic)
- [Phantom-Evasion](https://github.com/oddcod3/Phantom-Evasion)
- [Ps1encode](https://github.com/CroweCybersecurity/ps1encode)
- [DKMC](https://github.com/Mr-Un1k0d3r/DKMC)
- [Cromos](https://github.com/6IX7ine/cromos)
- [Eternal_scanner](https://github.com/peterpt/eternal_scanner)
- [Eternalblue-Doublepulsar-Metasploit](https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit)
- [MS17-010-EternalBlue-WinXP-Win10](https://github.com/hanshaze/MS17-010-EternalBlue-WinXP-Win10)
- [Spykey](https://github.com/thelinuxchoice/spykey)
- [WindowsExploits](https://github.com/WindowsExploits/Exploits)

### Phishing:

- [HiddenEye](https://github.com/DarkSecDevelopers/HiddenEye)
- [PhishX](https://github.com/Userphish/PhishX)
- [SocialPhish](https://github.com/xHak9x/SocialPhish)
- [SocialFish](https://github.com/UndeadSec/SocialFish)
- [Phisher-man](https://github.com/FDX100/Phisher-man)
- [Shellphish](https://github.com/thelinuxchoice/shellphish)
- [Spectre](https://github.com/Pure-L0G1C/Spectre)
- [Blackeye](https://github.com/An0nUD4Y/blackeye)
- [PhEmail](https://github.com/Dionach/PhEmail)
- [Weeman](https://github.com/evait-security/weeman)
- [Zphisher](https://github.com/htr-tech/zphisher.git)
- [Lockphish](https://github.com/thelinuxchoice/lockphish.git)

### Wifi Attacks:

- [Fluxion](https://github.com/FluxionNetwork/fluxion)
- [Wifiphisher](https://github.com/wifiphisher/wifiphisher)
- [WiFiBroot](https://github.com/hash3liZer/WiFiBroot)
- [Wifite](https://github.com/derv82/wifite)
- [Ettercap](https://www.ettercap-project.org)
- [Linset](https://github.com/chunkingz/linsetmv1-2)
- [Wifi-Pumpkin](https://github.com/P0cL4bs/WiFi-Pumpkin)
- [Wifresti](https://github.com/LionSec/wifresti)
- [Evillimiter](https://github.com/bitbrute/evillimiter)
- [Netool-toolkit](https://github.com/r00t-3xp10it/netool-toolkit)
- [Dracnmap](https://github.com/Screetsec/Dracnmap)
- [Airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon)
- [Routersploit](https://www.github.com/threat9/routersploit)
- [Eaphammer](https://github.com/s0lst1c3/eaphammer)
- [VMR-MDK](https://github.com/chunkingz/VMR-MDK-K2-2017R-012x4)
- [FakeAP](https://github.com/thelinuxchoice/fakeap)
- [Wirespy](https://github.com/aress31/wirespy)
- [Wireshark](https://www.wireshark.org)
- [SniffAir](https://github.com/Tylous/SniffAir)
- [Wifijammer](https://github.com/DanMcInerney/wifijammer)

### Passwords Attacks:

- [Cupp](https://github.com/Mebus/cupp)
- [Facebooker](https://github.com/FakeFBI/Facebooker)
- [Instainsane](https://github.com/thelinuxchoice/instainsane)
- [BluForce-FB](https://github.com/AngelSecurityTeam/BluForce-FB)
- [Brut3k1t](https://github.com/ex0dus-0x/brut3k1t)
- [SocialBox](https://github.com/TunisianEagles/SocialBox)
- [Crunch](https://github.com/crunchsec/crunch)
- [JohnTheRipper](https://github.com/magnumripper/JohnTheRipper)
- [Hashcat](https://github.com/hashcat/hashcat)
- [BruteDum](https://github.com/GitHackTools/BruteDum.git)

### Web Attacks:

- [SQLmap](https://github.com/sqlmapproject/sqlmap)
- [XAttacker](https://github.com/Moham3dRiahi/XAttacker)
- [Fuxploider](https://github.com/almandin/fuxploider)
- [Wordpresscan](https://github.com/swisskyrepo/Wordpresscan)
- [SiteBroker](https://github.com/Anon-Exploiter/SiteBroker)
- [NoSQLMap](https://github.com/codingo/NoSQLMap)
- [Sqli-scanner](https://github.com/the-c0d3r/sqli-scanner)
- [Joomscan](https://github.com/rezasp/joomscan)
- [Metagoofil](https://github.com/laramies/metagoofil)
- [Sublist3r](https://github.com/aboul3la/Sublist3r)
- [WAFNinja](https://github.com/khalilbijjou/WAFNinja)
- [Dirsearch](https://github.com/maurosoria/dirsearch)
- [XSStrike](https://github.com/s0md3v/XSStrike)
- [LinksF1nd3r](https://github.com/ihebski/LinksF1nd3r)

### Spoofing:

- [SpoofMAC](https://github.com/feross/SpoofMAC)
- [Ip_spoofing](https://github.com/pankajmore/ip_spoofing)
- [ArpSpoof](https://github.com/ickerwx/arpspoof)
- [DerpNSpoof](https://github.com/Trackbool/DerpNSpoof)
- [Email-spoof](https://github.com/MatiasTilerias/email-spoof)
- [DrSpoof](https://github.com/Enixes/Dr.Spoof)
- [Smslistattack](https://github.com/Firestormhacker/smslistattack)

### Information Gathering:

- [Nmap](https://github.com/nmap/nmap) 
- [Th3inspector](https://github.com/Moham3dRiahi/Th3inspector)  
- [Facebook Information](https://github.com/xHak9x/fbi) 
- [Infoga](https://github.com/m4ll0k/Infoga) 
- [Crips](https://github.com/Manisso/Crips) 
- [BillCipher](https://github.com/GitHackTools/BillCipher) 
- [RED_HAWK](https://github.com/Tuhinshubhra/RED_HAWK) 
- [Recon-ng](https://github.com/lanmaster53/recon-ng) 
- [TheHarvester](https://github.com/alanchavez88/theHarvester) 
- [PhoneInfoga](https://github.com/sundowndev/PhoneInfoga) 
- [Gasmask](https://github.com/twelvesec/gasmask) 
- [Infog](https://github.com/thelinuxchoice/infog) 
- [Locator](https://github.com/thelinuxchoice/locator) 
- [Userrecon](https://github.com/thelinuxchoice/userrecon) 
- [Excuseme](https://github.com/thelinuxchoice/excuseme) 
- [URLextractor](https://github.com/eschultze/URLextractor) 
- [Devploit](https://github.com/GhettoCole/Devploit) 
- [ReconDog](https://github.com/s0md3v/ReconDog) 
- [Webkiller](https://github.com/ultrasecurity/webkiller) 
- [Quasar](https://github.com/Cyb0r9/quasar) 

### Others:

- [TheFatRat](https://github.com/Screetsec/TheFatRat)
- [Msfpc](https://github.com/g0tmi1k/msfpc)
- [Fcrackzip](https://github.com/hyc/fcrackzip)
- [QRLJacking](https://github.com/OWASP/QRLJacking)
- [Lazy](https://github.com/arismelachroinos/lscript)
- [Blue-Thunder-IP-Locator](https://github.com/the-shadowbrokers/Blue-Thunder-IP-Locator)
- [HTB-INVITE](https://github.com/nycto-hackerone/HTB-INVITE)
- [Ngrok](https://ngrok.com)
- [TheChoice](https://github.com/thelinuxchoice/thechoice)
- [Ransomware](http://www.mediafire.com/file/3g7xyzt1611z8zl/ransomware.rar/file)
- [Bluepot](https://github.com/andrewmichaelsmith/bluepot)
- [Social-engineer-toolkit](https://github.com/trustedsec/social-engineer-toolkit)
- [A2sv](https://github.com/hahwul/a2sv)
- [4nonimizer](https://github.com/Hackplayers/4nonimizer)
- [Saycheese](https://github.com/thelinuxchoice/saycheese)
- [Easysploit](https://github.com/KALILINUXTRICKSYT/easysploit)
- [NXcrypt](https://github.com/Hadi999/NXcrypt)
- [KnockMail](https://github.com/4w4k3/KnockMail)
- [Rkhunter](https://github.com/installation/rkhunter)
- [HeraKeylogger](https://github.com/UndeadSec/HeraKeylogger)
- [ZLogger](https://github.com/z00z/ZLogger)
- [Xerosploit](https://github.com/LionSec/xerosploit)
- [Slacksec](https://github.com/franc205/Slacksec)

### Backdoors with msfvenom:

| Sistema |    Formato    |
|---------|---------------|
| Linux   | Kithack.elf   |
| Windows | Kithack.exe   |
| Android | Kithack.apk   |
| Mac OS  | Kithack.macho |
| Php     | Kithack.php   |
| Python  | Kithack.py    |
| Bash    | Kithack.sh    |
| Perl    | Kithack.pl    |

## Bug? 

Si encuentra algun fallo en la herramienta siga los siguientes pasos:

1. Tomar un screenshot y que el fallo se aprecie detalladamente.
2. Contactarme mediante el siguiente correo: kithacking@gmail.com
3. Mandar el screenshot y explicar su problemática con ese fallo.

## Contribuidores 

- Ironpuerquito - Diseñador 
- C1b0rk - Tester y diseñador 

## Licencia 

MIT License

Copyright (c) 2019 Adrián Guillermo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.








