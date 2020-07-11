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

<p align="center">
<a href="https://www.youtube.com/watch?v=Wsdn158PH50">
  <img src="https://github.com/AdrMXR/KitHack/blob/master/images/youtube.png" />
</a></p>

## Documentación
- [Hackear WhatsApp en Kali Linux](https://www.youtube.com/watch?v=Qck83WG0B5A&t=3s)
- [Como tener el control de un Android fuera de la red local](https://www.youtube.com/watch?v=V1w1CMSdTyU&t=308s)
- [KITHACK - Una herramienta todo en uno](https://www.youtube.com/watch?v=-8TCtiI9HWM&t=186s)

## Menu

- [Android](https://github.com/AdrMXR/KitHack/blob/master/TOOLS.md#android)
- [Windows](https://github.com/AdrMXR/KitHack/blob/master/TOOLS.md#windows) 
- [Phishing](https://github.com/AdrMXR/KitHack/blob/master/TOOLS.md#phishing)
- [Wifi Attacks](https://github.com/AdrMXR/KitHack/blob/master/TOOLS.md#wifi-attacks)
- [Passwords Attacks](https://github.com/AdrMXR/KitHack/blob/master/TOOLS.md#passwords-attacks)
- [Web Attacks](https://github.com/AdrMXR/KitHack/blob/master/TOOLS.md#web-attacks)
- [Spoofing](https://github.com/AdrMXR/KitHack/blob/master/TOOLS.md#spoofing)
- [Information Gathering](https://github.com/AdrMXR/KitHack/blob/master/TOOLS.md#information-gathering)
- [Others](https://github.com/AdrMXR/KitHack/blob/master/TOOLS.md#others)
- [Backdoors with msfvenom](https://github.com/AdrMXR/KitHack/blob/master/TOOLS.md#backdoors-with-msfvenom)

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








