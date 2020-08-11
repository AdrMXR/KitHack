<p align="center">
<img src="https://github.com/AdrMXR/KitHack/blob/master/images/banner.png" title="KitHack">
</p>

<p align="center">
<a href="https://github.com/AdrMXR"><img title="Autor" src="https://img.shields.io/badge/Author-Adrián%20Guillermo-blue?style=for-the-badge&logo=github"></a>
<a href=""><img title="Version" src="https://img.shields.io/badge/Version-1.3.0-red?style=for-the-badge&logo="></a>
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

**Kithack** es un framework diseñado para automatizar el proceso de descarga e instalación de diferentes herramientas para pruebas de penetración, con una opción especial que permite generar puertas traseras multiplataforma mediante Metasploit Framework. 

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

## Dependencias:

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
* pathlib
* python-zenity
* pgrep
* Cuenta autentificada de Ngrok 

## Novedades:

**1) Depuración de herramientas obsoletas.**
- Debido a la eliminación de algunos repositorios por parte de sus respectivos autores, es fundamental que nuestros usuarios nos [reporten](mailto:kithacking@gmail.com) cualquier herramienta que no se esté instalando de forma correcta, ya que de esa forma nosotros podremos depurarla completamente de kithack.

**2) Integración de nuevas herramientas.**
- Así como depuramos herramientas también integramos algunas nuevas, si tienes algún proyecto personal en github que te gustaría que apareciera en nuestro kit de herramientas, o si estás interesado en ser contribuidor de kithack, ayudanos a maximizar nuestro kit contestando esta [encuesta.](https://forms.gle/Kwrb3fbGni8z2kLi9) 

**3) Unificación de tipos de Payloads (por etapas y sin etapas).**
- Tal como lo explicamos en nuestra pagina web de documentación, kithack nos permite utilizar tanto payloads por etapas como individuales. Si deseas saber sus diferencias, consulta [aquí.](https://adrmxr.github.io/KitHack#tipos-de-payloads)

**4) Incorporación de un nuevo método que permite infectar aplicaciones Android legitimas.**
- Kithack nos proporciona la opción de poder infectar una APK original y certificarla para que sea menos detectable. Cabe destacar que no todas las aplicaciones son vulnerables, aplicaciones como Facebook, WhatsApp, Instagram y similares tienen los suficientes mecanismos de seguridad para evitar este tipo de infección de malware. Nosotros te sugerimos descargar las aplicaciones directamente de [apkpure](https://apkpure.com) o similares a esta.

**5) Generación de enlaces tcp mediante Ngrok para conexiones publicas (puerto 443 por default).**
- Ahora también puedes trabajar con [ngrok](https://ngrok.com) para realizar ataques fuera de tu red sin necesidad de abrir puertos. También se ha automatizado la validación de tu [authtoken](https://ngrok.com/docs#getting-started-authtoken), ya que en caso de no tenerlo configurado, kithack automaticamente te solicita ingresarlo para generar correctamente el enlace tcp. El archivo de configuración ```ngrok.yml``` ya no será validado en los directorios de inicio (home path), ahora se almacenará en ```KitHack/.config``` de manera predeterminada.

**6) Automatización de Metasploit para ponerlo en escucha de nuevas sesiones.**
- No tienes que perder tiempo en volver a setear las configuraciones de tu payload, kithack se encarga de poner en escucha a [metasploit](https://www.metasploit.com) de manera rapida.

**7) Planificación de puntos estrategicos para la evasión de antivirus.**
- Para nosotros es importante que nuestros backdoors sean lo menos detectables posibles, es por eso que te pedimos no subirlos a paginas como [virustotal](https://www.virustotal.com) ya que este tipo de plataformas almacenan en su base de datos los resultados de cada análisis.

**8) Elaboración de un nuevo método que permite modificar el nombre e icono predeterminados de una APK generada por Metasploit.**
- Ahora también tienes la posibilidad de personalizar tu propio payload para Android. Con kithack puedes cambiar el nombre predeterminado de la apk que genera [metasploit](https://www.metasploit.com) conocido como "MainActivity" y también puedes modificar el icono Android predeterminado. Da click [aquí](https://github.com/AdrMXR/KitHack/blob/master/icons/LEEME.txt) para conocer el formato.

**9) Aplicación de persistencia automatizada para cualquier APK.**
- Olvidate de que tu sesión de [metasploit](https://www.metasploit.com) expire muy rapido, con kithack ahora podrás generar tu archivo de persistencia para cualquier APK. Si deseas saber como ponerlo en marcha en la shell de meterpreter, da click [aquí.](https://youtu.be/VjRCnSBma9U)

## Algunas APK vulnerables:  

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

 ## Screenshots: 

| Menu principal | Generador de backdoors |	
| -------------- | ---------------------- |   
|![Index](https://github.com/AdrMXR/KitHack/blob/master/images/screenshot-1.png)|![f](https://github.com/AdrMXR/KitHack/blob/master/images/screenshot-2.png)

## Videos:  

| Demo 1 | Demo 2 | 
| ------ | ------ | 
<a href="https://asciinema.org/a/fiIoQatBqUh7z79DKTrQnG7bW" target="_blank"><img src="https://asciinema.org/a/fiIoQatBqUh7z79DKTrQnG7bW.svg" /></a>|<a href="https://asciinema.org/a/oV5lttCQpOmmgcgIaFIQEkcxY" target="_blank"><img src="https://asciinema.org/a/oV5lttCQpOmmgcgIaFIQEkcxY.svg" /></a>
<p align="center">

## Tutorial:

<p align="center">
<a href="https://www.youtube.com/watch?v=Wsdn158PH50">
  <img src="https://github.com/AdrMXR/KitHack/blob/master/images/youtube.png" />
</a></p>

## Documentación:

|                   Titulo                  |             Link             |
|-------------------------------------------|------------------------------| 
| Hackear WhatsApp en Kali Linux (CON ROOT) | https://youtu.be/Qck83WG0B5A |
| Hackear WhatsApp en Kali Linux (SIN ROOT) | https://youtu.be/19DyuX3a-qs |
| Controlar un Android fuera de la red local| https://youtu.be/V1w1CMSdTyU |
| KitHack - Una herramienta todo en uno     | https://youtu.be/-8TCtiI9HWM |

## Menu:

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

## Contribuidores: 

- Ironpuerquito - Diseñador 
- C1b0rk - Tester y diseñador 

## Licencia:

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








