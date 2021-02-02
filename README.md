<p align="center">
<img src="https://github.com/AdrMXR/KitHack/blob/master/images/banner.png" title="KitHack">
</p>

<p align="center">
<a href="https://github.com/AdrMXR"><img title="Autor" src="https://img.shields.io/badge/Author-Adrián%20Guillermo-blue?style=for-the-badge&logo=github"></a>
<a href=""><img title="Version" src="https://img.shields.io/badge/Version-1.3.2-red?style=for-the-badge&logo="></a>
</p>

<p align="center">
<a href=""><img title="System" src="https://img.shields.io/badge/Supported%20OS-Linux-orange?style=for-the-badge&logo=linux"></a>
<a href=""><img title="Python" src="https://img.shields.io/badge/Python-3.7-yellow?style=for-the-badge&logo=python"></a>
<a href=""><img title="Lincencia" src="https://img.shields.io/badge/License-MIT-brightgreen?style=for-the-badge&logo="></a>
<a href="https://www.paypal.me/AdrMXR0"><img title="Paypal" src="https://img.shields.io/badge/Donate-PayPal-green.svg?style=for-the-badge&logo=paypal"></a>
</p>

<p align="center">
<a href="mailto:kithacking@gmail.com"><img title="Correo" src="https://img.shields.io/badge/Correo-kithacking%40gmail.com-blueviolet?style=for-the-badge&logo=gmail"></a>
<a href="https://github.com/AdrMXR/KitHack/tree/master/docs/translations/English/README.md"><img title="English" src="https://img.shields.io/badge/Translate%20to-English-inactive?style=for-the-badge&logo=google-translate"></a>
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

```bash
# Actualice su lista de paquetes
$ sudo apt update

# Instale python3 python3-pip
$ sudo apt install python3 python3-pip

# Clone el repositorio 
$ git clone https://github.com/AdrMXR/KitHack.git

# Entre al repositorio
$ cd KitHack

# Instale KitHack
$ sudo bash install.sh

# Inicie KitHack
$ sudo python3 KitHack.py

# También puede ejecutarla desde el atajo
$ kithack

# Cuando desee actualizar ejecute
$ sudo bash update.sh

# Para desinstalar ejecute
$ sudo bash uninstall.sh
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
* requests
* pwgen
* py-getch
* python-tk
* pathlib
* python-zenity
* pgrep
* Ngrok authtoken 

## Novedades:

**1) Depuración de herramientas obsoletas.**
- Es fundamental que nuestros usuarios nos [reporten](mailto:kithacking@gmail.com) cualquier herramienta que no se esté instalando de forma correcta, ya que de esa forma nosotros podremos depurarla completamente de kithack.

**2) Integración de nuevas herramientas.**
- Así como depuramos herramientas también integramos algunas nuevas, si tienes algún proyecto personal en github que te gustaría que apareciera en nuestro kit de herramientas, o si estás interesado en ser contribuidor de kithack, lee nuestra [norma de contribución](https://github.com/AdrMXR/KitHack/blob/master/docs/CONTRIBUTING.md).

**3) Unificación de tipos de Payloads (por etapas y sin etapas).**
- Kithack nos permite utilizar tanto payloads por etapas como individuales. Si deseas saber sus diferencias, consulta [aquí.](https://adrmxr.github.io/KitHack#tipos-de-payloads)

**4) Incorporación de un nuevo método que permite infectar aplicaciones Android legitimas.**
- Kithack nos proporciona la opción de poder infectar una APK original. Cabe destacar que no todas las aplicaciones son vulnerables.

**5) Generación de conexiones TCP con ngrok.**
- Ahora también puedes trabajar con [ngrok](https://ngrok.com) para realizar ataques fuera de tu red sin necesidad de abrir puertos. El archivo de configuración ```ngrok.yml``` se almacena en ```KitHack/.config``` de manera predeterminada. Si por alguna razon necesita que kithack le solicite nuevamente su authtoken escriba ```rm .config/ngrok.yml```.

**6) Automatización de Metasploit.**
- No tienes que perder tiempo en volver a establecer las configuraciones de tu payload, kithack se encarga de poner en escucha a [metasploit](https://www.metasploit.com) de manera rapida.

**7) Personalización de payloads para android.**
- Ahora también tienes la posibilidad de personalizar tu propio payload para Android. Con kithack puedes cambiar el nombre predeterminado de la apk que genera [metasploit](https://www.metasploit.com) conocido como "MainActivity" y también puedes modificar el icono de Android predeterminado. Da click [aquí](https://github.com/AdrMXR/KitHack/blob/master/icons/LEEME.txt) para conocer el formato.

**8) Aplicación de persistencia automatizada para cualquier APK.**
- Olvidate de que tu sesión de [metasploit](https://www.metasploit.com) expire muy rapido, con kithack ahora podrás generar tu archivo de persistencia para cualquier APK. Si deseas saber como ponerlo en marcha en la shell de meterpreter, da click [aquí.](https://youtu.be/nERwsZyIVeo)

**9) Ejecución de herramientas.**
- Ahora el usuario podrá ejecutar las herramientas directamente desde kithack a pesar de que ya se encuentren instaladas.

**10) Creación de ```clean.sh```.**
- Si necesitas eliminar el contenido que te ha generado kithack en tus carpetas `tools` y `output`, puedes ejecutar el archivo `clean.sh` para hacerlo de forma rápida. 

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
<a href="https://asciinema.org/a/OTymOt3NNSTfFERrw2bHvuFw7" target="_blank"><img src="https://asciinema.org/a/OTymOt3NNSTfFERrw2bHvuFw7.svg" /></a>|<a href="https://asciinema.org/a/oV5lttCQpOmmgcgIaFIQEkcxY" target="_blank"><img src="https://asciinema.org/a/oV5lttCQpOmmgcgIaFIQEkcxY.svg" /></a>
<p align="center">

## Menu:

- [Android](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#android)
- [Windows](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#windows) 
- [Phishing](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#phishing)
- [Wifi Attacks](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#wifi-attacks)
- [Passwords Attacks](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#passwords-attacks)
- [Web Attacks](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#web-attacks)
- [Spoofing](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#spoofing)
- [Information Gathering](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#information-gathering)
- [Others](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#others)
- [Backdoors with msfvenom](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#backdoors-with-msfvenom)

## Bug? 

Si encuentra algun fallo en la herramienta siga los siguientes pasos:

1. Tomar un screenshot y que el fallo se aprecie detalladamente.
2. Contactarme mediante el siguiente correo: kithacking@gmail.com
3. Mandar el screenshot y explicar su problemática con ese fallo.

## Contribuidores: 

- Ironpuerquito 
- C1b0rk 

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








