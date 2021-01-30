<p align="center">
<img src="https://github.com/AdrMXR/KitHack/blob/master/images/banner.png" title="KitHack">
</p>

<p align="center">
<a href="https://github.com/AdrMXR"><img title="Autor" src="https://img.shields.io/badge/Author-Adrián%20Guillermo-blue?style=for-the-badge&logo=github"></a>
<a href=""><img title="Version" src="https://img.shields.io/badge/Version-1.3.1-red?style=for-the-badge&logo="></a>
</p>

<p align="center">
<a href=""><img title="System" src="https://img.shields.io/badge/Supported%20OS-Linux-orange?style=for-the-badge&logo=linux"></a>
<a href=""><img title="Python" src="https://img.shields.io/badge/Python-3.7-yellow?style=for-the-badge&logo=python"></a>
<a href=""><img title="Lincencia" src="https://img.shields.io/badge/License-MIT-brightgreen?style=for-the-badge&logo="></a>
<a href="https://www.paypal.me/AdrMXR0"><img title="Paypal" src="https://img.shields.io/badge/Donate-PayPal-green.svg?style=for-the-badge&logo=paypal"></a>
</p>

<p align="center">
<a href="mailto:kithacking@gmail.com"><img title="Correo" src="https://img.shields.io/badge/Correo-kithacking%40gmail.com-blueviolet?style=for-the-badge&logo=gmail"></a>
<a href="https://github.com/AdrMXR/KitHack/tree/master/README.md"><img title="Spanish" src="https://img.shields.io/badge/Translate%20to-Spanish-inactive?style=for-the-badge&logo=google-translate"></a>
</p>

**Kithack** is a framework designed to automate the process of downloading and installing different tools for penetration testing, with a special option that allows generating cross-platform backdoors using Metasploit Framework.

## KitHack Compatible Distributions:

| Distribution |    State      |
|--------------|---------------| 
| Kali Linux   | Compatible    |
| Ubuntu       | Compatible    |
| Xbuntu       | Compatible    |
| Debian       | Compatible    |
| Raspbian     | Compatible    |
| Deepin       | Compatible    |
| Parrot OS    | Compatible    |
| Arch Linux   | Developing    |
| Termux       | Developing    |

## Installation: 

```bash
# Update your package list
$ sudo apt update

# Install python3 python3-pip
$ sudo apt install python3 python3-pip

# Clone the repository 
$ git clone https://github.com/AdrMXR/KitHack.git

# Enter the repository
$ cd KitHack

# Install KitHack
$ sudo bash install.sh

# Start KitHack
$ sudo python3 KitHack.py

# You can also run it from the shortcut
$ kithack

# When you want to update run
$ sudo bash update.sh

# To uninstall run
$ sudo bash uninstall.sh
```

## Dependencies:

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

## New features:

**1) Debugging of obsolete tools.**
- Due to the elimination of some repositories by their respective authors, it is essential that our users [report us](mailto:kithacking@gmail.com) any tool that is not being installed correctly, since in this way we can eliminate it from kithack.

**2) Integration of new tools.**
- As we debug tools we also integrate some new ones, if you have a personal project on github that you would like to appear in our toolkit, or if you are interested in being a kithack contributor, read our [contribution policy](https://github.com/AdrMXR/KitHack/blob/master/docs/translations/English/CONTRIBUTING.md).

**3) Unification of types of Payloads (by stages and without stages).**
- As we explained on our documentation website, kithack allows us to use both staged and individual payloads. If you want to know their differences, see [here.](https://adrmxr.github.io/KitHack#tipos-de-payloads)

**4) Incorporation of a new method that allows legitimate Android applications to be infected.**
- Kithack gives us the option of being able to infect an original APK and certify it so that it is less detectable. It should be noted that not all applications are vulnerable, applications such as Facebook, WhatsApp, Instagram and the like have sufficient security mechanisms to avoid this type of attack. We suggest you download the applications directly from [apkpure](https://apkpure.com) or similar to it.

**5) Tcp link generation through Ngrok for public connections (port 443 by default).**
- Now you can also work with [ngrok](https://ngrok.com) to perform attacks outside of your network without opening ports. The validation of your [authtoken](https://ngrok.com/docs#getting-started-authtoken) has also been automated, since in case of not having it configured, kithack automatically asks you to enter it to correctly generate the tcp link. The configuration file ```ngrok.yml``` will no longer be validated against home directorie (home path), it will now be stored in ```KitHack/.config``` by default. If for some reason you require kithack to request your authtoken again write ```rm .config/ngrok.yml```.

**6) Metasploit automation to listen for new sessions.**
- You don't have to waste time in re-setting your payload settings, kithack takes care of listening to [metasploit](https://www.metasploit.com) quickly.

**7) Planning of strategic points for antivirus evasion.**
- For us it is important that our backdoors are as undetectable as possible, that is why we ask you not to upload them to pages like [virustotal](https://www.virustotal.com) since these types of platforms store in their database the results of each analysis.

**8) Development of a new method that allows modifying the default name and icon of an APK generated by Metasploit.**
- Now you also have the possibility to customize your own payload for Android. With kithack you can change the default name of the apk generated by [metasploit](https://www.metasploit.com) known as "MainActivity" and you can also modify the default Android icon. Click [here](https://github.com/AdrMXR/KitHack/blob/master/icons/LEEME.txt) to know the format.

**9) Automated persistence application for any APK.**
- Forget that your [metasploit](https://www.metasploit.com) session expires very quickly, with kithack you can now generate your persistence file for any APK. If you want to know how to start it in the meterpreter shell, click [here.](https://youtu.be/nERwsZyIVeo)

## Some vulnerable APK:  

|        APK          |   Version    |
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

|    Main menu   |   Backdoor generator   |	
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

## Documentation:

|                   Titulo                     |             Link             |
|----------------------------------------------|------------------------------| 
| Control an android outside the local network | https://youtu.be/V1w1CMSdTyU |
| KitHack - an all-in-one tool                 | https://youtu.be/-8TCtiI9HWM |

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

If the tool fails, follow these steps:

1. Take a screenshot and see the error in detail
2. Contact me through the following email: kithacking@gmail.com
3. Submit the screenshot and explain your problem with that error.

## Contributors: 

- Ironpuerquito  
- C1b0rk 

## Licence:

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
