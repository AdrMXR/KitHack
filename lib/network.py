#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Copyright 2020 KITHACK
#Written by: Adrian Guillermo
#Facebook: Adrian Guillero
#Github: https://www.github.com/AdrMXR

import socket
import urllib
import uuid
import os 
import re 
from os.path import expanduser

BLUE, RED, WHITE, CYAN, DEFAULT, YELLOW, MAGENTA, GREEN, END, BOLD = '\33[94m', '\033[91m', '\33[97m', '\033[36m', '\033[0m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m', '\033[1m'

def local():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
	print("\n{0}Local IP: {1}{2}".format(GREEN, DEFAULT, IP))
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

local()

def public_ip():
    lista = "0123456789."
    ip=""
    dato=urllib.urlopen("http://checkip.dyndns.org").read()
    for x in str(dato):
            if x in lista:
                    ip += x
    return ip 

print("\n{0}Public IP: {1}{2}").format(GREEN, DEFAULT, public_ip())

def ngrok():
    home = expanduser("~")
    if os.path.isfile('{}/.ngrok2/ngrok.yml'.format(home)):
        a = os.popen('pgrep ngrok').read()
        if not a:
            os.system('./ngrok tcp 443 > /dev/null 2>&1 &')
            while True:
                os.system('curl -s -N http://127.0.0.1:4040/status | grep "tcp://0.tcp.ngrok.io:[0-9]*" -oh > ngrok.tcp')
                TcpFile = open('ngrok.tcp', 'r')
                tcp = TcpFile.read()
                TcpFile.close()
                if re.match("tcp://0.tcp.ngrok.io:[0-9]*", tcp) != None:
                    print("\n{0}Ngrok TCP: {1}{2}".format(GREEN, DEFAULT, tcp))
                    break

        else:
            os.system('kill -9 $(pgrep ngrok)')
            ngrok()
    else:
        print("\n{0}Ngrok TCP:{1} None\n".format(GREEN, DEFAULT))

ngrok()



