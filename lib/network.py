#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Copyright 2019 KITHACK
#Written by: Adrian Guillermo
#Facebook: Adrian Guillero
#Github: https://www.github.com/AdrMXR

import socket
import urllib
import uuid

print("\033[1;32m")

def local():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
	print("Local IP: {}".format(IP))
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

print("\nPublic IP: {}").format(public_ip())

def Mac():
    print "\nMac Adress:", 
    print (':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) 
    for ele in range(0,8*6,8)][::-1])) 

Mac()