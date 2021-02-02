#!/usr/bin/python3
# -*- coding: utf-8 -*-
#Copyright 2021 KITHACK
#Written by: Adrian Guillermo
#Facebook: Adrian Guillero
#Github: https://www.github.com/AdrMXR

import socket
from urllib.request import urlopen
import re
import signal
from os import system as run_command, kill as kill_process, popen as sys_url
from pathlib import Path as pathlib_Path
from zenipy.zenipy import entry as entry_token, error as Error
from pgrep import pgrep as check_process

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

def public_ip():
    lista = "0123456789."
    ip=""
    dato=urlopen("http://checkip.dyndns.org").read()
    for x in str(dato):
            if x in lista:
                    ip += x
    print("\n{0}Public IP: {1}{2}".format(GREEN, DEFAULT, ip))              
    return ip 

def run_ngrok():
    ngrok_config = pathlib_Path(".config/ngrok.yml")
    if ngrok_config.exists():
        pid = check_process("ngrok")
        for p in pid:
            kill_process(p, signal.SIGKILL)
        # Continue
        run_command('./ngrok tcp -config=.config/ngrok.yml 443 > /dev/null 2>&1 &')
        while True:
            tcp = sys_url('curl -s -N http://127.0.0.1:4040/status | grep -o "tcp://[0-9]*.tcp.ngrok.io:[0-9]*"').read()
            if re.match("tcp://[0-9]*.tcp.ngrok.io:[0-9]*", tcp) != None:
                print("\n{0}Ngrok TCP: {1}{2}".format(GREEN, DEFAULT, tcp))
                break
    else:
        while True:
            try:
                token = entry_token(title="SET NGROK AUTHTOKEN", text="Register at https://ngrok.com\n", width=450, height=140)        
                if len(token) in range(40, 50):
                    ngrok_config.touch(mode=0o777, exist_ok=True)
                    ngrok_config = open('.config/ngrok.yml','w')
                    ngrok_config.write("authtoken: " + token)
                    ngrok_config.close()        
                    run_ngrok() 
                    break
                else:
                    Error(text="Invalid token, please try again")
                    continue
            except TypeError: #Evitar cierre de kithack 
                break

def run_network():
    local()
    public_ip()
    run_ngrok()
