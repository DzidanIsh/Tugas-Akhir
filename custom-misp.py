#!/usr/bin/env python
# Integrasi Wazuh-MISP untuk deteksi IoC
# 
# Script ini terintegrasi dengan Wazuh untuk mendeteksi IoC pada web server Apache2
# dan mengirimkannya ke MISP untuk pengecekan apakah termasuk malicious atau tidak.
import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
import ipaddress
import hashlib
import re

# Direktori Wazuh
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
# Lokasi socket Wazuh
socket_addr = '{0}/queue/sockets/queue'.format(pwd)

# Fungsi untuk mengirim event ke Wazuh
def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:misp:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->misp:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

# Config parameter
# Membaca file alert dari argumen
alert_file = open(sys.argv[1])
# Membaca alert file
alert = json.loads(alert_file.read())
alert_file.close()

# Output alert baru jika MISP menemukan IoC atau error
alert_output = {}

# MISP Server Base URL - GANTI DENGAN URL MISP ANDA
misp_base_url = "https://misp.example.com/attributes/restSearch/"

# MISP Server API AUTH KEY - GANTI DENGAN API KEY MISP ANDA
misp_api_auth_key = "your_misp_api_key_here"

# Header HTTP untuk API MISP
misp_apicall_headers = {"Content-Type":"application/json", "Authorization":f"{misp_api_auth_key}", "Accept":"application/json"}

# Ekstrak sumber event dan tipe event dari rule groups
event_source = ""
event_type = ""

if len(alert["rule"]["groups"]) > 0:
    event_source = alert["rule"]["groups"][0]
    if len(alert["rule"]["groups"]) > 2:
        event_type = alert["rule"]["groups"][2]

# Pola regex untuk hash SHA256 (panjang 64 karakter)
regex_file_hash = re.compile('\w{64}')

# Pola regex untuk deteksi URL mencurigakan di log Apache
regex_suspicious_url = re.compile(r'(\/\.\.\/|\/\.\.\%2f|\/\.\.\%25|%00|\\x00|\.\./|\./|union\+select|exec\(|eval\(|' + 
                                 r'select.*from|information_schema|\/etc\/passwd|cmd\.exe|xp_cmdshell|bin\/bash|' + 
                                 r'shell_exec|\/bin\/sh|\/var\/www|\/tmp\/|%0a|%0d)')

# Cek event dari FIM (File Integrity Monitoring)
if event_source == 'ossec' and event_type == "syscheck":
    try:
        # Cek apakah ada file baru atau dimodifikasi
        if "syscheck" in alert and "sha256_after" in alert["syscheck"]:
            wazuh_event_param = alert["syscheck"]["sha256_after"]
            
            # Buat URL pencarian MISP
            misp_search_value = "value:" + wazuh_event_param
            misp_search_url = ''.join([misp_base_url, misp_search_value])
            
            # Cek khusus untuk file di direktori web Apache2
            if "syscheck" in alert and "path" in alert["syscheck"]:
                file_path = alert["syscheck"]["path"]
                
                # Cek apakah file berada di direktori web Apache2
                if "/var/www/" in file_path or "/etc/apache2/" in file_path:
                    # Log peristiwa spesifik Apache2
                    alert_output["source"] = "apache2_file_change"
                    alert_output["path"] = file_path
            
            # Panggil API MISP
            try:
                misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=True)
            except ConnectionError:
                alert_output["misp"] = {}
                alert_output["integration"] = "misp"
                alert_output["misp"]["error"] = 'Kesalahan koneksi ke API MISP'
                send_event(alert_output, alert["agent"])
                sys.exit(0)
            
            # Proses response MISP
            misp_api_response = misp_api_response.json()
            
            # Cek apakah response termasuk Attributes (IoCs)
            if misp_api_response["response"]["Attribute"]:
                # Generate alert output dari MISP response
                alert_output["misp"] = {}
                alert_output["integration"] = "misp"
                alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
                alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
                alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
                alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
                send_event(alert_output, alert["agent"])
        else:
            sys.exit(0)
    except (IndexError, KeyError):
        sys.exit(0)

# Cek log Apache
elif "apache" in event_source or "web" in event_source:
    try:
        # Ekstrak URL, IP, dan User Agent dari data log
        url = ""
        ip = ""
        user_agent = ""
        
        if "data" in alert and "srcip" in alert["data"]:
            ip = alert["data"]["srcip"]
            
        if "data" in alert and "url" in alert["data"]:
            url = alert["data"]["url"]
            
        if "data" in alert and "agent" in alert["data"]:
            user_agent = alert["data"]["agent"]
        
        # Cek IoC: IP
        if ip and ipaddress.ip_address(ip).is_global:
            # Buat URL pencarian MISP untuk IP
            misp_search_value = "value:" + ip
            misp_search_url = ''.join([misp_base_url, misp_search_value])
            
            # Panggil API MISP
            try:
                misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=True)
                
                # Proses response MISP
                misp_api_response = misp_api_response.json()
                
                # Cek apakah response termasuk Attributes (IoCs)
                if misp_api_response["response"]["Attribute"]:
                    # Generate alert output dari MISP response
                    alert_output["misp"] = {}
                    alert_output["integration"] = "misp"
                    alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
                    alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
                    alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
                    alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
                    alert_output["misp"]["source"] = "apache_access_log"
                    send_event(alert_output, alert["agent"])
            except ConnectionError:
                # Lanjutkan ke pemeriksaan URL jika ada kesalahan koneksi
                pass
        
        # Cek IoC: URL mencurigakan
        if url and regex_suspicious_url.search(url):
            # Ekstrak domain dari URL untuk pemeriksaan
            parsed_url = url.split('/')
            if len(parsed_url) > 2:
                domain = parsed_url[2]
                
                # Buat URL pencarian MISP untuk domain
                misp_search_value = "value:" + domain
                misp_search_url = ''.join([misp_base_url, misp_search_value])
                
                # Panggil API MISP
                try:
                    misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=True)
                    
                    # Proses response MISP
                    misp_api_response = misp_api_response.json()
                    
                    # Cek apakah response termasuk Attributes (IoCs)
                    if misp_api_response["response"]["Attribute"]:
                        # Generate alert output dari MISP response
                        alert_output["misp"] = {}
                        alert_output["integration"] = "misp"
                        alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
                        alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
                        alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
                        alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
                        alert_output["misp"]["source"] = "apache_suspicious_url"
                        send_event(alert_output, alert["agent"])
                except ConnectionError:
                    pass
                
    except (IndexError, KeyError, ValueError):
        sys.exit(0)

# Cek log koneksi Linux
elif event_source == 'linux' or (event_source == 'ossec' and ("netinfo" in event_type or "firewall" in event_type)):
    try:
        # Dapatkan IP tujuan
        dst_ip = None
        
        if "data" in alert and "dstip" in alert["data"]:
            dst_ip = alert["data"]["dstip"]
        
        # Cek apakah IP adalah publik dan valid
        if dst_ip and ipaddress.ip_address(dst_ip).is_global:
            # Buat URL pencarian MISP
            misp_search_value = "value:" + dst_ip
            misp_search_url = ''.join([misp_base_url, misp_search_value])
            
            # Panggil API MISP
            try:
                misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=True)
            except ConnectionError:
                alert_output["misp"] = {}
                alert_output["integration"] = "misp"
                alert_output["misp"]["error"] = 'Kesalahan koneksi ke API MISP'
                send_event(alert_output, alert["agent"])
                sys.exit(0)
            
            # Proses response MISP
            misp_api_response = misp_api_response.json()
            
            # Cek apakah response termasuk Attributes (IoCs)
            if misp_api_response["response"]["Attribute"]:
                # Generate alert output dari MISP response
                alert_output["misp"] = {}
                alert_output["integration"] = "misp"
                alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
                alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
                alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
                alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
                alert_output["misp"]["source"] = "linux_connection"
                send_event(alert_output, alert["agent"])
        else:
            sys.exit(0)
    except (IndexError, KeyError, ValueError):
        sys.exit(0)

# Jika tidak ada kondisi yang sesuai, keluar
sys.exit(0) 