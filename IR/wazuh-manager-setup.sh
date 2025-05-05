#!/bin/bash
# Script instalasi dan konfigurasi Wazuh Manager untuk integrasi dengan MISP
# Dioptimalkan untuk monitoring server Apache2
# Jalankan sebagai root/sudo

set -e

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Fungsi log
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cek user root
if [ "$EUID" -ne 0 ]; then
    log_error "Script ini memerlukan akses root. Silakan jalankan dengan sudo."
    exit 1
fi

# Cek apakah server menggunakan Ubuntu
if [ ! -f /etc/lsb-release ] || ! grep -q "Ubuntu" /etc/lsb-release; then
    log_error "Script ini hanya berjalan pada sistem Ubuntu."
    exit 1
fi

# Parameter untuk konfigurasi
MISP_URL=""
MISP_API_KEY=""

# Minta URL MISP
while [ -z "$MISP_URL" ]; do
    read -p "Masukkan URL MISP (contoh: https://misp.example.com): " MISP_URL
    if [ -z "$MISP_URL" ]; then
        log_error "URL MISP wajib diisi."
    fi
done

# Minta API Key MISP
while [ -z "$MISP_API_KEY" ]; do
    read -p "Masukkan API Key MISP: " MISP_API_KEY
    if [ -z "$MISP_API_KEY" ]; then
        log_error "API Key MISP wajib diisi."
    fi
done

# Cek komponen yang sudah terinstal
WAZUH_MANAGER_INSTALLED=false
WAZUH_INDEXER_INSTALLED=false
WAZUH_DASHBOARD_INSTALLED=false
PYTHON_PIP_INSTALLED=false
JQ_INSTALLED=false
CURL_INSTALLED=false
REQUESTS_INSTALLED=false

# Cek status instalasi komponen
if dpkg -l | grep -q wazuh-manager; then
    WAZUH_MANAGER_INSTALLED=true
    log "Wazuh Manager sudah terinstal. Melewati langkah instalasi."
fi

if dpkg -l | grep -q wazuh-indexer; then
    WAZUH_INDEXER_INSTALLED=true
    log "Wazuh Indexer sudah terinstal. Melewati langkah instalasi."
fi

if dpkg -l | grep -q wazuh-dashboard; then
    WAZUH_DASHBOARD_INSTALLED=true
    log "Wazuh Dashboard sudah terinstal. Melewati langkah instalasi."
fi

if dpkg -l | grep -q python3-pip; then
    PYTHON_PIP_INSTALLED=true
    log "Python PIP sudah terinstal. Melewati langkah instalasi."
fi

if command -v jq &> /dev/null; then
    JQ_INSTALLED=true
    log "JQ sudah terinstal. Melewati langkah instalasi."
fi

if command -v curl &> /dev/null; then
    CURL_INSTALLED=true
    log "Curl sudah terinstal. Melewati langkah instalasi."
fi

if python3 -c "import requests" &> /dev/null; then
    REQUESTS_INSTALLED=true
    log "Python Requests sudah terinstal. Melewati langkah instalasi."
fi

# Tambah GPG key dan repository Wazuh jika diperlukan
if [ "$WAZUH_MANAGER_INSTALLED" = false ] || [ "$WAZUH_INDEXER_INSTALLED" = false ] || [ "$WAZUH_DASHBOARD_INSTALLED" = false ]; then
    log "Menambahkan repository Wazuh..."
    if [ ! -f /usr/share/keyrings/wazuh.gpg ]; then
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
        chmod 644 /usr/share/keyrings/wazuh.gpg
    fi
    
    if [ ! -f /etc/apt/sources.list.d/wazuh.list ]; then
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
    fi
    
    # Update package list
    log "Memperbarui daftar paket..."
    apt-get update
fi

# Instal paket yang belum terinstal
PACKAGES_TO_INSTALL=""

if [ "$WAZUH_MANAGER_INSTALLED" = false ]; then
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL wazuh-manager"
fi

if [ "$WAZUH_INDEXER_INSTALLED" = false ]; then
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL wazuh-indexer"
fi

if [ "$WAZUH_DASHBOARD_INSTALLED" = false ]; then
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL wazuh-dashboard"
fi

if [ "$PYTHON_PIP_INSTALLED" = false ]; then
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL python3-pip"
fi

if [ "$JQ_INSTALLED" = false ]; then
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL jq"
fi

if [ "$CURL_INSTALLED" = false ]; then
    PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL curl"
fi

if [ ! -z "$PACKAGES_TO_INSTALL" ]; then
    log "Menginstal paket yang diperlukan: $PACKAGES_TO_INSTALL"
    apt-get install -y $PACKAGES_TO_INSTALL
    log "Paket yang diperlukan berhasil diinstal."
else
    log "Semua paket sistem yang diperlukan sudah terinstal."
fi

# Instal dependensi Python jika belum ada
if [ "$REQUESTS_INSTALLED" = false ]; then
    log "Menginstal modul Python yang diperlukan..."
    pip3 install requests
    log "Modul Python berhasil diinstal."
else
    log "Modul Python yang diperlukan sudah terinstal."
fi

# Membuat direktori untuk integrasi dan rules kustom
log "Membuat direktori untuk file integrasi dan rules..."
mkdir -p /var/ossec/integrations
mkdir -p /var/ossec/etc/rules

# Membuat script integrator custom-misp.py
log "Membuat script integrasi custom-misp.py..."
cat > /var/ossec/integrations/custom-misp.py << 'EOF'
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
misp_base_url = "MISP_URL_PLACEHOLDER/attributes/restSearch/"

# MISP Server API AUTH KEY - GANTI DENGAN API KEY MISP ANDA
misp_api_auth_key = "MISP_API_KEY_PLACEHOLDER"

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
EOF

# Ganti placeholder dengan nilai sebenarnya
sed -i "s|MISP_URL_PLACEHOLDER|$MISP_URL|g" /var/ossec/integrations/custom-misp.py
sed -i "s|MISP_API_KEY_PLACEHOLDER|$MISP_API_KEY|g" /var/ossec/integrations/custom-misp.py

# Membuat wrapper script custom-misp
log "Membuat wrapper script custom-misp..."
cat > /var/ossec/integrations/custom-misp << 'EOF'
#!/bin/sh
WPYTHON_BIN="framework/python/bin/python3"

SCRIPT_PATH_NAME="$0"

DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"

case ${DIR_NAME} in
    */active-response/bin | */wodles*)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"
        fi

        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
    */bin)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

        PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/${SCRIPT_NAME}.py"
    ;;
     */integrations)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
esac

${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} "$@"
EOF

# Set permissions
chmod 750 /var/ossec/integrations/custom-misp
chmod 750 /var/ossec/integrations/custom-misp.py
chown root:wazuh /var/ossec/integrations/custom-misp
chown root:wazuh /var/ossec/integrations/custom-misp.py

# Membuat file rules MISP
log "Membuat file rules MISP..."
cat > /var/ossec/etc/rules/misp_rules.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<group name="misp,">
  <!-- Aturan dasar untuk event MISP -->
  <rule id="100620" level="10">
    <field name="integration">misp</field>
    <match>misp</match>
    <description>Event MISP Terdeteksi</description>
    <options>no_full_log</options>
  </rule>

  <!-- Aturan untuk error koneksi ke API MISP -->
  <rule id="100621" level="5">
    <if_sid>100620</if_sid>
    <field name="misp.error">\.+</field>
    <description>MISP - Error koneksi ke API</description>
    <options>no_full_log</options>
    <group>misp_error,</group>
  </rule>

  <!-- Aturan untuk menemukan IoC di MISP -->
  <rule id="100622" level="12">
    <field name="misp.category">\.+</field>
    <description>MISP - IoC ditemukan di Threat Intel - Kategori: $(misp.category), Atribut: $(misp.value)</description>
    <options>no_full_log</options>
    <group>misp_alert,</group>
    <mitre>
      <id>T1083</id> <!-- File and Directory Discovery -->
      <id>T1204</id> <!-- User Execution -->
      <id>T1027</id> <!-- Obfuscated Files or Information -->
      <id>T1059</id> <!-- Command and Scripting Interpreter -->
    </mitre>
  </rule>

  <!-- Aturan khusus untuk IP address berbahaya -->
  <rule id="100623" level="14">
    <if_sid>100622</if_sid>
    <field name="misp.type">ip-dst</field>
    <description>MISP - Terdeteksi koneksi ke IP berbahaya: $(misp.value)</description>
    <options>no_full_log</options>
    <group>misp_alert,connection_to_malicious_ip,</group>
    <mitre>
      <id>T1071</id> <!-- Application Layer Protocol -->
      <id>T1102</id> <!-- Web Service -->
      <id>T1571</id> <!-- Non-Standard Port -->
    </mitre>
  </rule>

  <!-- Aturan khusus untuk domain berbahaya -->
  <rule id="100624" level="14">
    <if_sid>100622</if_sid>
    <field name="misp.type">hostname|domain</field>
    <description>MISP - Terdeteksi DNS query ke domain berbahaya: $(misp.value)</description>
    <options>no_full_log</options>
    <group>misp_alert,connection_to_malicious_domain,</group>
    <mitre>
      <id>T1071.004</id> <!-- Application Layer Protocol: DNS -->
      <id>T1568</id> <!-- Dynamic Resolution -->
    </mitre>
  </rule>

  <!-- Aturan khusus untuk file berbahaya (berdasarkan hash) -->
  <rule id="100625" level="15">
    <if_sid>100622</if_sid>
    <field name="misp.type">sha256|md5|sha1</field>
    <description>MISP - Terdeteksi file berbahaya: $(misp.value)</description>
    <options>no_full_log</options>
    <group>misp_alert,malicious_file,</group>
    <mitre>
      <id>T1204.002</id> <!-- User Execution: Malicious File -->
      <id>T1027</id> <!-- Obfuscated Files or Information -->
    </mitre>
  </rule>

  <!-- Aturan khusus untuk file berbahaya yang dideteksi oleh FIM -->
  <rule id="100626" level="15">
    <if_sid>100625</if_sid>
    <field name="data.syscheck.path">\.+</field>
    <description>MISP - FIM mendeteksi file berbahaya di $(data.syscheck.path)</description>
    <options>no_full_log</options>
    <group>misp_alert,malicious_file,fim_alert,</group>
    <mitre>
      <id>T1204.002</id> <!-- User Execution: Malicious File -->
      <id>T1564</id> <!-- Hide Artifacts -->
    </mitre>
  </rule>

  <!-- Aturan khusus untuk file berbahaya di direktori web server -->
  <rule id="100627" level="15">
    <if_sid>100625</if_sid>
    <field name="data.syscheck.path">/var/www/|/etc/apache2/</field>
    <description>MISP - FIM mendeteksi file berbahaya di direktori web server: $(data.syscheck.path)</description>
    <options>no_full_log</options>
    <group>misp_alert,malicious_file,fim_alert,apache,</group>
    <mitre>
      <id>T1190</id> <!-- Exploit Public-Facing Application -->
      <id>T1505.003</id> <!-- Server Software Component: Web Shell -->
    </mitre>
  </rule>

  <!-- Aturan khusus untuk serangan web terdeteksi di log Apache -->
  <rule id="100628" level="14">
    <if_sid>100622</if_sid>
    <field name="misp.source">apache_access_log</field>
    <description>MISP - Terdeteksi akses berbahaya ke server web dari IP: $(misp.value)</description>
    <options>no_full_log</options>
    <group>misp_alert,web_attack,apache,</group>
    <mitre>
      <id>T1190</id> <!-- Exploit Public-Facing Application -->
      <id>T1133</id> <!-- External Remote Services -->
    </mitre>
  </rule>

  <!-- Aturan khusus untuk URLs mencurigakan di log Apache -->
  <rule id="100629" level="14">
    <if_sid>100622</if_sid>
    <field name="misp.source">apache_suspicious_url</field>
    <description>MISP - Terdeteksi URL mencurigakan pada server web: $(misp.value)</description>
    <options>no_full_log</options>
    <group>misp_alert,web_attack,url_injection,apache,</group>
    <mitre>
      <id>T1190</id> <!-- Exploit Public-Facing Application -->
      <id>T1059.007</id> <!-- Command and Scripting Interpreter: JavaScript -->
    </mitre>
  </rule>

  <!-- Aturan khusus untuk perubahan di direktori Apache2 -->
  <rule id="100630" level="12">
    <if_sid>100620</if_sid>
    <field name="source">apache2_file_change</field>
    <description>MISP - Perubahan terdeteksi pada file di server web: $(path)</description>
    <options>no_full_log</options>
    <group>misp_alert,configuration_change,apache,</group>
    <mitre>
      <id>T1562.001</id> <!-- Impair Defenses: Disable or Modify Tools -->
    </mitre>
  </rule>
</group>
EOF

# Membuat script active response
log "Membuat script active response..."
mkdir -p /var/ossec/active-response/bin
cat > /var/ossec/active-response/bin/active_response.sh << 'EOF'
#!/bin/bash
# Script Active Response untuk menangani insiden IoC berbahaya pada Apache2 Server
# Lokasi: /var/ossec/active-response/bin/active_response.sh

LOCAL=`dirname $0`;
cd $LOCAL
cd ../

PWD=`pwd`
read INPUT_JSON
COMMAND=$(echo $INPUT_JSON | jq -r .command)
ALERT_ID=$(echo $INPUT_JSON | jq -r .parameters.alert.id)
ALERT_RULE=$(echo $INPUT_JSON | jq -r .parameters.alert.rule.id)
ALERT_DESCRIPTION=$(echo $INPUT_JSON | jq -r .parameters.alert.rule.description)
SRC_IP=$(echo $INPUT_JSON | jq -r '.parameters.alert.data.srcip // empty')
DST_IP=$(echo $INPUT_JSON | jq -r '.parameters.alert.data.dstip // empty')
IOC_VALUE=$(echo $INPUT_JSON | jq -r '.parameters.alert.data.misp.value // empty')
IOC_TYPE=$(echo $INPUT_JSON | jq -r '.parameters.alert.data.misp.type // empty')
FILE_PATH=$(echo $INPUT_JSON | jq -r '.parameters.alert.data.syscheck.path // empty')
SOURCE=$(echo $INPUT_JSON | jq -r '.parameters.alert.data.source // empty')

# Log awal eksekusi
echo "`date` $0 $COMMAND Alert: $ALERT_ID Rule: $ALERT_RULE - $ALERT_DESCRIPTION" >> ${PWD}/logs/active-responses.log

# Respon hanya untuk tindakan add, delete untuk dihentikan
case ${COMMAND} in
    add)
        # Lanjutkan proses
        ;;
    delete)
        exit 0;
        ;;
    *)
        echo "`date` $0 invalid command: $COMMAND" >> ${PWD}/logs/active-responses.log
        exit 1;
        ;;
esac

# Jika ini adalah IoC malicious IP
if [ "$IOC_TYPE" = "ip-dst" ] && [ ! -z "$IOC_VALUE" ]; then
    # Blokir IP menggunakan iptables
    IP_TO_BLOCK="$IOC_VALUE"
    if [ ! -z "$IP_TO_BLOCK" ]; then
        # Periksa apakah IP sudah diblokir
        BLOCKED=$(iptables -L INPUT -v -n | grep "$IP_TO_BLOCK")
        if [ -z "$BLOCKED" ]; then
            iptables -I INPUT -s $IP_TO_BLOCK -j DROP
            iptables -I FORWARD -s $IP_TO_BLOCK -j DROP
            echo "`date` $0 blocked malicious IP: $IP_TO_BLOCK" >> ${PWD}/logs/active-responses.log
            
            # Tambahkan blok ke fail2ban jika tersedia
            if command -v fail2ban-client &> /dev/null; then
                fail2ban-client set apache-badhostname banip "$IP_TO_BLOCK" 2>/dev/null
                echo "`date` $0 added malicious IP to fail2ban: $IP_TO_BLOCK" >> ${PWD}/logs/active-responses.log
            fi
        else
            echo "`date` $0 IP already blocked: $IP_TO_BLOCK" >> ${PWD}/logs/active-responses.log
        fi
    fi
# Jika ini adalah IoC malicious domain
elif [ "$IOC_TYPE" = "hostname" ] || [ "$IOC_TYPE" = "domain" ] && [ ! -z "$IOC_VALUE" ]; then
    # Tambahkan domain ke /etc/hosts agar diarahkan ke localhost
    DOMAIN_TO_BLOCK="$IOC_VALUE"
    if [ ! -z "$DOMAIN_TO_BLOCK" ]; then
        # Periksa apakah domain sudah diblokir
        BLOCKED=$(grep "$DOMAIN_TO_BLOCK" /etc/hosts)
        if [ -z "$BLOCKED" ]; then
            echo "127.0.0.1 $DOMAIN_TO_BLOCK" >> /etc/hosts
            echo "`date` $0 blocked malicious domain: $DOMAIN_TO_BLOCK" >> ${PWD}/logs/active-responses.log
        else
            echo "`date` $0 domain already blocked: $DOMAIN_TO_BLOCK" >> ${PWD}/logs/active-responses.log
        fi
    fi
# Jika ini adalah IoC file berbahaya
elif [ "$IOC_TYPE" = "sha256" ] || [ "$IOC_TYPE" = "md5" ] || [ "$IOC_TYPE" = "sha1" ] && [ ! -z "$FILE_PATH" ]; then
    # Isolasi atau karantina file berbahaya
    if [ -f "$FILE_PATH" ]; then
        # Buat direktori karantina jika belum ada
        QUARANTINE_DIR="/var/ossec/quarantine"
        mkdir -p $QUARANTINE_DIR
        
        # Pindahkan file ke karantina dan buat file kosong di lokasi asli
        FILE_NAME=$(basename "$FILE_PATH")
        cp "$FILE_PATH" "$QUARANTINE_DIR/$FILE_NAME.malicious"
        chmod 000 "$FILE_PATH"  # Remove all permissions
        chattr +i "$FILE_PATH" 2>/dev/null  # Make immutable if possible
        
        echo "`date` $0 quarantined malicious file: $FILE_PATH" >> ${PWD}/logs/active-responses.log
        
        # Jika file berada di direktori web, lakukan tindakan tambahan
        if [[ "$FILE_PATH" == /var/www/* ]] || [[ "$FILE_PATH" == /etc/apache2/* ]]; then
            # Kembalikan ke versi backup/original jika ada
            if [ -f "$FILE_PATH.orig" ]; then
                chattr -i "$FILE_PATH" 2>/dev/null
                cp "$FILE_PATH.orig" "$FILE_PATH"
                chmod 644 "$FILE_PATH"
                echo "`date` $0 restored original file from backup: $FILE_PATH" >> ${PWD}/logs/active-responses.log
            fi
            
            # Restart Apache jika file konfigurasi terpengaruh
            if [[ "$FILE_PATH" == /etc/apache2/* ]]; then
                systemctl restart apache2
                echo "`date` $0 restarted Apache2 service after config change" >> ${PWD}/logs/active-responses.log
            fi
        fi
    else
        echo "`date` $0 file not found: $FILE_PATH" >> ${PWD}/logs/active-responses.log
    fi
# Tindakan khusus untuk perubahan pada Apache2
elif [ "$SOURCE" = "apache2_file_change" ] && [ ! -z "$FILE_PATH" ]; then
    echo "`date` $0 detected changes to Apache2 file: $FILE_PATH" >> ${PWD}/logs/active-responses.log
    
    # Jika ini adalah file PHP atau script executable, periksa isinya
    if [[ "$FILE_PATH" == *.php ]] || [[ "$FILE_PATH" == *.cgi ]] || [[ "$FILE_PATH" == *.pl ]]; then
        # Cari pola shell backdoor
        if grep -q -E '(system\(|exec\(|passthru\(|shell_exec\(|base64_decode\(eval|eval\(\$_)' "$FILE_PATH"; then
            # Buat direktori karantina jika belum ada
            QUARANTINE_DIR="/var/ossec/quarantine"
            mkdir -p $QUARANTINE_DIR
            
            # Pindahkan file ke karantina
            FILE_NAME=$(basename "$FILE_PATH")
            cp "$FILE_PATH" "$QUARANTINE_DIR/$FILE_NAME.webshell"
            chmod 000 "$FILE_PATH"  # Remove all permissions
            
            echo "`date` $0 possible web shell detected and quarantined: $FILE_PATH" >> ${PWD}/logs/active-responses.log
        fi
    fi
    
    # Jika ini adalah file konfigurasi Apache, verifikasi sintaksis
    if [[ "$FILE_PATH" == /etc/apache2/*.conf ]]; then
        if ! apachectl configtest &>/dev/null; then
            # Kembalikan ke versi backup jika sintaks tidak valid
            if [ -f "$FILE_PATH.orig" ]; then
                cp "$FILE_PATH.orig" "$FILE_PATH"
                systemctl restart apache2
                echo "`date` $0 invalid Apache2 config detected, restored from backup: $FILE_PATH" >> ${PWD}/logs/active-responses.log
            fi
        fi
    fi
fi

exit 0;
EOF

# Set permissions for active response script
chmod 750 /var/ossec/active-response/bin/active_response.sh
chown root:wazuh /var/ossec/active-response/bin/active_response.sh

# Cek apakah script fail2ban integration sudah ada
if [ ! -f /var/ossec/active-response/bin/fail2ban-apache.sh ]; then
    log "Membuat script integrasi fail2ban..."
    cat > /var/ossec/active-response/bin/fail2ban-apache.sh << 'EOF'
#!/bin/bash
# Script untuk fail2ban integration dengan Wazuh
# Lokasi: /var/ossec/active-response/bin/fail2ban-apache.sh

LOCAL=`dirname $0`;
cd $LOCAL
cd ../

PWD=`pwd`
read INPUT_JSON
COMMAND=$(echo $INPUT_JSON | jq -r .command)
ALERT_ID=$(echo $INPUT_JSON | jq -r .parameters.alert.id)
SRC_IP=$(echo $INPUT_JSON | jq -r '.parameters.alert.data.srcip // empty')
ALERT_RULE_GROUPS=$(echo $INPUT_JSON | jq -r '.parameters.alert.rule.groups // empty')

# Log awal eksekusi
echo "`date` $0 $COMMAND Alert: $ALERT_ID Source IP: $SRC_IP" >> ${PWD}/logs/active-responses.log

# Periksa apakah fail2ban terpasang
if ! command -v fail2ban-client &> /dev/null; then
    echo "`date` $0 fail2ban-client not found, unable to ban IP" >> ${PWD}/logs/active-responses.log
    exit 1
fi

# Respon hanya untuk tindakan add, delete untuk dihentikan
case ${COMMAND} in
    add)
        # Lanjutkan proses
        ;;
    delete)
        # Jika timeout tercapai, unban IP
        if [ ! -z "$SRC_IP" ]; then
            fail2ban-client set apache-badhostname unbanip "$SRC_IP" 2>/dev/null
            echo "`date` $0 unbanning IP: $SRC_IP" >> ${PWD}/logs/active-responses.log
        fi
        exit 0;
        ;;
    *)
        echo "`date` $0 invalid command: $COMMAND" >> ${PWD}/logs/active-responses.log
        exit 1;
        ;;
esac

# Pastikan IP sumber valid dan tersedia
if [ -z "$SRC_IP" ]; then
    echo "`date` $0 no source IP found in the alert" >> ${PWD}/logs/active-responses.log
    exit 1
fi

# Periksa apakah IP adalah private (tidak ban IP lokal)
IP_FIRST_OCTET=$(echo "$SRC_IP" | cut -d. -f1)
IP_SECOND_OCTET=$(echo "$SRC_IP" | cut -d. -f2)

# Jangan ban localhost dan IP pribadi
if [ "$IP_FIRST_OCTET" = "127" ] || [ "$IP_FIRST_OCTET" = "10" ] || [ "$IP_FIRST_OCTET" = "192" -a "$IP_SECOND_OCTET" = "168" ]; then
    echo "`date` $0 not banning private IP: $SRC_IP" >> ${PWD}/logs/active-responses.log
    exit 0
fi

# Tentukan jailname berdasarkan rule groups
JAIL_NAME="apache-badhostname"

if echo "$ALERT_RULE_GROUPS" | grep -q "web_scan"; then
    JAIL_NAME="apache-scan"
elif echo "$ALERT_RULE_GROUPS" | grep -q "sql_injection"; then
    JAIL_NAME="apache-sql-injection"
elif echo "$ALERT_RULE_GROUPS" | grep -q "xss"; then
    JAIL_NAME="apache-xss"
elif echo "$ALERT_RULE_GROUPS" | grep -q "web_attack"; then
    JAIL_NAME="apache-attack"
elif echo "$ALERT_RULE_GROUPS" | grep -q "authentication_failures"; then
    JAIL_NAME="apache-auth"
fi

# Tambahkan IP ke fail2ban jail
fail2ban-client set "$JAIL_NAME" banip "$SRC_IP" 2>/dev/null
BAN_STATUS=$?

if [ $BAN_STATUS -eq 0 ]; then
    echo "`date` $0 banned IP $SRC_IP in $JAIL_NAME jail" >> ${PWD}/logs/active-responses.log
else
    # Jika gagal, coba jail default
    fail2ban-client set apache-badhostname banip "$SRC_IP" 2>/dev/null
    BAN_STATUS=$?
    
    if [ $BAN_STATUS -eq 0 ]; then
        echo "`date` $0 banned IP $SRC_IP in apache-badhostname jail" >> ${PWD}/logs/active-responses.log
    else
        echo "`date` $0 failed to ban IP $SRC_IP" >> ${PWD}/logs/active-responses.log
    fi
fi

exit $BAN_STATUS;
EOF
    chmod 750 /var/ossec/active-response/bin/fail2ban-apache.sh
    chown root:wazuh /var/ossec/active-response/bin/fail2ban-apache.sh
    log "Script integrasi fail2ban berhasil dibuat."
else
    log "Script integrasi fail2ban sudah ada."
fi

# Cek direktori karantina
if [ ! -d /var/ossec/quarantine ]; then
    log "Membuat direktori karantina..."
    mkdir -p /var/ossec/quarantine
    chmod 750 /var/ossec/quarantine
    chown root:wazuh /var/ossec/quarantine
    log "Direktori karantina berhasil dibuat."
else
    log "Direktori karantina sudah ada."
fi

# Cek konfigurasi ossec.conf
log "Memperbarui konfigurasi ossec.conf..."
if [ -f /var/ossec/etc/ossec.conf ]; then
    # Buat backup jika belum ada
    if [ ! -f /var/ossec/etc/ossec.conf.bak ]; then
        cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
        log "Backup konfigurasi ossec.conf berhasil dibuat."
    fi
fi

# Tambahkan integrasi dan rules ke ossec.conf
log "Menulis konfigurasi baru ke ossec.conf..."
cat > /var/ossec/etc/ossec.conf << EOF
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>wazuh@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- Konfigurasi integrasi dengan MISP -->
  <integration>
    <name>custom-misp</name>
    <group>apache,web,syscheck</group>
    <alert_format>json</alert_format>
  </integration>

  <!-- Konfigurasi rules -->
  <ruleset>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
    <include>misp_rules.xml</include>
  </ruleset>

  <!-- Konfigurasi command untuk Active Response -->
  <command>
    <name>misp-block-ip</name>
    <executable>active_response.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <command>
    <name>misp-block-domain</name>
    <executable>active_response.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <command>
    <name>misp-quarantine-file</name>
    <executable>active_response.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <command>
    <name>misp-apache-response</name>
    <executable>active_response.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <command>
    <name>add-to-fail2ban</name>
    <executable>fail2ban-apache.sh</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- Active Response untuk memblokir IP berbahaya -->
  <active-response>
    <disabled>no</disabled>
    <command>misp-block-ip</command>
    <location>local</location>
    <rules_id>100623,100628</rules_id>
    <timeout>0</timeout>
  </active-response>

  <!-- Active Response untuk memblokir domain berbahaya -->
  <active-response>
    <disabled>no</disabled>
    <command>misp-block-domain</command>
    <location>local</location>
    <rules_id>100624,100629</rules_id>
    <timeout>0</timeout>
  </active-response>

  <!-- Active Response untuk karantina file berbahaya -->
  <active-response>
    <disabled>no</disabled>
    <command>misp-quarantine-file</command>
    <location>local</location>
    <rules_id>100625,100626,100627</rules_id>
    <timeout>0</timeout>
  </active-response>

  <!-- Active Response untuk perubahan file Apache -->
  <active-response>
    <disabled>no</disabled>
    <command>misp-apache-response</command>
    <location>local</location>
    <rules_id>100630</rules_id>
    <timeout>0</timeout>
  </active-response>

  <!-- Active Response untuk pendeteksian serangan web -->
  <active-response>
    <disabled>no</disabled>
    <command>misp-block-ip</command>
    <location>server</location>
    <level>7</level>
    <rules_group>web_attack</rules_group>
    <timeout>1800</timeout>
  </active-response>

  <!-- Active Response untuk fail2ban -->
  <active-response>
    <disabled>no</disabled>
    <command>add-to-fail2ban</command>
    <location>local</location>
    <rules_group>attack,web_scan</rules_group>
    <timeout>3600</timeout>
  </active-response>
</ossec_config>
EOF
log "Konfigurasi ossec.conf berhasil diperbarui."

# Restart Wazuh jika sudah terinstal sebelumnya
if systemctl is-active --quiet wazuh-manager; then
    log "Memulai ulang Wazuh Manager..."
    systemctl restart wazuh-manager
    
    # Validasi konfigurasi
    if systemctl is-active --quiet wazuh-manager; then
        log "Wazuh Manager berhasil dikonfigurasi dan berjalan."
    else
        log_error "Wazuh Manager gagal berjalan. Periksa log dengan 'journalctl -u wazuh-manager'."
    fi
else
    log "Wazuh Manager berhasil dikonfigurasi. Jalankan 'systemctl start wazuh-manager' untuk memulai layanan."
fi

log "============================================================="
log "Konfigurasi Wazuh Manager untuk Apache2 monitoring selesai!"
log "URL MISP: $MISP_URL"
log "============================================================="
log "Pastikan untuk meregister dan menghubungkan Wazuh Agent dari server Apache2."
log "Gunakan perintah berikut di Wazuh Manager untuk mendapatkan kunci registrasi:"
log "  /var/ossec/bin/manage_agents -l"
log "=============================================================" 