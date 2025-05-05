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