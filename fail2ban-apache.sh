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

# Tambahkan notifikasi ke log Apache
echo "[`date '+%Y-%m-%d %H:%M:%S'`] [notice] [client $SRC_IP] ModSecurity: Access denied by Wazuh Active Response (banned for malicious activity)" >> /var/log/apache2/error.log

exit $BAN_STATUS; 