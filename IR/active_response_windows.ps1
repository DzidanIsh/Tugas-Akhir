# Script Active Response untuk Windows
# Penanganan IoC berbahaya di sistem Windows
# Lokasi: C:\Program Files (x86)\ossec-agent\active-response\bin\active_response_windows.ps1

# Fungsi untuk mencatat log
function Write-Log {
    param (
        [string]$Message
    )
    $logPath = "$env:ProgramFiles\ossec-agent\active-response\active-response.log"
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timeStamp - $Message" | Out-File -Append -FilePath $logPath
}

# Fungsi untuk memblokir IP berbahaya dengan Windows Firewall
function Block-MaliciousIP {
    param (
        [string]$IPAddress
    )
    
    try {
        # Cek apakah rule sudah ada
        $existingRule = Get-NetFirewallRule -DisplayName "WAZUH-MISP-BLOCK-$IPAddress" -ErrorAction SilentlyContinue
        
        if (-not $existingRule) {
            # Buat aturan firewall baru
            New-NetFirewallRule -DisplayName "WAZUH-MISP-BLOCK-$IPAddress" -Direction Inbound -Action Block -RemoteAddress $IPAddress | Out-Null
            New-NetFirewallRule -DisplayName "WAZUH-MISP-BLOCK-$IPAddress-OUT" -Direction Outbound -Action Block -RemoteAddress $IPAddress | Out-Null
            Write-Log "IP berbahaya berhasil diblokir: $IPAddress"
        } else {
            Write-Log "IP sudah diblokir sebelumnya: $IPAddress"
        }
    } catch {
        Write-Log "Gagal memblokir IP $IPAddress. Error: $_"
    }
}

# Fungsi untuk memblokir domain berbahaya di hosts file
function Block-MaliciousDomain {
    param (
        [string]$Domain
    )
    
    try {
        $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
        $hostsContent = Get-Content $hostsFile
        
        # Cek apakah domain sudah ada di hosts file
        if (-not ($hostsContent -match "127\.0\.0\.1\s+$Domain")) {
            # Tambahkan domain ke hosts file
            Add-Content -Path $hostsFile -Value "127.0.0.1 $Domain"
            Write-Log "Domain berbahaya berhasil diblokir: $Domain"
        } else {
            Write-Log "Domain sudah diblokir sebelumnya: $Domain"
        }
    } catch {
        Write-Log "Gagal memblokir domain $Domain. Error: $_"
    }
}

# Fungsi untuk mengisolasi file berbahaya
function Quarantine-MaliciousFile {
    param (
        [string]$FilePath
    )
    
    try {
        if (Test-Path $FilePath) {
            # Buat direktori karantina jika belum ada
            $quarantineDir = "$env:ProgramFiles\ossec-agent\quarantine"
            if (-not (Test-Path $quarantineDir)) {
                New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null
            }
            
            # Dapatkan nama file
            $fileName = Split-Path $FilePath -Leaf
            
            # Salin file ke karantina
            Copy-Item -Path $FilePath -Destination "$quarantineDir\$fileName.malicious" -Force
            
            # Hapus akses ke file
            $acl = Get-Acl $FilePath
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "Deny")
            $acl.AddAccessRule($accessRule)
            Set-Acl -Path $FilePath -AclObject $acl
            
            Write-Log "File berbahaya berhasil dikarantina: $FilePath"
        } else {
            Write-Log "File tidak ditemukan: $FilePath"
        }
    } catch {
        Write-Log "Gagal mengisolasi file $FilePath. Error: $_"
    }
}

# Main script
try {
    # Baca input JSON
    $inputJson = [Console]::In.ReadLine()
    $alertData = $inputJson | ConvertFrom-Json
    
    # Ekstrak informasi
    $command = $alertData.command
    $alertId = $alertData.parameters.alert.id
    $ruleId = $alertData.parameters.alert.rule.id
    $description = $alertData.parameters.alert.rule.description
    
    # Extract IoC information
    $iocValue = $alertData.parameters.alert.data.misp.value
    $iocType = $alertData.parameters.alert.data.misp.type
    $filePath = $alertData.parameters.alert.data.syscheck.path
    
    # Log awal eksekusi
    Write-Log "Command: $command, Alert: $alertId, Rule: $ruleId - $description"
    
    # Hanya proses jika command adalah 'add'
    if ($command -ne "add") {
        Write-Log "Exiting: command is not 'add'"
        exit 0
    }
    
    # Proses berdasarkan tipe IoC
    if ($iocType -eq "ip-dst" -and $iocValue) {
        Block-MaliciousIP -IPAddress $iocValue
    } elseif (($iocType -eq "hostname" -or $iocType -eq "domain") -and $iocValue) {
        Block-MaliciousDomain -Domain $iocValue
    } elseif (($iocType -eq "sha256" -or $iocType -eq "md5" -or $iocType -eq "sha1") -and $filePath) {
        Quarantine-MaliciousFile -FilePath $filePath
    } else {
        Write-Log "No action taken: Unsupported IoC type or missing value"
    }

} catch {
    Write-Log "Error processing alert: $_"
    exit 1
}

exit 0 