#!/bin/bash

# Memeriksa apakah script dijalankan sebagai root
if [ "$EUID" -ne 0 ]; then
  echo "Mohon jalankan script ini sebagai root (gunakan sudo)"
  exit 1
fi

echo "====================================================="
echo "    INSTALASI WEB RENTAN UNTUK PENGUJIAN DEFACEMENT"
echo "====================================================="

# Install Apache2 dan PHP
echo "[+] Memperbarui repository..."
apt update
echo "[+] Menginstall Apache2 dan PHP..."
apt install -y apache2 php libapache2-mod-php php-gd

# Disable Apache default security dan mod_security jika ada
echo "[+] Menonaktifkan fitur keamanan default Apache..."
a2dismod security2 2>/dev/null
sed -i 's/Options Indexes FollowSymLinks/Options Indexes FollowSymLinks ExecCGI/' /etc/apache2/apache2.conf
sed -i 's/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf

# Membuat .htaccess yang mengizinkan eksekusi script
echo "[+] Mengkonfigurasi izin eksekusi file upload..."
cat << 'EOF' > /var/www/html/.htaccess
<Directory "/var/www/html">
    Options +ExecCGI +Indexes +FollowSymLinks
    AddHandler cgi-script .php .php5 .phtml .pl .py .jsp .asp .htm .html .shtml
    AllowOverride All
    Require all granted
</Directory>
EOF

# Membuat direktori uploads
echo "[+] Membuat direktori uploads..."
UPLOAD_DIR="/var/www/html/uploads"
mkdir -p "$UPLOAD_DIR"
chmod -R 777 "$UPLOAD_DIR"

# Membuat direktori untuk assets
ASSETS_DIR="/var/www/html/assets"
mkdir -p "$ASSETS_DIR/css"
mkdir -p "$ASSETS_DIR/js"

# Membuat CSS file
echo "[+] Membuat file CSS untuk tampilan website..."
cat << 'EOF' > $ASSETS_DIR/css/style.css
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: #f5f5f5;
    margin: 0;
    padding: 20px;
    color: #333;
}

.container {
    max-width: 800px;
    margin: 0 auto;
    background-color: white;
    padding: 30px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

header {
    text-align: center;
    margin-bottom: 30px;
    padding-bottom: 15px;
    border-bottom: 1px solid #eee;
}

h1 {
    color: #2c3e50;
    margin: 0;
}

h2 {
    color: #3498db;
    margin-top: 0;
}

.description {
    background-color: #f8f9fa;
    padding: 15px;
    border-left: 4px solid #3498db;
    margin-bottom: 20px;
}

.upload-form {
    background-color: #ffffff;
    padding: 20px;
    border-radius: 5px;
    border: 1px solid #ddd;
}

.btn {
    background-color: #3498db;
    color: white;
    border: none;
    padding: 10px 15px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 16px;
    transition: background-color 0.3s;
}

.btn:hover {
    background-color: #2980b9;
}

input[type="file"] {
    display: block;
    margin: 15px 0;
    width: 100%;
}

.message {
    margin-top: 20px;
    padding: 10px;
    border-radius: 4px;
}

.success {
    background-color: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
}

.error {
    background-color: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
}

.file-list {
    margin-top: 30px;
}

.file-list h3 {
    margin-bottom: 10px;
    color: #2c3e50;
}

.file-item {
    padding: 10px;
    background-color: #f8f9fa;
    margin-bottom: 5px;
    border-radius: 4px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.file-link {
    color: #3498db;
    text-decoration: none;
}

.file-link:hover {
    text-decoration: underline;
}

footer {
    margin-top: 30px;
    text-align: center;
    font-size: 14px;
    color: #7f8c8d;
    padding-top: 20px;
    border-top: 1px solid #eee;
}
EOF

# Membuat halaman PHP yang rentan untuk upload
echo "[+] Membuat halaman upload file rentan..."
cat << 'EOF' > /var/www/html/index.php
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Website Pengujian Defacement</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>Website Pengujian Defacement</h1>
            <p>Platform untuk menguji kerentanan web melalui file upload</p>
        </header>

        <div class="description">
            <p>Website ini sengaja dibuat rentan untuk keperluan pengujian dan pembelajaran 
            tentang teknik web defacement. Anda dapat mengunggah file apapun tanpa batasan 
            tipe dan ekstensi.</p>
        </div>

        <div class="upload-form">
            <h2>Unggah File Anda</h2>
            <form action="" method="post" enctype="multipart/form-data">
                <input type="file" name="fileToUpload" id="fileToUpload">
                <button type="submit" class="btn" name="submit">Unggah File</button>
            </form>
            
            <?php
            if(isset($_FILES['fileToUpload'])){
                $target_dir = "uploads/";
                $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
                
                // Tidak ada validasi tipe file, semua file diterima
                if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
                    echo '<div class="message success">
                        File '. htmlspecialchars(basename($_FILES["fileToUpload"]["name"])). ' berhasil diunggah.
                        <br>Anda dapat mengaksesnya di: <a href="'.$target_file.'" class="file-link" target="_blank">'.$target_file.'</a>
                    </div>';
                } else {
                    echo '<div class="message error">Maaf, terjadi kesalahan saat mengunggah file.</div>';
                }
            }
            ?>
        </div>

        <div class="file-list">
            <h3>File yang Telah Diunggah:</h3>
            <?php
            $files = glob('uploads/*');
            if (count($files) > 0) {
                foreach($files as $file) {
                    $filename = basename($file);
                    echo '<div class="file-item">
                        <span>'.$filename.'</span>
                        <a href="'.$file.'" class="file-link" target="_blank">Lihat</a>
                    </div>';
                }
            } else {
                echo '<p>Belum ada file yang diunggah.</p>';
            }
            ?>
        </div>

        <footer>
            <p>Website Rentan untuk Pengujian &copy; <?php echo date("Y"); ?></p>
        </footer>
    </div>
</body>
</html>
EOF

# Restart Apache
echo "[+] Merestart Apache..."
systemctl restart apache2

# Mendeteksi IP lokal secara otomatis
LOCAL_IP=$(hostname -I | awk '{print $1}')

# Jika otomatis gagal, gunakan manual
if [ -z "$LOCAL_IP" ]; then
    read -p "Deteksi IP otomatis gagal. Silakan masukkan IP lokal Anda secara manual: " LOCAL_IP
fi

# Informasi akhir
echo "====================================================="
echo "              INSTALASI SELESAI"
echo "====================================================="
echo "Website rentan berhasil dibuat!"
echo "Anda dapat mengakses website melalui: http://$LOCAL_IP/"
echo "Direktori uploads: http://$LOCAL_IP/uploads/"
echo "====================================================="
echo "PERINGATAN: Website ini dengan sengaja dibuat rentan."
echo "            JANGAN gunakan di lingkungan produksi!"
echo "====================================================="
