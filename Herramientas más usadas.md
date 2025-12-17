# NMAP

## Cosas que "no afectan" a la enumeración
--open (solo mostrar puertos abiertos)
-oN, -oG, -oX, -oA (export a un tipo de archivo)
--min-rate (requests minimas)
-T0-5 (perfiles)

## Parámetros para diferentes enumeraciones
-sn buscar hosts en red

-O detectar OS
-pPUERTOS o -p- para todos
-n desactivar resolución DNS
-Pn desactivar host discovery (arp)
-sT --> TCP Connect Scan
-sU --> UDP
-sV --> version de servicios
-sC --> scripts comunes
	Hay varias categorías de scripts
		auth
		broadcast
		brute
		default
		discovery
		dos
		exploit
		external
		fuzzer
		intrusive
		malware
		safe
		version
		vuln
	--script="vuln and safe"
-sS --> SYN scan --> en vez de hacer SYN | SYN/ACK | ACK hace SYN | SYN/ACK | RST --> no deja evidencia y es más rápido
-f --> fragmentar paquetes
-D --> paquetes decoy, tienes q pasarle la ip que quieres que mande los paquetes
--source-port --> hace q los paquetes le lleguen desde un puerto
--data-length  --> length del paquete
--spoof-mac MARCA --> falsifica una mac

# Seclists

git clone https://github.com/danielmiessler/SecLists.git


# John The Ripper

Es una herramienta para romper hashes. La usaremos para bruteforcear .zips por ejemplo. 
zip2john, rar2john, pdf2john, office, unshadow, luks, vnc, ssh, keepass, krb

# Suits de impacket y CME


**1. RECON**

| Herramienta                    | Suite    | Propósito                                                   | Protocolos                   | Notas tácticas                                             |
| ------------------------------ | -------- | ----------------------------------------------------------- | ---------------------------- | ---------------------------------------------------------- |
| **rpcdump.py**                 | Impacket | Enumerar interfaces RPC expuestas                           | MSRPC                        | Identifica servicios vulnerables (Print Spooler, EFSRPC…). |
| **lookupsid.py**               | Impacket | Enumerar usuarios/grupos por RID cycling                    | SMB + SAMR                   | Permite inventario de cuentas sin credenciales.            |
| **samrdump.py**                | Impacket | Enumeración mediante SAMR                                   | SMB                          | Extrae SID-Name mapping útil para posterior targeting.     |
| **smbclient.py**               | Impacket | Cliente SMB interactivo                                     | SMB                          | Revisión de shares, configuración y permisos.              |
| **GetUserSPNs.py**             | Impacket | Detecta cuentas con SPN para análisis de servicios          | Kerberos                     | Recon previo para Kerberoasting (alto nivel).              |
| **findDelegation.py**          | Impacket | Descubre delegaciones en AD                                 | LDAP/Kerberos                | Mapa de relaciones de confianza y rutas de escalada.       |
| **ldapdomaindump**             | Externo  | Detección y volcado estructurado AD                         | LDAP                         | Inventario completo de AD para análisis offline.           |
| **CrackMapExec (enumeration)** | CME      | Enumeración masiva de hosts, SO, dominios, shares, sesiones | SMB, WinRM, LDAP, MSSQL, RDP | Excelente para reconocimiento rápido a escala.             |
**2. ACCESO**

| Herramienta                       | Suite    | Propósito                                          | Protocolos       | Notas tácticas                               |
| --------------------------------- | -------- | -------------------------------------------------- | ---------------- | -------------------------------------------- |
| **smbclient.py**                  | Impacket | Verificar accesos abiertos                         | SMB              | Identifica rutas accesibles sin privilegios. |
| **CME + módulos de credenciales** | CME      | Validar listas de credenciales de forma controlada | SMB, WinRM, LDAP | Normaliza intentos y reduce ruido.           |

**3. RCE**

|Herramienta|Suite|Propósito|Protocolos|Notas tácticas|
|---|---|---|---|---|
|**wmiexec.py**|Impacket|Ejecución remota por WMI|WMI/DCOM|Menos ruidoso que PsExec; sin servicios persistentes.|
|**atexec.py**|Impacket|Tareas programadas remotas|RPC/SCHTASKS|Útil cuando WMI está bloqueado.|
|**psexec.py**|Impacket|Ejecución remota en estilo PsExec|SMB/RPC|Crea servicio temporal; a veces más detectable.|
|**dcomexec.py**|Impacket|Exec vía DCOM|DCOM|Alternativa para bypass de restricciones.|
|**CME wmiexec / smbexec / psexec**|CME|Ejecución remota masiva|SMB/WMI/DCOM|Ideal para lateral movement a escala.|

**4. RELAY Y LATERAL**

|Herramienta|Suite|Propósito|Protocolos|Notas tácticas|
|---|---|---|---|---|
|**ntlmrelayx.py**|Impacket|Relay NTLM hacia SMB/LDAP/HTTP|NTLM/SMB/LDAP|Punto central en operaciones con coerción de autenticación.|
|**smbserver.py**|Impacket|Servidor SMB controlado|SMB|Cebo para capturar autenticaciones.|
|**CME relay (mod NTLM)**|CME|Relay básico integrado|SMB/HTTP|Menos flexible que ntlmrelayx, pero más rápido para evaluación continua.|

**5. KERBEROS**

|Herramienta|Suite|Propósito|Protocolos|Notas tácticas|
|---|---|---|---|---|
|**GetUserSPNs.py**|Impacket|Inventario de SPN|Kerberos|Recon para ataques sobre cuentas de servicio.|
|**GetNPUsers.py**|Impacket|Identifica cuentas sin preauth|Kerberos|Ideal para análisis AS-REP (alto nivel).|
|**ticketer.py**|Impacket|Crear TGT/TGS personalizados|Kerberos|Permite persistencia y movimiento lateral avanzado.|
|**raiseChild.py**|Impacket|Abuso de trusts inter-dominios|Kerberos|Escalado entre dominios hijo ↔ padre.|
|**CME kerberos**|CME|Módulos para autenticación y consultas Kerberos|Kerberos|Simplifica interacción Kerberos en grandes redes.|

**6. SECRETOS**

|Herramienta|Suite|Propósito|Protocolos|Notas tácticas|
|---|---|---|---|---|
|**secretsdump.py**|Impacket|Extraer SAM, LSA, NTDS|SMB/RPC|Estándar post-compromiso a alto nivel.|
|**dpapi.py**|Impacket|Leer blobs DPAPI si se conocen claves|DPAPI|Complemento útil para datos protegidos.|
|**CME creds**|CME|Gestión centralizada de credenciales|Interno|Optimiza reutilización y tracking.|

**7. PERSISTENCIA**

|Herramienta|Suite|Propósito|Protocolos|Notas tácticas|
|---|---|---|---|---|
|**addcomputer.py**|Impacket|Agregar objetos Computer en AD|LDAP|Persistencia basada en creación de máquinas controladas.|
|**ticketer.py**|Impacket|TGT/TGS manipulados|Kerberos|Persistencia basada en claves KRBTGT.|
|**CME --execute y módulos persistentes**|CME|Automatización de backdoors benignos|SMB/WMI|Control de múltiples máquinas desde una plataforma.|

**8. TAKEOVER (AD)**

|Herramienta|Suite|Propósito|Protocolos|Notas tácticas|
|---|---|---|---|---|
|**secretsdump.py (contra DC)**|Impacket|Obtención de ntds.dit / claves KRBTGT|SMB|Paso previo a control total del AD.|
|**ticketer.py**|Impacket|Tickets de alto privilegio|Kerberos|Control completo del entorno Kerberos.|
|**rbcd.py**|Impacket|Configurar delegación|LDAP|Movimientos y suplantación dentro del dominio.|
|**CME + módulos AD**|CME|Acciones extensivas contra todo el dominio|SMB/LDAP|Utilidad de administración masiva orientada a evaluación.|

# NetCat

listener: nc -nlvp 444
conectarse: nc ip 444


# MSFCONSOLE
Flujo de trabajo habitual:
1. Buscar módulos
2. Seleccionar módulo
3. Ver información
4. Configurar opciones
5. GO

**1. Buscar módulos**
search cosa
search type:exploit cosa

**2. Seleccionar módulo**
use module
back

**3. Ver información**
show options
show payloads
show targets
info

**4. Configurar opciones**
set LHOST ip
set LPORT puerto
set PAYLOAD payload

**5. Ejecución**
run // exploit
exploit -j # Background
exploit -z # No interactuar con la sesión

**5.1 Shell interactiva**
meterpreter --> shell # Estabilización [[Infosec]]

# Gobuster
```shell
gobuster dir -u http://10.10.10.121/ -w diccionario
```
Para subdominios, podemos usar
```shell
gobuster dns -d dominio.com -w diccionario
```


# Whatweb
ver tecnologias que usa una web --> extensión wappalyzer


