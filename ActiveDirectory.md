# Active Directory

## Parte I — Conceptos

### 1. ¿Qué es Active Directory?

Active Directory (AD) es el sistema centralizado de Microsoft para gestionar identidades, autenticación, autorización, recursos y políticas en redes Windows empresariales. Sustituye y complementa cuentas locales, exponiendo un directorio jerárquico accesible vía LDAP y soportando autenticación mediante Kerberos y, en compatibilidad, NTLM.

Se compone de:

- una base de datos central lógica
- múltiples servidores (Domain Controllers)
- protocolos de autenticación
- un modelo jerárquico de objetos
- un sistema de políticas

El objetivo es responder siempre a tres preguntas:

- ¿Quién eres? (autenticación)
- ¿Qué puedes hacer? (autorización)
- ¿Qué recursos existen? (directorio)

### 2. Estructura lógica: Forest, Domain y OU

#### 2.1 Forest (bosque)

- Nivel superior lógico. Una frontera administrativa y de seguridad.
- Contiene uno o varios dominios y un esquema común (schema) que define objetos y atributos.

#### 2.2 Domain

- Unidad principal de administración (ej. empresa.local).
- Contiene usuarios, equipos, grupos y políticas; cada dominio tiene al menos un Domain Controller.

#### 2.3 Organizational Units (OU)

- Contenedores lógicos para organizar objetos, aplicar GPOs y delegar administración.
- Ejemplo de árbol:

```text
empresa.local
├── Users
├── Computers
├── IT
└── Finance
```

### 3. Objetos en Active Directory

- Todo en AD es un objeto LDAP: `user`, `computer`, `group`, `serviceAccount`, `printer`, `GPO`.
- Atributos importantes: `sAMAccountName`, `distinguishedName`, `memberOf`, `userAccountControl`, `servicePrincipalName`, `lastLogon`, hashes (almacenados en la base del DC).

### 4. Identidad interna: SID y tokens

- Cada objeto tiene un `Security Identifier` (SID), ej. `S-1-5-21-...-1001`.
- Cuando un usuario inicia sesión se genera un `Access Token` que contiene el SID del usuario, los SIDs de grupos y privilegios; este token se usa para decisiones de autorización.

### 5. DNS: pieza crítica del sistema

- AD depende fuertemente de DNS para localizar DCs y servicios. Registros clave: `_ldap._tcp.dc._msdcs.<dominio>`, SRV records, etc.
- Sin DNS correcto, Kerberos y localización de servicios fallan.

### 6. LDAP: el lenguaje de consulta

- Lightweight Directory Access Protocol es el mecanismo para consultar y modificar el directorio.
- Usos: enumerar usuarios, grupos, SPNs, obtener políticas, localizar equipos. Se puede entender como un SQL del directorio.

### 7. Domain Controllers (DC)

- Ejecutan Active Directory Domain Services y almacenan la base `NTDS.dit`.
- Funciones: autenticar usuarios, emitir tickets Kerberos, responder LDAP y replicar cambios entre DCs para consistencia y alta disponibilidad.

### 8. Autenticación: visión general

- AD soporta Kerberos (principal) y NTLM (legacy). Kerberos es preferido; NTLM permanece por compatibilidad y es fuente de ataques.

### 9. Kerberos (detalle)

#### 9.1 Qué es

- Protocolo de autenticación basado en tickets y criptografía simétrica. Diseñado para no enviar contraseñas en claro y reducir consultas al DC.

#### 9.2 Componentes

- **KDC (Key Distribution Center):** normalmente en el DC; contiene AS (Authentication Service) y TGS (Ticket Granting Service).
- **TGT (Ticket Granting Ticket):** ticket maestro que demuestra que el usuario fue autenticado.
- **TGS (Service Ticket):** ticket para acceder a un servicio específico (SMB, HTTP, MSSQL, LDAP, CIFS...).
- **PAC (Privilege Attribute Certificate):** bloque dentro del ticket con información de grupos y atributos de autorización.

#### 9.3 Flujo Kerberos (completo)

**Paso 1: Login**

- El usuario introduce su contraseña en el cliente.
- El cliente solicita TGT al KDC (AS) presentando credenciales.

**Paso 2: KDC valida**

- Si la contraseña es correcta, el KDC entrega un TGT cifrado y clave de sesión.

**Paso 3: Acceso a servicio**

- Cuando el usuario quiere acceder a un servicio (ej. fileserver), el cliente solicita un TGS al KDC.

**Paso 4: KDC entrega TGS**

- El KDC emite un TGS cifrado con la clave del servicio.

**Paso 5: Acceso**

- El cliente presenta el TGS al servidor; si es válido, el servicio concede acceso.

#### 9.4 Claves y cifrado

- Kerberos utiliza la clave derivada de la contraseña del usuario, la clave del KDC y la clave del servicio; también claves de sesión temporales.

#### 9.5 PAC

- Contiene SIDs, grupos y atributos de autorización que el servicio usa sin consultar constantemente al DC.

### 10. SPN (Service Principal Name)

- Identificador que asocia un servicio a una cuenta AD. Ejemplos: `MSSQLSvc/sqlserver`, `HTTP/webserver`, `CIFS/fileserver`.
- Las cuentas de servicio con SPNs son objetivo de Kerberoasting.

### 11. NTLM (detalle)

#### 11.1 Qué es

- NT LAN Manager es un mecanismo challenge-response legacy usado aún en muchos entornos.

#### 11.2 NT hash

- Windows deriva el NT hash con MD4(UTF-16(password)). Este hash actúa en muchos flujos como la credencial real.

#### 11.3 Challenge-response

- Flujo simplificado: servidor envía challenge aleatorio; el cliente responde usando el hash NT; el servidor valida. La contraseña nunca viaja en claro.

### 12. LSASS y credenciales en memoria

- `lsass.exe` (Local Security Authority Subsystem Service) mantiene tickets, hashes y tokens en memoria.
- Es objetivo principal en post-explotación; herramientas como Mimikatz o Rubeus extraen NT hashes, tickets (TGT/TGS) y otros secretos.

### 13. GPO (Group Policy)

- Sistema de políticas centralizadas para configurar equipos y usuarios: scripts de inicio, firewall, instalación de software, asignación de administradores locales, tareas programadas.
- GPOs se aplican por dominio, sitio y OU; los equipos consultan a los DCs para descargar y aplicar las políticas.

### 14. Relaciones entre máquinas en el dominio

#### 14.1 Confianza en el dominio

- Una máquina que se une al dominio crea una cuenta (ej. `PC01$`) y establece una clave compartida con el DC; pasa a ser trusted.

#### 14.2 Autenticación máquina ↔ DC

- Las máquinas también se autentican como cuentas `computer$` ante el DC.

#### 14.3 Comunicación entre máquinas

- Acceso a recursos típicamente: Usuario -> Cliente -> Servidor -> DC (si se necesita validación adicional). Kerberos reduce consultas al DC.

#### 14.4 Delegación de confianza

- La delegación permite que servicios actúen en nombre de usuarios (web -> backend). Existen modalidades: unconstrained, constrained delegation y resource-based constrained delegation (RBCD).

### 15. Modelo de autorización

- Cuando un usuario accede a un recurso, se autentica (Kerberos/NTLM), obtiene identidad (SID + grupos), el sistema genera un token y compara permisos mediante ACLs.

**ACL (Access Control List)**

- Cada recurso tiene ACLs que permiten read, write, execute, modify y full control.

### 16. Resumen estructural

- Capa 1: Identidad (usuarios, equipos, grupos, SIDs).
- Capa 2: Directorio (LDAP, consultas y estructura).
- Capa 3: Autenticación (Kerberos principal y NTLM legacy).
- Capa 4: Autorización (tokens, ACLs, grupos).
- Capa 5: Políticas (GPOs y configuración).
- Capa 6: Infraestructura (DCs, DNS y replicación).

---

## Parte II — Ataques

### 17. Por qué atacar AD

- AD agrupa identidades y permisos críticos; si un atacante compromete objetos con privilegios (Domain Admins, Enterprise Admins) puede controlar la infraestructura.
- AD confía en relaciones entre máquinas y protocolos legacy (NTLM), lo que facilita muchas técnicas de ataque.

### 18. Caché de credenciales y extracción

- Windows mantiene en memoria tickets, hashes y tokens, especialmente en `lsass.exe`.
- Suites/herramientas asociadas:
  - Mimikatz y Rubeus para tickets/credenciales en memoria.
  - Impacket (`secretsdump.py`) para extracción de secretos según contexto y privilegios.
  - NetExec/CME para validar alcance lateral del material recuperado.

### 19. Pass-the-Hash (PtH)

- Idea: si tienes el NT hash, puedes autenticarte vía NTLM sin conocer la contraseña.
- Flujo: comprometes una máquina -> extraes NT hash -> usas el hash para autenticaciones de red (SMB, WMI, PsExec, WinRM) y movimiento lateral.
- Suites/herramientas asociadas:
  - NetExec/CME para validación de hash a escala sobre SMB/WinRM.
  - Impacket (`wmiexec.py`, `psexec.py`, `smbexec.py`) para ejecución remota autenticada.
  - BloodHound para priorizar objetivos con valor de escalado.

### 20. Pass-the-Ticket (PtT)

- Versión Kerberos: robar tickets (TGT/TGS) y reusarlos/inyectarlos para suplantar identidad sin conocer contraseña.
- Suites/herramientas asociadas:
  - Rubeus para operaciones sobre tickets Kerberos.
  - Mimikatz para análisis de credenciales Kerberos en post-explotación.
  - Impacket para interacción con servicios Kerberos con material ya obtenido.

### 21. Kerberoasting

- Idea: los TGS solicitados para SPNs están cifrados con la clave de la cuenta de servicio.
- Flujo: enumera SPNs -> pide TGS para SPN -> obtiene ticket cifrado -> crackeo offline (Hashcat).
- Suites/herramientas asociadas:
  - Impacket (`GetUserSPNs.py`) para identificar objetivos y extraer material TGS.
  - Rubeus para operaciones equivalentes en host Windows.
  - Hashcat/John para validación de fortaleza de contraseñas offline.

### 22. AS-REP Roasting

- Idea: algunas cuentas no requieren preautenticación Kerberos; el DC devuelve material cifrado crackeable offline.
- Flujo: solicita AS-REP -> recibe blob cifrado -> crackeo offline.
- Suites/herramientas asociadas:
  - Impacket (`GetNPUsers.py`) para detección y extracción AS-REP.
  - Rubeus para comprobación desde entorno Windows.
  - Hashcat/John para crackeo offline controlado.

### 23. NTLM Relay

- Idea: NTLM no autentica al servidor; un atacante puede reenviar autenticación de la víctima a otro servicio.
- No requiere crackear hashes; es un ataque en tiempo real.
- Suites/herramientas asociadas:
  - Responder para captura de autenticaciones en redes mal endurecidas.
  - Impacket (`ntlmrelayx.py`) como motor de relay.
  - NetExec/CME para validar prerequisitos de exposición.

### 24. SMB Relay

- Variante: usar SMB para captar y relayear autenticaciones; posibles consecuencias: ejecución remota, volcado de SAM, creación de usuarios y movimiento lateral.
- Suites/herramientas asociadas:
  - Impacket (`ntlmrelayx.py`) para relay contra SMB.
  - Responder para captura/inducción inicial.
  - NetExec/CME para comprobar SMB signing y superficie vulnerable.

### 25. DHCPv6 Takeover (mitm6)

- Explota preferencia IPv6 de Windows: el atacante responde como servidor DHCPv6 y fuerza DNS malicioso para inducir autenticaciones NTLM relayables.
- Suites/herramientas asociadas:
  - mitm6 para inducir escenario de resolución/control vía IPv6.
  - Responder para cadenas de captura cuando aplica.
  - Impacket (`ntlmrelayx.py`) para materializar el relay posterior.

### 26. LDAP Relay

- Relay de autenticación hacia LDAP del DC para modificar AD (crear máquinas, cambiar ACLs, configurar delegación/RBCD).
- Suites/herramientas asociadas:
  - Impacket (`ntlmrelayx.py`) para relay hacia LDAP.
  - BloodHound para identificar qué cambios LDAP darían mayor impacto.
  - NetExec/CME para validar condiciones previas del entorno.

### 27. RBCD (Resource-Based Constrained Delegation)

- Permite que la máquina destino defina quién puede delegar en su nombre (`msDS-AllowedToActOnBehalfOfOtherIdentity`).
- Si un atacante escribe ese atributo, puede realizar S4U impersonation y obtener privilegios elevados.
- Suites/herramientas asociadas:
  - BloodHound para detectar rutas de control que habilitan RBCD.
  - Impacket (scripts LDAP/AD como `rbcd.py`, según flujo) para validación técnica.
  - Rubeus para operaciones Kerberos relacionadas con S4U.

### 28. GPO Abuse

- Modificar GPOs permite ejecutar código en muchas máquinas (scripts de inicio, tareas programadas, asignación de admin local).
- Suites/herramientas asociadas:
  - BloodHound para descubrir permisos efectivos sobre GPO/OUs.
  - Herramientas AD/PowerShell nativas para validación controlada de cambios.
  - NetExec/CME para medir alcance operativo tras aplicación de políticas.

### 29. ACL abuse y abuso de delegación

- Abusar de permisos granulares para resetear contraseñas, escribir SPNs, modificar delegación o cambiar grupos.
- Suites/herramientas asociadas:
  - BloodHound para mapear rutas basadas en ACL.
  - Impacket (por ejemplo `dacledit.py` y flujos LDAP relacionados) para validación puntual.
  - NetExec/CME para comprobar impacto práctico en autenticación/movimiento lateral.

### 30. BloodHound y mapeo de rutas

- BloodHound modela relaciones AD en grafos y ayuda a encontrar caminos (user -> ACL -> machine -> DA), rutas RBCD, GPO abuse y cadenas de admin local.
- Papel operativo en pentest real:
  - prioriza objetivos de mayor retorno técnico,
  - ordena cadenas multi-salto entre ataques distintos,
  - facilita justificar el riesgo con evidencia de ruta completa.
