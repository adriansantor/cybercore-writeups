# 0. Conceptos & Útiles

## 0.1 Diferencia entre shell, terminal y consola

- **Shell** → intérprete (bash, zsh, fish...).
    
- **Terminal** → programa que muestra una shell.
    
- **Consola** → interfaz física o TTY.

## 0.2 Procesos

- **&** → ejecutar en segundo plano.
    
- **jobs** → listar trabajos.
    
- **fg / bg** → mandar procesos a primer/segundo plano.

## 0.3 Compresión

- `tar -czf archivo.tar.gz carpeta/`
    
- `tar -xzf archivo.tar.gz`.

## 0.4 nano

- ctrl+o → guardar
    
- ctrl+x → salir

# 1. Comandos básicos del sistema

## 1.1 Navegación y consulta

- **whoami** → muestra el usuario actual.
    
- **pwd** → muestra el directorio actual.
    
- **groups** → lista los grupos del usuario.
    
- **apropos palabra** → busca comandos relacionados con la palabra.


### Listado de archivos

**ls** admite múltiples flags:

- `-l` → muestra permisos, dueño, etc.
    
- `-a` → muestra archivos ocultos.
    
- `-i` → muestra el número de inodo.
    
- `-t` → ordena por última edición.    

### Localización y búsqueda

**find**:

- `-type f` → archivos.
    
- `-name nombre` → por nombre.
    
- `-user dueño` → por propietario.
    
- `-size +tamaño` → por tamaño.
    
- `-newermt fecha` → más nuevos que una fecha.
    
**lsof** → muestra archivos abiertos.

### Información del sistema

- **uname -a** → kernel, arquitectura, versión.
    
- **lsblk** → muestra dispositivos de bloque (discos, particiones).
    
- **lsusb** → muestra dispositivos USB.
 
---

# 2. Redes

## 2.1 Comprobación y estado

- **ping host** → envía paquetes ICMP.
    
- **ifconfig** → información de red.
    
- **netstat -a** → conexiones y puertos.
    
- **netstat -rn** → tabla de rutas.
    
- **ss** → alternativa moderna a netstat.

## 2.2 Procesos de red

- **ps** → ver tus procesos.
    
- **ps aux** → ver _todos_ los procesos.

## 2.3 Configuración manual

- `ifconfig int0 IP` → asignar IP manual.
    
- `ifconfig int0 netmask MASCARA`.
    
- `route add default gw IP int0` → configurar gateway.
    
- DNS → `/etc/resolv.conf`.
    
- Interfaces → `/etc/network/interfaces`.
    
- **traceroute** → muestra el camino de un paquete.    

---

# 3. Permisos en Linux

![Permisos](Pasted%20image%2020251023001300.png)

## 3.1 Conceptos generales

- `chmod` → cambia permisos.
    
- `chown` → cambia dueño.
    
- Grupos de permisos: **Owner – Group – Others**.    

## 3.2 CHMOD

**Letras:**

- r = read
    
- w = write
    
- x = execute


**Octales:**

- 4 → read
    
- 2 → write
    
- 1 → execute

Ejemplo:  
`chmod 754 f` → Owner: rwx, Group: r-x, Others: r--.

### Valores comunes

- 777 → todos pueden todo. **Peligroso**.
    
- 755 → ejecutable universal.
    
- 700 → solo dueño.
    
- 644 → archivo de texto estándar.
    
- 600 → texto privado.
    
- 664 → grupo edita, otros leen.
    
- 775 → trabajo colaborativo.
    
- 711 → ejecutable oculto.
    
- 444 → todos leen.
    
- 400 → solo dueño lee.    

### Bits especiales

- **SUID** → 4xxx
    
- **SGID** → 2xxx
    
- **Sticky Bit** → 1xxx


## 3.3 CHOWN

- `chown usuario:grupo archivo`.
    
- `chown -R usuario:grupo carpeta` (recursivo).
    
- `chgrp grupo archivo` equivalente a `chown :grupo archivo`.

---

# 4. Gestión de usuarios y grupos

- **sudo** → ejecutar como root.
    
- **su** → cambiar de usuario.
    
- **useradd (-m)** → crear usuario (con HOME).
    
- **userdel** → borrar usuario.
    
- **usermod** → modificar usuario.
    
- **addgroup** / **delgroup**.
    
- **passwd** → cambiar contraseña.

### Administración práctica

Ver permisos sudo:

```
sudo -l
```

---

# 5. Gestión de paquetes

## 5.1 Debian/Ubuntu

- **dpkg** → bajo nivel.
    
- **apt** → repositorios.
    
- **snap** → contenedores de apps.
    
    - Nota: _inseguros y se rompen mucho._        

## 5.2 Lenguajes

- **gem** → Ruby
    
- **pip** → Python
    
- **git** → control de versiones    

---

# 6. Servicios y logs

## 6.1 systemd

- `systemctl start|status|stop servicio`.
    
- `systemctl enable servicio`. # Empieza al arranque del sistema
    
- `systemctl list-units --type=service`. # Mostrar todos los servicios
    
- **journalctl** → logs.

## 6.2 Señales a procesos

- `kill -l` → lista señales.
    

---

# 7. Almacenamiento

- `/etc/fstab` → configuración de particiones.
    
- `sudo fdisk -l` → inspección de discos.
    
- `mount` → ver montajes.
    
- NFS → carpetas compartidas, hay que montarlas manualmente (requiere `nfs-kernel-server`).
    
- **python server**: `python3 -m http.server 443`.
    
- **wget** → descarga.
    
- **curl** → transferencias HTTP/HTTPS/FTP/SFTP.
    
- **rsync / duplicity** → backups.

---

# 8. Docker

## 8.1 Ejemplo Dockerfile

```dockerfile
# Use the latest Ubuntu 22.04 LTS as the base image
FROM ubuntu:22.04

# Update the package repository and install the required packages
RUN apt-get update && \
    apt-get install -y \
        apache2 \
        openssh-server \
        && \
    rm -rf /var/lib/apt/lists/*

# Create a new user called "docker-user"
RUN useradd -m docker-user && \
    echo "docker-user:password" | chpasswd

# Configure permissions
RUN chown -R docker-user:docker-user /var/www/html && \
    chown -R docker-user:docker-user /var/run/apache2 && \
    chown -R docker-user:docker-user /var/log/apache2 && \
    chown -R docker-user:docker-user /var/lock/apache2 && \
    usermod -aG sudo docker-user && \
    echo "docker-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Expose ports
EXPOSE 22 80

# Start services
CMD service ssh start && /usr/sbin/apache2ctl -D FOREGROUND
```
Montarlo --> docker build -t
## 8.2 Comandos Docker

- `docker ps` 
     Listar contenedores activos
- `docker stop`
	 Parar un contenedor
- `docker start`
     Iniciar un contenedor
- `docker restart`
     Reiniciar un contenedor
- `docker rm`
	 Eliminar un contenedor
- `docker rmi`
     Eliminar una imagen
- `docker logs`.


## 8.3 LXC

Contenedores del kernel de Linux para entornos reproducibles.

---

# 9. Firewall

## 9.1 Conceptos

**Tables → Chains → Rules**

Reglas posibles:

- ACCEPT
    
- DROP
    
- REJECT
    
- LOG
    
- SNAT
    
- DNAT
    
- REDIRECT
    

## 9.2 iptables

Parámetros:

- `-p` protocolo
    
- `--dport` puerto destino
    
- `--sport` puerto origen
    
- `-s` IP origen
    
- `-m tcp|udp|string|mac`
    

Listar reglas:

```
sudo iptables -L -v
```

Eliminar regla:

```
sudo iptables -D numlinea
```

Ejemplo:

```
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```
[[Hardening]]

---

# 10. Logs importantes

- `/var/log/auth.log`
    
- `/var/log/syslog`
    
- `/var/log/mysql/mysql.log`
    
- `/var/log/journal/`
    
- `/var/log/apache2/access.log`
    
- `/var/log/fail2ban.log`
    
- `/var/log/ufw.log`
    

---

# 11. Shortcuts 

```
ctrl+a → inicio de línea
ctrl+e → final de línea
ctrl+u → borrar hasta el inicio
ctrl+k → borrar hasta el final
ctrl+w → borrar palabra previa
ctrl+y → pegar
ctrl+d → EOF
ctrl+c → SIGINT
alt+b → atrás una palabra
alt+f → adelante una palabra
```
