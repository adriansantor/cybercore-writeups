
# daemons
Un daemon es un proceso de sistema que se inicia durante el arranque, cuya función es ofrecer un servicio.
estos daemons suelen estar corriendo con root, y escuchan en sockets (/var/run/\*.sock) o en puertos TCP/UDP.

El error de seguridad se da cuando el daemon, proceso que ejecuta acciones como root, confía en órdenes que le dan usuarios que no deberían de tener esos permisos (caso docker).

```bash
ps aux | grep root
ls -l /var/run/*.sock
find / -type s 2>/dev/null
getent group
id
```

Con esos comandos podemos hacernos con un montón de información relacionada con procesos que se están ejecutando como root, sockets accesibles por usuarios no admin...

# sockets
Los sockets permiten comunicación entre procesos sin necesidad de una red.
No tienen autenticación por contraseña, roles, o ningún tipo de sandboxing. Si puedes abrir el archivo, hay total confianza. Los daemons se comunican por sockets, y los daemons corren como root. Poder acceder a un socket es poder acceder a root.

```bash
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
```


# id
El comando id muestra primero el uid, luego el gid y luego los identificadores del resto de grupos a los que pertenece un usuario. el comando `groups` nos dirá lo mismo
```uid=1000(izio) gid=1000(izio) grupos=1000(izio),108(vboxusers),953(ollama),984(video),993(input),998(wheel)```
puedes hacer id a otros usuarios también. 
La uid del usuario root es 0

Los grupos que más nos pueden interesar son 
`sudo/wheel` --> te deja ejecutar comandos como root teniendo la contraseña del usuario. 
`docker/lxd` --> docker y lxd funcionan prácticamente igual, montas contenedor que use tu disco y tienes root.
`dbus-daemon` --> acciones del sistema (dbus), reinicios, cambios de red, y en algunos casos acciones privilegiadas

--- 

`adm/shadow/journal` --> acceso a archivos privilegiados como /var/log/auth.log y /var/log/syslog
shadow te deja leer el /etc/shadow, donde están los hashes de las contraseñas de los usuarios
journal te deja ver los logs de systemd, que te puede mostrar variables de entorno, credenciales en servicios...

`disk/kmem` --> son más extraños de ver, pero te deja leer discos completos y montarlos, y kmem te deja acceder a la memoria del kernel, que es practicamente escalada directa

# env | set

muestra las variables de entorno. nos interesan cosas como SHELL, PATH, USER...
también se pueden almacenar aquí credenciales o otra información sensible

# sudo -l

este comando nos va a decir que comandos puede ejecutar el usuario actual con privilegios elevados, tal y como esté definido en /etc/sudoers y archivos incluidos /etc/sudoers.d/*
```bash
User user may run the following commands on host:
    (root) NOPASSWD: /usr/bin/vim
```
Esto nos dice que podemos ejecutar vim como root sin que nos pida la contraseña.

también podemos ejecutarlo sobre otro usuario del que tengamos credenciales con 
sudo -l -U user

Si encontramos un script o algo que podamos ejecutar como root, y ese script llama a un programa sin usar su ruta absoluta, podemos hacer path hijacking para que el script llame a lo que nosotros queramos.


# SUID y SGID

A parte de los 3 bits de permisos q ya conocemos, hay un cuerto, el bit SUID
Cuando un binario tiene el SUID activado, el proceso que se crea hereda los permisos del dueño. 
Es decir, si un binario cuyo dueño es root tiene el suid activado, ejecute quién ejecute el programa, se ejecuta como root. El SGID es lo mismo pero con el grupo en vez del usuario, bastante menos común.

```bash
find / -perm -4000 -type f 2>/dev/null
``` 

Si encontramos un script con SUID que llame a un programa sin su ruta absoluta, seguramente podamos hacer path hijacking.

# Path Hijacking

Por ejemplo, si un script hace `tar algo`, el sistema va a buscar en la variable PATH "tar"
si nosotros añadimos al PATH una carpeta que tenga un ejecutable "tar" que hayamos hecho nosotros, el script va a ejecutar como root el ejecutable que nosotros queremos.

PATH es una variable de entorno que podemos conocer con `echo $PATH`

para editar el PATH, simplemente podemos hacer 
`export PATH=/nuestraruta:$PATH`

Si en vez de un string es un binaro, podemos saber como trabaja con herramientas como `strings` 
o `strace`

# Capabilities
Las capabilities definen permisos de manera más granulada que root o no root. Se usan para dar privilegios de forma selectiva.
Para saber que capabilities tiene nuestra shell:
```bash
capsh --print
```

Y para saber que caps tienen binarios:
```bash
getcap -r / 2>/dev/null
```

Las más peligrosas son:
`CAP_SETUID/CAP_SETGID`
Le puedes cambiar el UID/GID del proceso a cualquiera, incluyendo 0
```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

`CAP_SYS_ADMIN`
Tener esta cap es prácticamente tener root también, aunque a veces puede dar muchas vueltas
Nos puede servir para montar un FS entero y entrar a él con chroot y ser root.

`CAP_DAC_OVERRIDE` 
Nos permite saltarnos permisos de rwx, que nos vale para saber hashes de contraseñas

`CAP_NET_ADMIN/CAP_NET_RAW`
La primera nos permite manipular interfaces y configurar iptables, nos vale para exfiltrar paquetes o métodos de persistencia avanzados. La segunda nos deja crear paquetes propios, y escuchar el tráfico completamente. Vale para pivoting en una red o intentar sniffear credenciales

`CAP_SYS_PTRACE`
Permite adjuntarse a procesos y leer/escribir su memoria
Por ejemplo, listamos procesos y filtramos por los de root
`ps aux | grep root`

Nos adjuntamos al proceso que nos interese
`gdb -p PID`

y nos llamamos una shell
`call system("/bin/bash")`

# CRON
un cronjob es una tarea que se ejecuta automáticamente cada x intervalo. Se puede ejecutar como root o otro usuario.
si el cron:
	corre como root
	ejecuta algo modificable
	no tiene bien configurado el PATH
	ejecuta binarios sin su ruta absoluta
	lee archivos que podemos controlar
	ejecuta código desde directorios world-writables (todos podemos escribir, /tmp)
peligro

```bash
ls -l /etc/cron*
```

Esto nos va a mostrar todos los cronjobs del sistema

Podemos hacerlo también con
```bash
crontab -u user -l
```

Por ejemplo, si cada 10 segundos cron ejecuta /opt/backup.sh, y nosotros podemos escribir en backup.sh, tenemos un script a nuestro gusto que root ejecuta todo el rato.