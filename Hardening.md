# Principios
## Principio del menor privilegio
- Cada proceso y usuario debe tener justamente los privilegios que necesita, ninguno más.

## Seguridad de servicios
- Los daemons son los primeros vectores de ataque. Un servicio innecesario escuchando en la red es un riesgo innecesario

## Control de acceso y permisos
- Un solo archivo con permisos 777 puede ser una puerta abierta

## Logs y monitoreo
- Lo que no se monitorea no se puede proteger --> journalctl, syslog

## Actualizaciones
- Un sistema desactualizado puede contener cves o exploits antiguos


# Metodología
1. Inventario
2. Reducir superficie
3. Configurar defensas
4. Monitorizar
5. Revisar

# Gestión de usuarios
## Conceptos
- **Mínimo privilegio** --> Usuarios solo con permisos necesarios
- **Separación de funciones** --> Diferentes roles para diferentes tareas
- **Accountability** --> Trazabilidad de acciones
- **Deshabilitar cuentsa innecesarias** --> Reducir superficie de ataque
- **Configurar sudo correctamente** --> Control granular de privilegios
- **Deshabilitar el login de root** --> Forzar uso de sudo para auditoría

# Listar y auditar usuarios

```bash
#Users con privilegios
cat /etc/passwd | grep -v nologin | grep -v false
```

```bash
#Usuarios con perms de root
sudo getent root
```

```bash
sudo passwd -l <user> # Bloquear
```



# Conceptos de seguridad
## SSH es el objetivo principal, escaneado constantemente por bots.
### Hardening SSH
1. Cambiar puerto 22
2. Deshabilitar autenticación por pswd
3. Usar solo claves (id_rsa)
4. Deshabilitar el login de root por ssh
5. Limitar usuarios permitidos (AllowUsers/AllowGroups)
6. Timeout de sesión (ClientAliveInterval)
7. Deshabilitar forwading innecesario

### Generación de pares:
``` bash
ssh-keygen -t ed25519 -f ~/.shh/id_secure -C "Comentario" 
```

# IPTables/UFW
## Cadenas:
 -- INPUT # Tráfico que entra
 -- OUTPUT # Tráfico que sale
 -- FORWARD # Tráfico que se redirige


# Auditoría
## Subsistema de auditoria -- auditd
### Ventajas
- Registros a nivel de kernel
- Granularidad extrema
- Compliance
- Análisis forense admisible como evidencia
- Detección de actividad anómala en tiempo real
### Usos
- Monitorear acceso a archivos críticos
- Rastrear comandos ejecutados con priv
- Detectar cambios y acciones usuarios
- Investigación de incidentes

```bash
auditctl -l # Listar todas las reglas

auditctl -w /ruta -p perms -k etiqueta # Crear reglas
```


# Docker
- **Contenedor** --> Máquina virtual ligera con aislamiento de procesos
- **Compartir kernel** --> A diferencia de VMs, comparten kernel del host
- **Riesgo principal** --> Escape de contenedor --> Compromiso del host
- **Vector de ataque primario** --> Imagen base insegura o desactualizada
- **Importancia** --> La seguridad del contenedor depende de la seguridad del host

SELinux && AppArmor && TCPWrappers (/etc/hosts.allow|hosts.deny)