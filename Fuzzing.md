---
description: Guía completa sobre técnicas de fuzzing web con ffuf y gobuster
---

# Web Fuzzing

## Introducción

El **fuzzing web** es una técnica de enumeración que consiste en descubrir recursos ocultos o no listados en aplicaciones web, tales como:

- Directorios y subdirectorios
- Archivos y scripts
- Parámetros GET/POST
- Virtual Hosts (VHosts)
- Subdominios
- Endpoints de APIs

Esta técnica es fundamental en las fases de reconocimiento y enumeración de un pentest web, permitiendo descubrir superficies de ataque que no son visibles mediante navegación normal.

## Herramientas y Diccionarios

### Herramientas Principales

- **ffuf** (Fuzz Faster U Fool): Herramienta de fuzzing web rápida y flexible escrita en Go
- **Gobuster**: Herramienta de fuerza bruta para URIs, DNS y VHosts (ver [Herramientas.md](Herramientas.md))
- **wfuzz**: Alternativa con funcionalidades avanzadas de filtrado

### Diccionarios Recomendados (SecLists)

```bash
# Diccionarios de contenido web general
/usr/share/seclists/Discovery/Web-Content/common.txt              # ~4,700 entradas
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  # ~220,000 entradas
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/Web-Content/big.txt

# Diccionarios de subdominios
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# Diccionarios de parámetros
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
/usr/share/seclists/Discovery/Web-Content/api/objects.txt
```

## Fuzzing Básico con ffuf

### Sintaxis Básica

ffuf utiliza la palabra clave **FUZZ** como marcador de posición para las entradas del diccionario.

```bash
ffuf -w <wordlist> -u <URL>
```

### Opciones Principales de ffuf

| Opción | Descripción | Ejemplo |
|--------|-------------|---------|
| `-w, --wordlist` | Especifica el diccionario a usar | `-w wordlist.txt` |
| `-u, --url` | URL objetivo (usa FUZZ como placeholder) | `-u http://target.com/FUZZ` |
| `-e, --extensions` | Extensiones de archivo a probar | `-e .php,.txt,.html,.bak` |
| `-recursion` | Habilita fuzzing recursivo | `-recursion` |
| `-recursion-depth` | Profundidad máxima de recursión | `-recursion-depth 2` |
| `-rate` | Limita peticiones por segundo | `-rate 100` |
| `-t, --threads` | Número de hilos concurrentes | `-t 50` |
| `-timeout` | Timeout de conexión en segundos | `-timeout 10` |

### Filtros de Respuesta

| Opción | Descripción                          | Ejemplo           |
| ------ | ------------------------------------ | ----------------- |
| `-fc`  | Filtrar por código de estado HTTP    | `-fc 404,403`     |
| `-mc`  | Mostrar solo estos códigos de estado | `-mc 200,301,302` |
| `-fs`  | Filtrar por tamaño de respuesta      | `-fs 4242`        |
| `-ms`  | Mostrar solo estos tamaños           | `-ms 1234`        |
| `-fw`  | Filtrar por número de palabras       | `-fw 97`          |
| `-mw`  | Mostrar solo este número de palabras | `-mw 100`         |
| `-fl`  | Filtrar por número de líneas         | `-fl 30`          |
| `-ml`  | Mostrar solo este número de líneas   | `-ml 50`          |
| `-fr`  | Filtrar por regexp                   | `-fr "error"`     |
| `-mr`  | Mostrar solo regexp                  | `-mr "admin"`     |

### Ejemplo 1: Fuzzing de Directorios

```bash
# Fuzzing básico de directorios
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://example.com/FUZZ \
     -mc 200,301,302,403
```

### Ejemplo 2: Fuzzing con Extensiones

```bash
# Buscar archivos con múltiples extensiones
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
     -u http://example.com/FUZZ \
     -e .php,.txt,.html,.bak,.old,.zip \
     -mc 200 \
     -fc 404
```

### Ejemplo 3: Filtrado por Tamaño

```bash
# Filtrar respuestas por tamaño (útil cuando todas devuelven 200)
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
     -u http://example.com/FUZZ \
     -fs 1234 \
     -mc 200
```

## Fuzzing Recursivo

El fuzzing recursivo ejecuta el fuzzing sobre el directorio raíz indicado y crea automáticamente nuevas ramas de fuzzing por cada resultado positivo encontrado. Es útil para mapear completamente la estructura de directorios de una aplicación web.

### Conceptos Clave

- **Profundidad de recursión**: Niveles de directorios anidados a explorar
- **Rate limiting**: Control de velocidad de peticiones para evitar sobrecarga del servidor
- **Timeout**: Tiempo máximo de espera por respuesta

### Ejemplo 1: Fuzzing Recursivo Básico

```bash
# Fuzzing recursivo con profundidad máxima de 2 niveles
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u http://example.com/FUZZ \
     -recursion \
     -recursion-depth 2 \
     -e .php,.html \
     -v
```

### Ejemplo 2: Fuzzing Recursivo con Control de Velocidad

```bash
# Fuzzing recursivo limitando a 50 peticiones/segundo
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://example.com/FUZZ \
     -recursion \
     -recursion-depth 3 \
     -rate 50 \
     -timeout 10 \
     -mc 200,301,302,403 \
     -fc 404
```

### Ejemplo 3: Fuzzing Recursivo con Filtrado Avanzado

```bash
# Fuzzing recursivo filtrando respuestas repetidas
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
     -u http://example.com/FUZZ \
     -recursion \
     -recursion-depth 2 \
     -e .php,.asp,.aspx,.jsp \
     -mc 200,301,302 \
     -fs 0 \
     -fw 1 \
     -v \
     -o output.json \
     -of json
```


## Fuzzing de Parámetros

### Parámetros GET

Los parámetros GET se pasan a través de la URL y son visibles en la barra de direcciones del navegador. Se utilizan principalmente para acciones que no modifican el estado del servidor (operaciones de lectura).

**Estructura de una URL con parámetros GET:**
```
https://example.com/search?query=fuzzing&category=security&page=1
```

En este ejemplo:
- `query`, `category` y `page` son parámetros GET
- Se separan del path con `?`
- Se separan entre sí con `&`
- Formato: `nombre=valor`

#### Ejemplo 1: Fuzzing de Nombres de Parámetros GET

```bash
# Descubrir parámetros GET válidos
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u "http://example.com/search.php?FUZZ=test" \
     -mc 200 \
     -fw 0 \
     -v
```

También se puede probar a hacer una petición GET, y si requiere algún parámetro, dará error.
#### Ejemplo 2: Fuzzing de Valores de Parámetros GET

```bash
# Probar diferentes valores en un parámetro conocido
ffuf -w /usr/share/seclists/Fuzzing/special-chars.txt \
     -u "http://example.com/user.php?id=FUZZ" \
     -mc 200 \
     -fs 1234

# Probar IDs numéricos secuenciales (IDOR testing)
ffuf -w <(seq 1 1000) \
     -u "http://example.com/user.php?id=FUZZ" \
     -mc 200 \
     -v
```

#### Ejemplo 3: Fuzzing de Múltiples Parámetros

```bash
# Usar múltiples wordlists simultáneamente
ffuf -w params.txt:PARAM -w values.txt:VAL \
     -u "http://example.com/api?PARAM=VAL" \
     -mc 200 \
     -v

# Fuzzing con parámetros múltiples en la URL
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u "http://example.com/search.php?query=admin&FUZZ=1" \
     -mc 200 \
     -fr "error|invalid"
```

### Parámetros POST

Los parámetros POST no son visibles en la URL y se envían en el cuerpo de la petición HTTP. Se utilizan para operaciones que modifican el estado del servidor (crear, actualizar, eliminar) y para transmitir información sensible como credenciales.

#### Proceso de una Petición POST

1. **Codificación**: Los datos se codifican según el Content-Type
   - `application/x-www-form-urlencoded`: Parámetros separados por `&` (por defecto)
   - `multipart/form-data`: Para formularios con archivos adjuntos
   - `application/json`: Para APIs RESTful

2. **HTTP Request**: Los datos codificados se envían en el cuerpo de la petición

3. **Server-side Processing**: El servidor decodifica y procesa la petición

**Ejemplo de petición POST:**
```http
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 45

username=admin&password=secretpass123
```

#### Ejemplo 1: Fuzzing de Parámetros POST (application/x-www-form-urlencoded)

```bash
# Descubrir parámetros POST válidos
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u http://example.com/login.php \
     -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=admin&FUZZ=test" \
     -mc 200,302 \
     -fr "invalid|error"
```

#### Ejemplo 2: Fuzzing de Valores POST

```bash
# Fuzzing de valores de password con diccionario
ffuf -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt \
     -u http://example.com/login.php \
     -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=admin&password=FUZZ" \
     -mc 302 \
     -fr "incorrect|invalid"
```

#### Ejemplo 3: Fuzzing de APIs con JSON

```bash
# Fuzzing de parámetros en API REST con JSON
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
     -u http://example.com/api/v1/users \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"FUZZ":"testvalue","action":"create"}' \
     -mc 200,201 \
     -v

# Fuzzing de valores en JSON
ffuf -w usernames.txt \
     -u http://example.com/api/v1/users \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"username":"FUZZ","role":"admin"}' \
     -mc 200,201,403 \
     -v
```

#### Ejemplo 4: Fuzzing Multipart (File Upload)

```bash
# Fuzzing de nombres de campo en upload de archivos
ffuf -w fieldnames.txt \
     -u http://example.com/upload.php \
     -X POST \
     -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary" \
     -d $'------WebKitFormBoundary\r\nContent-Disposition: form-data; name="FUZZ"; filename="test.txt"\r\n\r\ntest\r\n------WebKitFormBoundary--' \
     -mc 200,302 \
     -v
```

### Herramientas Complementarias

**wenum** es un wrapper de ffuf especializado en fuzzing de parámetros GET, simplificando la sintaxis:

```bash
# Con wenum (simplificado)
wenum -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
      -u "http://example.com/search.php" \
      --hc 404

# Equivalente con ffuf
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u "http://example.com/search.php?FUZZ=test" \
     -fc 404
```

### Casos de Uso y Vulnerabilidades

Manipular parámetros HTTP puede exponer diversas vulnerabilidades:

- **IDOR (Insecure Direct Object Reference)**: Acceso no autorizado modificando IDs
- **Privilege Escalation**: Parámetros ocultos como `role=admin` o `is_admin=true`
- **SQL Injection**: Parámetros sin validación adecuada
- **Command Injection**: Parámetros ejecutados en el sistema
- **SSRF (Server-Side Request Forgery)**: Parámetros de URL internas


## Virtual Hosts (VHosts) y Subdominios

### Virtual Hosts (VHosts)

Los Virtual Hosts permiten alojar múltiples sitios web (dominios/subdominios) en una misma dirección IP. El servidor web determina qué sitio servir analizando la cabecera HTTP `Host`.

**Funcionamiento:**
1. Cliente envía petición HTTP con cabecera `Host: subdomain.example.com`
2. Servidor web (Apache/Nginx) comprueba configuración de VHosts
3. Sirve el contenido correspondiente al VHost configurado

**Configuración típica de VHost (Apache):**
```apache
<VirtualHost *:80>
    ServerName admin.example.com
    DocumentRoot /var/www/admin
</VirtualHost>

<VirtualHost *:80>
    ServerName dev.example.com
    DocumentRoot /var/www/dev
</VirtualHost>
```

### Fuzzing de Virtual Hosts con ffuf

#### Ejemplo 1: Fuzzing Básico de VHosts

```bash
# Fuzzing de VHosts mediante cabecera Host
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://example.com \
     -H "Host: FUZZ.example.com" \
     -mc 200,301,302,403 \
     -fs 1234
```
#### Ejemplo 2 VHost Fuzzing con IP Directa

```bash
# Cuando solo tienes la IP pero no el dominio
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://192.168.1.100 \
     -H "Host: FUZZ.target.local" \
     -mc all \
     -fc 404 \
     -fl 0 \
     -v
```

### Fuzzing de Virtual Hosts con Gobuster

```bash
# Gobuster en modo vhost
gobuster vhost \
    -u http://example.com \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    --append-domain \
    -t 50

# --append-domain: Añade automáticamente el dominio base
# Sin --append-domain (para VHosts sin dominio padre)
gobuster vhost \
    -u http://example.com \
    -w vhosts.txt \
    -t 50
```

### Fuzzing de Subdominios

Los subdominios son divisiones lógicas de un dominio principal que pueden apuntar a diferentes IPs o servicios.

**Diferencia VHost vs Subdominio:**
- **VHost**: Múltiples dominios en la misma IP (configuración de servidor web)
- **Subdominio**: Entrada DNS que puede apuntar a cualquier IP

#### Ejemplo 1: Fuzzing de Subdominios con ffuf

```bash
# Fuzzing de subdominios mediante resolución DNS
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
     -u http://FUZZ.example.com \
     -mc 200,301,302 \
     -v
```

#### Ejemplo 2: Subdomain Fuzzing con Verificación DNS

```bash
# Fuzzing con salida detallada para ver IPs
ffuf -w /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt \
     -u http://FUZZ.example.com \
     -mc all \
     -ac \
     -v \
     -o subdomain-results.json \
     -of json
```

#### Ejemplo 3: Fuzzing de Subdominios con Gobuster (DNS Mode)

```bash
# Gobuster en modo DNS (más eficiente para subdominios)
gobuster dns \
    -d example.com \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -t 50 \
    -i
```

#### Ejemplo 4: Fuzzing con Permutaciones

```bash
# Crear permutaciones de subdominios conocidos
ffuf -w <(echo -e "dev\nstaging\ntest\nprod\nuat") \
     -u http://FUZZ-app.example.com \
     -mc 200,301,302 \
     -v
```

### Técnicas Avanzadas

#### Combinación de Wordlists

```bash
# Combinar múltiples diccionarios
cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt | \
    sort -u > combined-subdomains.txt

ffuf -w combined-subdomains.txt \
     -u http://FUZZ.example.com \
     -mc 200,301,302,403 \
     -v
```

#### Fuzzing con Resolución DNS Personalizada

```bash
# Usar servidor DNS específico (útil en redes internas)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://FUZZ.internal.company.local \
     -mc 200 \
     -v \
     -dns-server 10.10.10.1
```

### Herramientas Complementarias

**Filtrado de Gobuster por Códigos de Estado:**

```bash
# Incluir solo ciertos códigos
gobuster vhost \
    -u http://example.com \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    --append-domain \
    -s 200,301,302 \
    -t 50

# Excluir códigos específicos
gobuster vhost \
    -u http://example.com \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    --append-domain \
    -b 404,403 \
    -t 50

# -s (--status-codes): Incluir estos códigos
# -b (--exclude-status-codes): Excluir estos códigos
``` 


## Validación de Resultados

Después de ejecutar fuzzing, es crucial validar los resultados para:

1. **Confirmar vulnerabilidades**: Verificar que los hallazgos son explotables
2. **Eliminar falsos positivos**: Descartar resultados que no son relevantes
3. **Demostrar reproducibilidad**: Probar que el hallazgo es consistente
4. **Documentar evidencias**: Preparar pruebas para informes

### Técnicas de Validación

#### 1. Verificación Manual con curl

```bash
# Verificar un directorio encontrado
curl -i http://example.com/admin/

# Verificar con diferentes métodos HTTP
curl -i -X GET http://example.com/admin/
curl -i -X POST http://example.com/admin/
curl -i -X OPTIONS http://example.com/admin/

# Verificar parámetro encontrado
curl -i "http://example.com/search.php?debug=true"

# Verificar VHost encontrado
curl -i -H "Host: admin.example.com" http://example.com/
```

#### 2. Análisis de Respuestas

```bash
# Verificar con verbose para ver headers completos
ffuf -w found-paths.txt \
     -u http://example.com/FUZZ \
     -mc 200 \
     -v \
     | tee validation-results.txt

# Buscar patrones específicos en las respuestas
ffuf -w wordlist.txt \
     -u http://example.com/FUZZ \
     -mc 200 \
     -mr "admin|dashboard|login|password" \
     -v
```

#### 3. Comparación de Respuestas

```bash
# Guardar respuesta de referencia
curl http://example.com/notfound > baseline.html

# Comparar con hallazgos
curl http://example.com/admin/ > result.html
diff baseline.html result.html

# Verificar tamaños diferentes
curl -s http://example.com/admin/ | wc -c
curl -s http://example.com/notfound | wc -c
```

#### 4. Prueba de Funcionalidad

- Acceder a recursos encontrados mediante navegador
- Verificar si requieren autenticación
- Intentar interactuar con formularios o APIs
- Buscar información sensible expuesta
- Comprobar permisos y controles de acceso

### Checklist de Validación

- [ ] **Accesibilidad**: ¿El recurso es realmente accesible?
- [ ] **Autenticación**: ¿Requiere autenticación o es público?
- [ ] **Contenido**: ¿Contiene información útil o sensible?
- [ ] **Funcionalidad**: ¿Es funcional o está en desarrollo?
- [ ] **Permisos**: ¿Qué acciones se pueden realizar?
- [ ] **Reproducibilidad**: ¿Es consistente en múltiples pruebas?

### Ejemplo de Flujo de Validación

```bash
# 1. Ejecutar fuzzing inicial
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://example.com/FUZZ \
     -mc 200,301,302,403 \
     -o initial-results.json \
     -of json

# 2. Extraer solo los paths encontrados
cat initial-results.json | jq -r '.results[].url' > found-urls.txt

# 3. Validar cada URL manualmente
while read url; do
    echo "Testing: $url"

# -s (--status-codes): Incluir estos códigos
# -b (--exclude-status-codes): Excluir estos códigos    curl -i -s "$url" | head -20
    echo "---"
done < found-urls.txt

# 4. Verificar con diferentes User-Agents
ffuf -w found-urls.txt \
     -u FUZZ \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
     -mc 200 \
     -v
``` 


## Fuzzing de Web APIs

Las APIs web modernas son superficies de ataque críticas que requieren fuzzing especializado. Las APIs exponen funcionalidad de backend y suelen manejar datos sensibles.

### Tipos de APIs

#### 1. REST APIs (Representational State Transfer)

**Características:**
- Usan métodos HTTP estándar (GET, POST, PUT, DELETE, PATCH)
- Operaciones CRUD (Create, Read, Update, Delete)
- Recursos identificados por URLs
- Respuestas típicamente en JSON o XML

**Estructura típica de una REST API:**
```
GET    /api/v1/users           # Listar usuarios
GET    /api/v1/users/123       # Obtener usuario específico
POST   /api/v1/users           # Crear usuario
PUT    /api/v1/users/123       # Actualizar usuario completo
PATCH  /api/v1/users/123       # Actualizar usuario parcialmente
DELETE /api/v1/users/123       # Eliminar usuario
```

#### 2. GraphQL APIs

**Características:**
- Single endpoint (típicamente `/graphql`)
- Query language flexible
- Cliente especifica exactamente qué datos necesita
- Introspección del schema

**Estructura típica:**
```graphql
# Query
query {
  user(id: 123) {
    name
    email
    posts {
      title
    }
  }
}

# Mutation
mutation {
  createUser(name: "John", email: "john@example.com") {
    id
    name
  }
}
```

#### 3. SOAP APIs

**Características:**
- Basadas en XML
- Protocolo más estricto y formal
- WSDL (Web Services Description Language) para definición

### Tipos de Fuzzing en APIs

#### 1. Fuzzing de Parámetros

Probar valores edge cases, inesperados o inválidos para exponer vulnerabilidades.

**Ejemplo 1: Fuzzing de Endpoints REST**

```bash
# Descubrir endpoints de API REST
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
     -u http://example.com/api/v1/FUZZ \
     -mc 200,201,400,401,403,405 \
     -v
```

**Ejemplo 2: Fuzzing de Versiones de API**

```bash
# Descubrir versiones de API
ffuf -w <(seq 1 10) \
     -u http://example.com/api/vFUZZ/users \
     -mc 200,301,302 \
     -v

# Probar diferentes formatos de versionado
ffuf -w versions.txt \
     -u http://example.com/api/FUZZ/users \
     -mc 200,301,302 \
     -v
```

**Ejemplo 3: Fuzzing de IDs de Recursos (IDOR Testing)**

```bash
# Probar IDs numéricos secuenciales
ffuf -w <(seq 1 1000) \
     -u http://example.com/api/v1/users/FUZZ \
     -mc 200 \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -v

# Probar UUIDs o hashes comunes
ffuf -w uuid-wordlist.txt \
     -u http://example.com/api/v1/users/FUZZ \
     -mc 200 \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -v
```

**Ejemplo 4: Fuzzing de Valores en Parámetros JSON**

```bash
# Fuzzing de valores en API JSON
ffuf -w /usr/share/seclists/Fuzzing/special-chars.txt \
     -u http://example.com/api/v1/search \
     -X POST \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -d '{"query":"FUZZ","limit":10}' \
     -mc 200,400,500 \
     -v

# Fuzzing de privilegios
ffuf -w roles.txt \
     -u http://example.com/api/v1/users/123 \
     -X PATCH \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -d '{"role":"FUZZ"}' \
     -mc 200,403 \
     -v

# roles.txt contiene:
# user
# admin
# superadmin
# root
# moderator
```

#### 2. Fuzzing de Formato

Probar diferentes formatos de datos para identificar problemas de parsing.

**Ejemplo 1: Fuzzing de Content-Type**

```bash
# Probar diferentes Content-Types
ffuf -w content-types.txt \
     -u http://example.com/api/v1/users \
     -X POST \
     -H "Content-Type: FUZZ" \
     -d '{"name":"test","email":"test@test.com"}' \
     -mc 200,201,400,415 \
     -v

# content-types.txt contiene:
# application/json
# application/xml
# text/xml
# application/x-www-form-urlencoded
# multipart/form-data
# text/plain
# application/yaml
```

**Ejemplo 2: Fuzzing de Formatos de Datos**

```bash
# Probar inyección XML en API JSON
ffuf -w /usr/share/seclists/Fuzzing/XXE-Fuzzing.txt \
     -u http://example.com/api/v1/import \
     -X POST \
     -H "Content-Type: application/xml" \
     -d "FUZZ" \
     -mc all \
     -v

# Probar payload JSON malformado
ffuf -w json-payloads.txt \
     -u http://example.com/api/v1/users \
     -X POST \
     -H "Content-Type: application/json" \
     -d "FUZZ" \
     -mc all \
     -v
```

#### 3. Fuzzing de Secuencias (Race Conditions)

Enviar secuencias de requests para encontrar vulnerabilidades de lógica o race conditions.

**Ejemplo 1: Detección de Race Conditions**

```bash
# race-condition-test.sh
#!/bin/bash
URL="http://example.com/api/v1/transfer"
TOKEN="YOUR_TOKEN"

for i in {1..10}; do
    curl -X POST "$URL" \
         -H "Content-Type: application/json" \
         -H "Authorization: Bearer $TOKEN" \
         -d '{"from":"account1","to":"account2","amount":100}' &
done
wait

# Ejecutar con ffuf en modo parallel
seq 1 100 | xargs -P 50 -I {} \
    curl -s -X POST "http://example.com/api/v1/coupon" \
         -H "Content-Type: application/json" \
         -H "Authorization: Bearer YOUR_TOKEN" \
         -d '{"code":"DISCOUNT50"}'
```

**Ejemplo 2: Fuzzing de Secuencias de Operaciones**

```bash
# Probar secuencias de operaciones en orden diferente
# 1. Crear recurso
curl -X POST http://example.com/api/v1/orders \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer TOKEN" \
     -d '{"item":"product1","qty":1}'

# 2. Intentar pagar antes de confirmar
curl -X POST http://example.com/api/v1/orders/123/pay \
     -H "Authorization: Bearer TOKEN"

# 3. Intentar cancelar después de pagar
curl -X DELETE http://example.com/api/v1/orders/123 \
     -H "Authorization: Bearer TOKEN"
```

#### 4. Fuzzing de Métodos HTTP

**Ejemplo 1: Descubrir Métodos HTTP Permitidos**

```bash
# Probar todos los métodos HTTP
for method in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE CONNECT; do
    echo "Testing $method:"
    curl -i -X $method http://example.com/api/v1/users/123
    echo "---"
done

# Con ffuf
ffuf -w http-methods.txt \
     -u http://example.com/api/v1/users/123 \
     -X FUZZ \
     -mc all \
     -v

# http-methods.txt:
# GET
# POST
# PUT
# DELETE
# PATCH
# OPTIONS
# HEAD
```

**Ejemplo 2: Explotar Métodos No Seguros**

```bash
# Intentar modificar recurso con PUT sin autenticación
ffuf -w <(seq 1 100) \
     -u http://example.com/api/v1/users/FUZZ \
     -X PUT \
     -H "Content-Type: application/json" \
     -d '{"role":"admin"}' \
     -mc 200,204 \
     -v
```

### Fuzzing de GraphQL

**Ejemplo 1: Introspección de GraphQL Schema**

```bash
# Query de introspección
curl -X POST http://example.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{ __schema { types { name } } }"}' \
     | jq .

# Fuzzing de queries GraphQL
ffuf -w graphql-queries.txt \
     -u http://example.com/graphql \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"query":"FUZZ"}' \
     -mc 200 \
     -fr "error" \
     -v
```

**Ejemplo 2: Fuzzing de GraphQL Mutations**

```bash
# Probar diferentes mutations
ffuf -w mutation-names.txt \
     -u http://example.com/graphql \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"query":"mutation { FUZZ(id: 1, role: \"admin\") { id role } }"}' \
     -mc 200 \
     -v
```

### Fuzzing Avanzado de APIs

**Ejemplo 1: Fuzzing con Autenticación JWT**

```bash
# Obtener token JWT
TOKEN=$(curl -X POST http://example.com/api/v1/login \
             -H "Content-Type: application/json" \
             -d '{"username":"testuser","password":"testpass"}' \
             | jq -r '.token')

# Fuzzing con token
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
     -u http://example.com/api/v1/FUZZ \
     -H "Authorization: Bearer $TOKEN" \
     -mc 200,201,400,401,403 \
     -v

# Probar manipulación de JWT
ffuf -w jwt-payloads.txt \
     -u http://example.com/api/v1/admin/users \
     -H "Authorization: Bearer FUZZ" \
     -mc 200,403 \
     -v
```

**Ejemplo 2: Fuzzing de SSRF en APIs**

```bash
# Probar parámetros de URL para SSRF
ffuf -w ssrf-payloads.txt \
     -u http://example.com/api/v1/fetch \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"url":"FUZZ"}' \
     -mc 200,500 \
     -v

# ssrf-payloads.txt incluye:
# http://localhost:80
# http://127.0.0.1:80
# http://169.254.169.254/latest/meta-data/
# http://internal.company.local
# file:///etc/passwd
```

**Ejemplo 3: Mass Assignment Testing**

```bash
# Intentar inyectar campos adicionales
ffuf -w object-properties.txt \
     -u http://example.com/api/v1/users/123 \
     -X PATCH \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer TOKEN" \
     -d '{"FUZZ":"admin"}' \
     -mc 200,400 \
     -v

# object-properties.txt:
# role
# is_admin
# permissions
# privilege
# admin
# superuser
```

### Vulnerabilidades Comunes en APIs

- **Broken Object Level Authorization (BOLA/IDOR)**: Acceso a recursos de otros usuarios
- **Broken Authentication**: Tokens débiles o mal implementados
- **Excessive Data Exposure**: API devuelve más datos de los necesarios
- **Lack of Resources & Rate Limiting**: Sin limitación de peticiones
- **Broken Function Level Authorization**: Acceso a funciones privilegiadas
- **Mass Assignment**: Asignar campos no autorizados
- **Security Misconfiguration**: Configuraciones por defecto, debug habilitado
- **Injection**: SQL, NoSQL, Command injection
- **Improper Assets Management**: Versiones antiguas de API expuestas
- **Insufficient Logging & Monitoring**: Actividad maliciosa no detectada

### Herramientas Especializadas para APIs

```bash
# Arjun - Descubridor de parámetros HTTP
arjun -u http://example.com/api/v1/users

# Kiterunner - Scanner de APIs
kr scan http://example.com -w routes-large.kite

# Postman/Newman - Testing automatizado
newman run api-collection.json -e environment.json

# GraphQL Voyager - Visualizar schema
```

## Mejores Prácticas

### 1. Optimización de Performance

#### Ajuste de Hilos y Rate Limiting

```bash
# Configuración conservadora (servidores lentos o WAF presente)
ffuf -w wordlist.txt \
     -u http://example.com/FUZZ \
     -t 10 \
     -rate 20 \
     -timeout 15 \
     -mc 200

# Configuración agresiva (servidores rápidos, red local)
ffuf -w wordlist.txt \
     -u http://example.com/FUZZ \
     -t 100 \
     -rate 500 \
     -timeout 5 \
     -mc 200

# Configuración balanceada
ffuf -w wordlist.txt \
     -u http://example.com/FUZZ \
     -t 40 \
     -rate 100 \
     -timeout 10 \
     -mc 200
```

#### Selección de Diccionarios

```bash
# Fase de reconocimiento inicial - Diccionario pequeño y rápido
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://example.com/FUZZ \
     -mc 200,301,302,403

# Fase de enumeración profunda - Diccionario medio
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u http://example.com/FUZZ \
     -mc 200,301,302,403

# Fase exhaustiva - Diccionario grande (solo si es necesario)
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt \
     -u http://example.com/FUZZ \
     -mc 200,301,302,403
```

### 2. Evasión de WAF y Detección

#### Técnicas de Evasión

```bash
# Usar User-Agent personalizado
ffuf -w wordlist.txt \
     -u http://example.com/FUZZ \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
     -mc 200

# Añadir headers comunes para parecer tráfico legítimo
ffuf -w wordlist.txt \
     -u http://example.com/FUZZ \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
     -H "Accept: text/html,application/xhtml+xml,application/xml" \
     -H "Accept-Language: en-US,en;q=0.9" \
     -H "Accept-Encoding: gzip, deflate" \
     -H "Connection: keep-alive" \
     -mc 200

# Limitar velocidad para evitar detección
ffuf -w wordlist.txt \
     -u http://example.com/FUZZ \
     -rate 10 \
     -p 0.5-1.5 \
     -mc 200

# -p 0.5-1.5: Añade delay aleatorio entre 0.5 y 1.5 segundos
```

#### Rotación de User-Agents

```bash
# Crear archivo con múltiples User-Agents
cat > user-agents.txt << 'EOF'
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15
EOF

# Usar con ffuf (requiere script wrapper)
while read ua; do
    ffuf -w small-wordlist.txt \
         -u http://example.com/FUZZ \
         -H "User-Agent: $ua" \
         -mc 200
done < user-agents.txt
```

### 3. Gestión de Resultados

#### Guardar y Procesar Resultados

```bash
# Guardar en múltiples formatos
ffuf -w wordlist.txt \
     -u http://example.com/FUZZ \
     -mc 200,301,302,403 \
     -o results.json \
     -of json

# Formato HTML para visualización
ffuf -w wordlist.txt \
     -u http://example.com/FUZZ \
     -mc 200,301,302,403 \
     -o results.html \
     -of html

# Exportar solo URLs encontradas
ffuf -w wordlist.txt \
     -u http://example.com/FUZZ \
     -mc 200 \
     -o results.json \
     -of json

cat results.json | jq -r '.results[].url' > found-urls.txt

# Exportar con detalles adicionales
cat results.json | jq -r '.results[] | "\(.url) [\(.status)] Size:\(.length)"' > detailed-results.txt
```

#### Filtrado Inteligente

```bash
# Auto-calibración (ffuf decide qué filtrar automáticamente)
ffuf -w wordlist.txt \
     -u http://example.com/FUZZ \
     -ac \
     -v

# Filtrado por múltiples criterios
ffuf -w wordlist.txt \
     -u http://example.com/FUZZ \
     -mc 200,301,302 \
     -fs 1234,5678 \
     -fw 42,97 \
     -fr "error|not found|404" \
     -v

# Usar modo silencioso para respuestas específicas
ffuf -w wordlist.txt \
     -u http://example.com/FUZZ \
     -mc 200 \
     -ms 1000-5000 \
     -s

# -s: Modo silencioso, solo imprime resultados encontrados
```

### 4. Estrategias de Fuzzing

#### Approach Incremental

```bash
# 1. Reconocimiento rápido (2-5 minutos)
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://example.com/FUZZ \
     -mc 200,301,302,403 \
     -t 50

# 2. Si se encuentran resultados interesantes, profundizar
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u http://example.com/FUZZ \
     -mc 200,301,302,403 \
     -t 40

# 3. Fuzzing recursivo en paths encontrados
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
     -u http://example.com/admin/FUZZ \
     -e .php,.txt,.html,.bak \
     -mc 200 \
     -t 40

# 4. Fuzzing de parámetros en endpoints descubiertos
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u "http://example.com/admin/panel.php?FUZZ=test" \
     -mc 200 \
     -fw 0
```

#### Fuzzing por Tecnología

```bash
# Para aplicaciones PHP
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://example.com/FUZZ \
     -e .php,.phps,.php3,.php4,.php5,.phtml,.inc \
     -mc 200,403

# Para aplicaciones ASP.NET
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://example.com/FUZZ \
     -e .asp,.aspx,.asmx,.ashx,.config \
     -mc 200,403

# Para aplicaciones Java
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://example.com/FUZZ \
     -e .jsp,.jspx,.jsf,.do,.action \
     -mc 200,403

# Para aplicaciones Node.js/JavaScript
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://example.com/FUZZ \
     -e .js,.json,.node \
     -mc 200,403
```

### Cuándo Usar Cada Herramienta

**ffuf**: 
- Fuzzing complejo con múltiples parámetros
- APIs y peticiones POST/PUT/DELETE
- Necesitas filtrado avanzado
- Fuzzing de headers, cookies, POST data

**Gobuster**:
- Fuzzing simple y rápido de directorios
- Enumeración de subdominios (modo DNS)
- Descubrimiento de VHosts
- Cuando quieres sintaxis simple

**Feroxbuster**:
- Fuzzing recursivo automático
- Cuando quieres configuración mínima
- Detección automática de wildcards

### Scripts Útiles

#### Script de Fuzzing Automatizado

```bash
#!/bin/bash
# auto-fuzz.sh - Script de fuzzing automatizado

TARGET=$1
OUTPUT_DIR="fuzzing-results-$(date +%Y%m%d-%H%M%S)"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-url>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[+] Starting directory fuzzing..."
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u "$TARGET/FUZZ" \
     -mc 200,301,302,403 \
     -o "$OUTPUT_DIR/directories.json" \
     -of json

echo "[+] Starting file fuzzing..."
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
     -u "$TARGET/FUZZ" \
     -e .php,.txt,.html,.bak,.old \
     -mc 200 \
     -o "$OUTPUT_DIR/files.json" \
     -of json

echo "[+] Starting VHost fuzzing..."
DOMAIN=$(echo "$TARGET" | sed -e 's|^https://||' -e 's|^http://||' -e 's|/.*||')
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u "$TARGET" \
     -H "Host: FUZZ.$DOMAIN" \
     -mc 200,301,302 \
     -o "$OUTPUT_DIR/vhosts.json" \
     -of json

echo "[+] Results saved to $OUTPUT_DIR"
cat "$OUTPUT_DIR/directories.json" | jq -r '.results[].url' | tee "$OUTPUT_DIR/found-urls.txt"
```

#### Script de Validación de Resultados

```bash
#!/bin/bash
# validate-results.sh - Validar resultados de fuzzing

URLS_FILE=$1

if [ -z "$URLS_FILE" ]; then
    echo "Usage: $0 <urls-file>"
    exit 1
fi

while read url; do
    echo "=== Testing: $url ==="
    
    # Comprobar código de estado
    status=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    echo "Status: $status"
    
    # Comprobar tamaño
    size=$(curl -s "$url" | wc -c)
    echo "Size: $size bytes"
    
    # Buscar palabras clave interesantes
    content=$(curl -s "$url")
    echo "Keywords found:"
    echo "$content" | grep -iE "admin|password|login|key|token|secret|config" | head -3
    
    echo "---"
done < "$URLS_FILE"
```

### Referencias y Documentación

- **ffuf GitHub**: https://github.com/ffuf/ffuf
- **Gobuster GitHub**: https://github.com/OJ/gobuster
- **SecLists**: https://github.com/danielmiessler/SecLists
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **HackTricks - Web Fuzzing**: https://book.hacktricks.xyz/pentesting-web/web-tool-ffuf
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings

## Resumen de Comandos Rápidos

```bash
# Fuzzing básico de directorios
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://target.com/FUZZ -mc 200,301,302,403

# Fuzzing con extensiones
ffuf -w wordlist.txt -u http://target.com/FUZZ -e .php,.txt,.html,.bak -mc 200

# Fuzzing recursivo
ffuf -w wordlist.txt -u http://target.com/FUZZ -recursion -recursion-depth 2 -mc 200,301,302

# Fuzzing de parámetros GET
ffuf -w params.txt -u "http://target.com/page.php?FUZZ=test" -mc 200 -fw 0

# Fuzzing de parámetros POST
ffuf -w params.txt -u http://target.com/login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&FUZZ=test" -mc 200,302

# Fuzzing de VHosts
ffuf -w subdomains.txt -u http://target.com -H "Host: FUZZ.target.com" -mc 200 -fs 1234

# Fuzzing de subdominios
gobuster dns -d target.com -w subdomains.txt -t 50

# Fuzzing de API
ffuf -w objects.txt -u http://target.com/api/v1/FUZZ -mc 200,201,400,401,403

# Auto-calibración (filtrado automático)
ffuf -w wordlist.txt -u http://target.com/FUZZ -ac
```

