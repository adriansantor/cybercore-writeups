El fuzzing es intentar descubrir directorios o archivos ocultos o no listados

Para ello necesitamos herramientas que hagan las solicitudes y diccionarios
Usaremos ffuf y gobuster, y los diccionarios de las seclists:
Discovery/Web-Content/common.txt o directory-list-2.3-medium.txt

Para ffuf le vamos a pasar el sitio donde queremos poner las palabras del diccionario con la palabra reservada FUZZ. le podemos pasar
	-e para indicarle extensiones de archivos: .php,.txt,.html,.bak
	-recursion para que fuzzee recursivamente
