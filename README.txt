Laboratorio Alice - Bob - Eve: primitivas criptográficas

Aplicación educativa de consola para comprender y comparar mecanismos criptográficos sin llaves, simétricos y asimétricos. Simula un canal de comunicación con tres actores:

- Alice (emisor): introduce un mensaje, selecciona el mecanismo y ejecuta la operación.
- Eve(observador o atacante simulado): ve solo lo que viaja por el canal y puede modificar, sustituir o reenviar datos.
- Bob (receptor): verifica o descifra y muestra si la operación fue aceptada o rechazada.

                      Eve
                   /\_____/\
                  (  o   o  )
                   \  vvv  /
                      |
                      v
   +---------+  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  +---------+
   |  Alice  |================================|   Bob   |
   +---------+  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  +---------+

Contenido del repositorio

- cripto_lab.py: todo el programa en un solo archivo.
- README.md: este archivo.
Requisitos

- Python 3.9 o superior.
- Biblioteca cryptography.

pip install cryptography

En Windows, si pip o python apuntan a otra instalación de Python, usa py -m pip install cryptography y py Cifradores_CelinaHdez.py.

Cómo ejecutarlo

Desde la carpeta donde está Cifradores_CelinaHdez.py:
python Cifradores_CelinaHdez.py

Pasos para usar el programa

1. Al iniciar aparece el menú principal:
   - 1. Cifrados sin uso de llaves
   - 2. Cifrado simétrico
   - 3. Cifrado asimétrico
   - 4. Demostraciones (ataques y manipulaciones)
   - 0. Salir
2. Escribe 1, 2 o 3 para entrar al laboratorio de esa categoría.
3. Alice: escribe el mensaje (si lo dejas vacío usa uno de ejemplo) y selecciona el mecanismo escribiendo su número. Los mecanismos están agrupados por apartado. Alice ejecuta la operación y se muestran los componentes que envía a Bob, el tiempo, los tamaños de entrada y salida y el pico de memoria.
4. Eve: se muestra lo que ve en el canal y eliges una acción:
   - 1. Solo observar.
   - 2. Modificar un byte (eliges el campo del paquete).
   - 3. Sustituir o forjar (solo disponible donde Eve puede construir un paquete sin conocer secretos: hash, XOF, ECDH y PKI).
   - 4. Reenviar el paquete capturado (repetición o replay): Bob lo recibe dos veces.
   - 5. Escenario separado: filtración de llaves. Muestra los secretos del laboratorio y se marca como un escenario aparte, porque Eve no recibe las llaves en el modelo normal.
5. Bob: recibe el paquete, lo verifica o descifra y muestra ACEPTADO o RECHAZADO con una explicación, más el tiempo y la memoria de su operación.
6. Pulsa Enter para volver al menú y probar otro mecanismo.

Prueba sugerida: en la categoría 2 elige AES-256-CTR (sin autenticación), modifica un byte y observa que Bob acepta el cambio. Repite con AES-256-GCM y observa que Bob lo rechaza.

Demostraciones (opción 4)

Ejecutan las 9 simulaciones de la práctica con datos de prueba creados por el programa y muestran el resultado de cada una:

1. Contraseña débil: ataque de diccionario pequeño contra un hash SHA-256 de prueba.
2. Derivación de contraseñas: SHA-256 directo contra Scrypt (tiempo por intento).
3. Cifrado sin autenticación: alterar bytes de un mensaje cifrado con AES-CTR.
4. Cifrado autenticado: alterar el cifrado, los datos asociados y el nonce de AES-GCM.
5. HMAC: modificar el mensaje sin conocer la llave.
6. Firma digital: modificar un mensaje firmado con RSA-PSS.
7. Acuerdo de claves sin autenticación: sustituir valores públicos en ECDH (intermediario) y la defensa con firma.
8. Repetición de mensajes: reenvío con HMAC sin contador y con contador.
9. PKI: presentar un certificado de una CA no confiable.


Mecanismos incluidos

Cifrados sin uso de llaves
- Funciones hash criptográficas: SHA-256.
- Construcción esponja y salida extensible: SHAKE128.

Cifrado simétrico
- Cifrado simétrico por bloques: AES-256-CBC (sin autenticación) y AES-256-GCM (autenticado).
- Cifrado por flujo: AES-256-CTR.
- Códigos de autenticación de mensajes: HMAC-SHA256.
- Derivación de claves (KDF): Scrypt.

Cifrado asimétrico
- Cifrado de clave pública: RSA-OAEP 2048.
- Firmas digitales: RSA-PSS 2048.
- Intercambio de claves: ECDH con curva P-256.
- Infraestructura de clave pública (PKI): certificado X.509 firmado con RSA.

Para cada mecanismo, el programa muestra los componentes que viajan por el canal (llave, IV, nonce, sal, etiqueta, firma o certificado según corresponda), separando lo público de lo secreto: los secretos viven en un contexto compartido solo por Alice y Bob, nunca en el canal.

Límites del modelo de Eve

Eve solo trabaja con los datos del canal. No recibe llaves secretas ni privadas. Las únicas llaves que genera son las suyas (por ejemplo, su par ECDH en el ataque de intermediario o su CA falsa en PKI). La filtración de llaves está separada y marcada de forma explícita.

Limitación de la medición de memoria

La memoria se mide con tracemalloc, que solo registra las asignaciones hechas desde Python. No incluye la memoria que reservan las bibliotecas nativas (OpenSSL, usada por cryptography), así que los valores son una subestimación. Por ejemplo, Scrypt usa unos 16 MiB reales, pero el programa reporta solo unos KiB. El tiempo se mide con time.perf_counter y varía según el equipo.

Herramientas para ataques reales

El ataque de diccionario del programa es propio y usa una lista pequeña. Para ataques a hashes con listas grandes existen herramientas como hashcat y John the Ripper.

Análisis: qué puede ser vulnerable y qué es más confiable

Los algoritmos usados no están rotos hoy con parámetros correctos. Los problemas vienen del uso incorrecto, que es lo que muestran las demostraciones:

- Hash solo: no autentica. Eve cambia el mensaje y recalcula la huella. Los hashes rápidos tampoco sirven para guardar contraseñas, porque un diccionario los adivina.
- AES-CBC y AES-CTR sin autenticación: son maleables. Eve altera bytes y Bob no lo detecta.
- HMAC sin contador: no impide la repetición de mensajes.
- DH sin autenticar: permite el ataque de intermediario, porque nadie comprueba quién envió cada valor público.
- RSA-OAEP: no autentica al emisor, y si la llave pública es sustituida, el mensaje se cifra para Eve.
- Amenaza futura: RSA y ECDH serían vulnerables a una computadora cuántica suficientemente grande. AES-256 y SHA-256 resisten mejor.

Los mecanismos más confiables en este laboratorio son los que combinan protecciones o encarecen el ataque:

1. AES-GCM: cifra y autentica a la vez, y cualquier alteración se rechaza.
2. HMAC-SHA256: integridad y autenticidad sencillas, sin ataques prácticos conocidos.
3. Scrypt: encarece cada intento de adivinar una contraseña en tiempo y memoria.
4. Firmas digitales con PKI: autenticación y no repudio, siempre que la llave pública esté certificada por una CA de confianza.
5. ECDH combinado con firmas o certificados: nunca solo.

Conclusión: la confidencialidad por sí sola no basta. Hace falta integridad y autenticación, y controles adicionales contra la repetición.
