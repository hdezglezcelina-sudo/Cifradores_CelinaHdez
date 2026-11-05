"""Laboratorio Alice - Bob - Eve
Requisito:  pip install cryptography      Ejecutar:  python cripto_lab.py"""

import os, sys, time, tracemalloc, hashlib, hmac, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, padding as sp, serialization as ser
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as ap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CATS = {"Cifrados sin uso de llaves": [], "Cifrado simétrico": [], "Cifrado asimétrico": []}
MECH = {}
FALSO = b"Mensaje falso de Eve"

def reg(nombre, cat, alice, bob, eve, forja=None):
    MECH[nombre] = dict(a=alice, b=bob, eve=eve, forja=forja); CATS[cat].append(nombre)
def clave(c): c.setdefault("k", os.urandom(32)); return c["k"]          # llave compartida Alice-Bob (Eve NO la recibe)
def eq(a, b): return hmac.compare_digest(a, b)
def raw(p): return p.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
def pem(p): return p.public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
def txt(b): return b.decode(errors="replace")
def flip(p, campo): q = dict(p); b = bytearray(q[campo]); b[0] ^= 1; q[campo] = bytes(b); return q
def tam(p): return sum(len(v) for v in p.values())
def medir(f, *a):
    #Tiempo y pico de memoria de Python (tracemalloc). No incluye memoria de bibliotecas nativas (OpenSSL).
    tracemalloc.start(); t = time.perf_counter(); r = f(*a); dt = (time.perf_counter() - t) * 1000
    pico = tracemalloc.get_traced_memory()[1] / 1024; tracemalloc.stop(); return r, dt, pico

def hash_mech(alg):
    def a(m, c): return {"mensaje": m, "huella": hashlib.new(alg, m).digest()}
    def b(p, c):
        ok = eq(hashlib.new(alg, p["mensaje"]).digest(), p["huella"])
        return ok, "La huella coincide: el mensaje no cambió." if ok else "La huella no coincide: mensaje alterado."
    def f(p, e): return a(FALSO, {}), "Eve cambió el mensaje y recalculó la huella (el algoritmo es público): Bob lo acepta. El hash solo NO autentica."
    return a, b, f
for n, alg in (("SHA-256", "sha256"),):
    reg(n, "Cifrados sin uso de llaves", *hash_mech(alg)[:2], "Ve mensaje y huella; puede sustituir ambos.", hash_mech(alg)[2])
def xof_a(m, c): return {"mensaje": m, "salida_extensible": hashlib.shake_128(m).digest(c.get("largo", 32))}
def xof_b(p, c):
    ok = eq(hashlib.shake_128(p["mensaje"]).digest(len(p["salida_extensible"])), p["salida_extensible"])
    return ok, "La salida XOF coincide." if ok else "La salida XOF no coincide: mensaje alterado."
reg("SHAKE128 (esponja, salida extensible)", "Cifrados sin uso de llaves", xof_a, xof_b, "Ve mensaje y salida; puede sustituir ambos.",
    lambda p, e: ({"mensaje": FALSO, "salida_extensible": hashlib.shake_128(FALSO).digest(len(p["salida_extensible"]))}, "Eve recalculó la salida XOF: Bob la acepta."))

def cbc_a(m, c):
    iv = os.urandom(16); pd = sp.PKCS7(128).padder(); e = Cipher(algorithms.AES(clave(c)), modes.CBC(iv)).encryptor()
    return {"iv": iv, "texto_cifrado": e.update(pd.update(m) + pd.finalize()) + e.finalize()}
def cbc_b(p, c):
    try:
        d = Cipher(algorithms.AES(c["k"]), modes.CBC(p["iv"])).decryptor(); u = sp.PKCS7(128).unpadder()
        return True, "Descifrado: «%s». Nadie verificó integridad: los cambios no se detectan." % txt(u.update(d.update(p["texto_cifrado"]) + d.finalize()) + u.finalize())
    except ValueError: return False, "Relleno inválido (fallo accidental, no es una verificación de autenticidad)."
reg("AES-256-CBC (por bloques, sin autenticación)", "Cifrado simétrico", cbc_a, cbc_b, "Ve IV y texto cifrado, no el mensaje; puede alterar bytes.")
def gcm_a(m, c):
    n, aad = os.urandom(12), b"cabecera:v1"; return {"nonce": n, "datos_asociados": aad, "cifrado_y_etiqueta": AESGCM(clave(c)).encrypt(n, m, aad)}
def gcm_b(p, c):
    try: return True, "Etiqueta válida. Descifrado: «%s»" % txt(AESGCM(c["k"]).decrypt(p["nonce"], p["cifrado_y_etiqueta"], p["datos_asociados"]))
    except Exception: return False, "Etiqueta GCM inválida: el cifrado o los datos asociados fueron alterados."
reg("AES-256-GCM (por bloques, autenticado)", "Cifrado simétrico", gcm_a, gcm_b, "Ve nonce, datos asociados y cifrado; cualquier cambio hará fallar la etiqueta.")
def ctr(k, n, d): return Cipher(algorithms.AES(k), modes.CTR(n)).encryptor().update(d)
reg("AES-256-CTR (flujo, sin autenticación)", "Cifrado simétrico",
    lambda m, c: (lambda n: {"nonce_contador": n, "texto_cifrado": ctr(clave(c), n, m)})(os.urandom(16)),
    lambda p, c: (True, "Descifrado: «%s». Sin integridad: no se detectan cambios." % txt(ctr(c["k"], p["nonce_contador"], p["texto_cifrado"]))),
    "Ve nonce y texto cifrado; con texto claro conocido puede cambiar bytes concretos.")
def hm_a(m, c): return {"mensaje": m, "etiqueta": hmac.new(clave(c), m, "sha256").digest()}
def hm_b(p, c):
    ok = eq(hmac.new(c["k"], p["mensaje"], "sha256").digest(), p["etiqueta"]); return ok, "Etiqueta válida: mensaje íntegro y de quien tiene la llave." if ok else "Etiqueta inválida."
reg("HMAC-SHA256", "Cifrado simétrico", hm_a, hm_b, "Ve mensaje y etiqueta; sin la llave no puede forjar otra.")
scr = lambda pw, s: Scrypt(s, 32, 2**14, 8, 1).derive(pw)
def kdf_a(m, c): c["pw"] = m; s = os.urandom(16); return {"sal": s, "clave_derivada": scr(m, s)}
def kdf_b(p, c):
    ok = eq(scr(c["pw"], p["sal"]), p["clave_derivada"]); return ok, "La contraseña produce la misma clave derivada." if ok else "Clave derivada distinta: dato alterado."
reg("Scrypt (N=2^14, r=8, p=1)", "Cifrado simétrico", kdf_a, kdf_b, "Ve sal y clave derivada: puede probar un diccionario sin conexión.")



def rsa_key(c, n="rsa"):
    if n not in c: c[n] = rsa.generate_private_key(65537, 2048)
    return c[n]
OAEP = lambda: ap.OAEP(mgf=ap.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
def rsa_a(m, c): k = rsa_key(c); return {"clave_publica": pem(k.public_key()), "texto_cifrado": k.public_key().encrypt(m, OAEP())}
def rsa_b(p, c):
    try: return True, "Descifrado con la clave privada de Bob: «%s». Bob no sabe quién lo envió (cualquiera puede cifrar con la pública)." % txt(rsa_key(c).decrypt(p["texto_cifrado"], OAEP()))
    except Exception: return False, "Descifrado RSA-OAEP fallido: texto cifrado alterado."
reg("RSA-OAEP 2048 (cifrado de clave pública, mensaje <= 190 bytes)", "Cifrado asimétrico", rsa_a, rsa_b, "Ve la clave pública y el texto cifrado; puede sustituir la clave pública si no hay PKI.")
PSS = lambda: ap.PSS(ap.MGF1(hashes.SHA256()), 32)
def pss_a(m, c): k = rsa_key(c, "rsa_f"); return {"mensaje": m, "firma": k.sign(m, PSS(), hashes.SHA256()), "clave_publica": pem(k.public_key())}
def pss_b(p, c):
    try: rsa_key(c, "rsa_f").public_key().verify(p["firma"], p["mensaje"], PSS(), hashes.SHA256()); return True, "Firma RSA-PSS válida."
    except Exception: return False, "Firma RSA-PSS inválida."
reg("RSA-PSS 2048 (firma digital)", "Cifrado asimétrico", pss_a, pss_b, "Ve mensaje, firma y clave pública; no puede forjar sin la clave privada.")
CURVA = ec.SECP256R1()
def pub_bytes(k): return k.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)
def pub_load(b): return ec.EllipticCurvePublicKey.from_encoded_point(CURVA, b)
dk = lambda sh: HKDF(hashes.SHA256(), 32, None, b"ecdh-lab").derive(sh)   # el secreto crudo no se usa directamente como llave
huella = lambda k: hashlib.sha256(k).hexdigest()[:16]
def dh_a(m, c):
    c["xa"], c["xb"] = ec.generate_private_key(CURVA), ec.generate_private_key(CURVA); c["ka"] = dk(c["xa"].exchange(ec.ECDH(), c["xb"].public_key()))
    return {"pub_alice": pub_bytes(c["xa"]), "pub_bob": pub_bytes(c["xb"])}
def dh_b(p, c):
    kb = dk(c["xb"].exchange(ec.ECDH(), pub_load(p["pub_alice"]))); igual = eq(kb, c["ka"])
    return True, "Bob aceptó el acuerdo (huella de clave %s). %s" % (huella(kb), "[Laboratorio] Coincide con la clave de Alice." if igual else "[Laboratorio] NO coincide con la de Alice: Bob negoció con otra parte, nadie autenticó a Alice.")
def dh_f(p, e):
    e["x"] = ec.generate_private_key(CURVA); e["k"] = dk(e["x"].exchange(ec.ECDH(), pub_load(p["pub_bob"])))
    return {"pub_alice": pub_bytes(e["x"]), "pub_bob": p["pub_bob"]}, "Eve sustituyó la pública de Alice por la suya (llave propia, no robada). Eve y Bob comparten la clave %s: ataque de intermediario." % huella(e["k"])
reg("ECDH P-256 (acuerdo de claves Diffie-Hellman)", "Cifrado asimétrico", dh_a, dh_b, "Ve ambas públicas, no calcula la clave; puede sustituir los valores.", dh_f)
def cert(sujeto, pub, emisor, priv, ca=False):
    ahora = datetime.datetime.now(datetime.timezone.utc); n = lambda s: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, s)])
    return (x509.CertificateBuilder().subject_name(n(sujeto)).issuer_name(n(emisor)).public_key(pub).serial_number(x509.random_serial_number())
            .not_valid_before(ahora - datetime.timedelta(minutes=1)).not_valid_after(ahora + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True).sign(priv, hashes.SHA256()))
der = lambda c: c.public_bytes(ser.Encoding.DER)
nueva = lambda: rsa.generate_private_key(65537, 2048)
def pki_a(m, c):
    if "ca" not in c:
        c["ca"], c["al"] = nueva(), nueva()
        c["ca_cert"] = cert("CA Confiable", c["ca"].public_key(), "CA Confiable", c["ca"], True); c["al_cert"] = cert("Alice", c["al"].public_key(), "CA Confiable", c["ca"])
    return {"mensaje": m, "firma": c["al"].sign(m, PSS(), hashes.SHA256()), "certificado": der(c["al_cert"])}
def pki_b(p, c):
    try:
        ce = x509.load_der_x509_certificate(p["certificado"]); ce.verify_directly_issued_by(c["ca_cert"]); ahora = datetime.datetime.now(datetime.timezone.utc)
        if not ce.not_valid_before_utc <= ahora <= ce.not_valid_after_utc: return False, "Certificado fuera de vigencia."
        ce.public_key().verify(p["firma"], p["mensaje"], PSS(), hashes.SHA256()); return True, "Certificado de «%s» emitido por la CA de confianza y firma válida." % ce.subject.rfc4514_string()
    except Exception as e: return False, "Certificado o firma rechazados (%s): emisor no confiable o datos alterados." % type(e).__name__
def pki_f(p, e):
    ca, k = nueva(), nueva()
    return {"mensaje": FALSO, "firma": k.sign(FALSO, PSS(), hashes.SHA256()), "certificado": der(cert("Alice", k.public_key(), "CA Confiable", ca))}, "Eve presentó un certificado «Alice» emitido por su propia CA (no confiable)."
reg("PKI (certificado X.509 + firma RSA)", "Cifrado asimétrico", pki_a, pki_b, "Ve el certificado; no puede emitir uno aceptado sin una CA de confianza.", pki_f)





#  demostraciones
LISTA = ["123456", "password", "qwerty", "letmein", "admin", "iloveyou", "dragon", "monkey", "abc123", "welcome", "sunshine", "veracruz2026"]
def run(n, ctx, msg=b"Transferir $100 a Bob"): M = MECH[n]; p = M["a"](msg, ctx); return M, p
def d_diccionario():
    obj = hashlib.sha256(b"dragon").hexdigest(); t = time.perf_counter()
    for i, w in enumerate(LISTA, 1):
        if hashlib.sha256(w.encode()).hexdigest() == obj: return "Diccionario de %d palabras contra SHA-256 de prueba" % len(LISTA), "Encontró «%s» en %d intentos (%.3f ms)" % (w, i, (time.perf_counter() - t) * 1000), "Recuperar una contraseña por conjeturas no equivale a descifrar un hash: el hash no se invierte, se adivina la entrada.", True
    return "Diccionario", "No encontrada", "", False
def d_kdf():
    s = os.urandom(16); t = time.perf_counter(); [hashlib.sha256(str(i).encode()).digest() for i in range(20000)]; a = (time.perf_counter() - t) / 20000
    t = time.perf_counter(); [scr(str(i).encode(), s) for i in range(5)]; b = (time.perf_counter() - t) / 5
    return "Comparar intentos: SHA-256 directo vs Scrypt", "SHA-256: %.2f us/intento (%d por s) | Scrypt: %.1f ms/intento (%.1f por s) | Scrypt es %d veces mas lento" % (a * 1e6, 1 / a, b * 1e3, 1 / b, b / a), "Los parámetros de costo afectan el trabajo de cada intento.", b > 100 * a
def d_sin_auth():
    n = "AES-256-CTR (flujo, sin autenticación)"; c = {}; m = b"Transferir $100 a Bob"; M, p = run(n, c, m); q = dict(p); ct = bytearray(p["texto_cifrado"]); ct[m.index(b"1")] ^= ord("1") ^ ord("9"); q["texto_cifrado"] = bytes(ct)
    ok, t = M["b"](q, c); return "Alterar un byte del texto cifrado (AES-CTR)", "Bob aceptó: " + t, "El cifrado por sí solo no garantiza detección de modificaciones (Eve cambió $100 por $900 sin conocer la llave).", ok
def d_gcm():
    c = {}; M, p = run("AES-256-GCM (por bloques, autenticado)", c); r = [(k, M["b"](q, c)[0]) for k, q in (("sin cambios", p), ("cifrado alterado", flip(p, "cifrado_y_etiqueta")), ("datos asociados alterados", flip(p, "datos_asociados")), ("nonce alterado", flip(p, "nonce")))]
    return "Alterar cifrado, datos asociados y nonce de AES-GCM", "; ".join("%s: %s" % (k, "ACEPTADO" if v else "RECHAZADO") for k, v in r), "La verificación debe fallar.", r[0][1] and not any(v for _, v in r[1:])
def d_mac():
    r = []
    for n in ("HMAC-SHA256",):
        c = {}; M, p = run(n, c, b"Pagar 100"); q = dict(p); q["mensaje"] = b"Pagar 999"; r.append((n, M["b"](p, c)[0], M["b"](q, c)[0]))
    return "Modificar el mensaje sin conocer la llave", "; ".join("%s: original %s, modificado %s" % (n, "OK" if a else "FALLA", "ACEPTADO" if b else "RECHAZADO") for n, a, b in r), "La etiqueta original deja de ser válida.", all(a and not b for _, a, b in r)
def d_firma():
    c = {}; M, p = run("RSA-PSS 2048 (firma digital)", c, b"Contrato v1"); q = dict(p); q["mensaje"] = b"Contrato v2"; a, b = M["b"](p, c)[0], M["b"](q, c)[0]
    return "Modificar un mensaje firmado", "original: %s; modificado: %s" % ("VALIDA" if a else "invalida", "VALIDA" if b else "INVALIDA"), "La firma deja de verificarse.", a and not b
def d_acuerdo():
    c, e = {}, {}; M, p = run("ECDH P-256 (acuerdo de claves Diffie-Hellman)", c); q, nota = M["forja"](p, e); t = M["b"](q, c)[1]; ed = nueva(); sig = ed.sign(p["pub_alice"] + p["pub_bob"], PSS(), hashes.SHA256())
    try: ed.public_key().verify(sig, q["pub_alice"] + q["pub_bob"], PSS(), hashes.SHA256()); df = "aceptado"
    except Exception: df = "RECHAZADO"
    return "Sustituir valores públicos (simulación de intermediario)", nota + " | " + t + " | Con valores públicos firmados por Alice: " + df, "Un acuerdo de claves necesita autenticar a los participantes.", e["k"] != c["ka"] and df == "RECHAZADO"
def d_replay():
    k = os.urandom(32); m = b"Transferir $100"; ult = 0; r1 = []; r2 = []; seen = set()
    for _ in range(2):  # sin contador
        t = hmac.new(k, m, "sha256").digest(); r1.append(eq(t, hmac.new(k, m, "sha256").digest()))
    t = hmac.new(k, (1).to_bytes(8, "big") + m, "sha256").digest()
    for _ in range(2):  # con contador: la etiqueta cubre el contador y Bob exige uno mayor al último
        v = eq(t, hmac.new(k, (1).to_bytes(8, "big") + m, "sha256").digest()) and 1 > ult; r2.append(v); ult = 1 if v else ult
    return "Reenviar un mensaje válido con HMAC", "Sin contador: 1.o %s, 2.o %s | Con contador: 1.o %s, 2.o %s" % tuple("ACEPTADO" if x else "RECHAZADO" for x in r1 + r2), "La autenticación necesita controles adicionales (contador, nonce, marca de tiempo).", r1[1] and r2[0] and not r2[1]
def d_pki():
    c = {}; M, p = run("PKI (certificado X.509 + firma RSA)", c, b"Hola Bob"); a = M["b"](p, c); q, nota = M["forja"](p, {}); b = M["b"](q, c)
    return "Presentar un certificado de una CA no confiable", "legítimo: %s; de CA falsa: %s. %s" % ("ACEPTADO" if a[0] else "rechazado", "ACEPTADO" if b[0] else "RECHAZADO", b[1]), "El receptor debe rechazar el certificado.", a[0] and not b[0]
DEMOS = [("Contraseña débil", d_diccionario), ("Derivación de contraseñas", d_kdf), ("Cifrado sin autenticación", d_sin_auth), ("Cifrado autenticado", d_gcm), ("HMAC", d_mac),
         ("Firma digital", d_firma), ("Acuerdo de claves sin autenticación", d_acuerdo), ("Repetición de mensajes", d_replay), ("PKI", d_pki)]
def demostraciones():
    for i, (nombre, f) in enumerate(DEMOS, 1):
        acc, res, apr, ok = f(); print("\n%d. %s  [%s]\n   Acción de Eve: %s\n   Resultado: %s\n   Aprendizaje: %s" % (i, nombre, "OK" if ok else "FALLO", acc, res, apr))

#  interfaz de consola
ARTE = r"""
                      Eve
                   /\_____/\
                  (  o   o  )     (observa y puede alterar el canal)
                   \  vvv  /
                      |
                      v
   +---------+  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  +---------+
   |  Alice  |================================|   Bob   |
   +---------+  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~  +---------+
"""
APART = [("SHA-256", "Funciones hash criptográficas"), ("SHAKE", "Construcción esponja y salida extensible"), ("AES-256-CTR", "Cifrado por flujo (stream cipher)"), ("AES-256-C", "Cifrado simétrico por bloques"), ("AES-256-G", "Cifrado simétrico por bloques"),
         ("HMAC", "Códigos de autenticación de mensajes (MAC)"), ("Scrypt", "Derivación de claves (KDF)"),
         ("RSA-OAEP", "Cifrado de clave pública"), ("RSA-PSS", "Firmas digitales"), ("ECDH", "Intercambio de claves"), ("PKI", "Infraestructura de clave pública (PKI)")]
def apartado(n): return next(a for k, a in APART if n.startswith(k))
def pedir(texto, n):
    while True:
        v = input(texto).strip()
        if v.isdigit() and 0 <= int(v) <= n: return int(v)
        print("  Opción no válida.")
def mostrar(p):
    for k, v in p.items():
        h = v.hex(); print("   %-26s [%3d B] %s%s" % (k, len(v), h[:60], "..." if len(h) > 60 else "")); 
        if k == "mensaje": print("   %-26s texto: %s" % ("", txt(v)))
def laboratorio(cat):
    nombres = CATS[cat]; ctx, eve = {}, {}; print(ARTE)
    print("=== ALICE (emisor) ===")
    msg = (input("Introduce el mensaje: ").strip() or "Transferir $100 a Bob").encode()
    ult = None
    for i, n in enumerate(nombres, 1):
        if apartado(n) != ult: ult = apartado(n); print("\n  [%s]" % ult)
        print("    %d. %s" % (i, n))
    print()
    nombre = None
    while nombre is None:
        i = pedir("Selecciona el mecanismo: ", len(nombres))
        if i: nombre = nombres[i - 1]
    M = MECH[nombre]
    if nombre.startswith("SHAKE"): ctx["largo"] = max(1, pedir("Longitud de la salida en bytes (1-512): ", 512))
    try: p, ms, kib = medir(M["a"], msg, ctx)
    except Exception as e: print("Error: %s" % e); return
    print("\nAlice ejecuta %s y envía a Bob:" % nombre); mostrar(p)
    print("   Recursos: %.3f ms | entrada %d B -> salida %d B | pico de memoria Python %.1f KiB" % (ms, len(msg), tam(p), kib))
    print("\n=== EVE (observador / atacante simulado) ===\nEve solo ve lo que viaja por el canal:"); mostrar(p); print("Qué obtiene: " + M["eve"])
    entregas = [p]
    while True:
        print("\n  1. Solo observar\n  2. Modificar un byte\n  3. Sustituir / forjar\n  4. Reenviar el paquete capturado (replay)\n  5. ESCENARIO SEPARADO: filtración de llaves")
        o = pedir("Acción de Eve: ", 5)
        if o == 5:
            sec = {k: v for k, v in ctx.items() if isinstance(v, bytes)}
            print("  *** Escenario explícito: se filtraron llaves secretas (no es el modelo normal) ***")
            for k, v in sec.items(): print("   %s: %s" % (k, v.hex()))
            if not sec: print("   (este mecanismo usa llaves privadas no exportadas en el laboratorio)")
            continue
        if o == 2:
            cs = list(p); [print("   %d. %s" % (i, c)) for i, c in enumerate(cs, 1)]
            entregas = [flip(p, cs[max(1, pedir("Campo a modificar: ", len(cs))) - 1])]; print("  Eve modificó 1 bit.")
        elif o == 3:
            if M["forja"]: q, nota = M["forja"](p, eve); entregas = [q]; print("  " + nota)
            else: print("  Sin la llave o clave privada Eve no puede construir un paquete válido. Prueba «Modificar un byte»."); continue
        elif o == 4: entregas = [p, p]; print("  Eve reenviará el paquete: Bob lo recibirá dos veces.")
        break
    print("\n=== BOB (receptor) ===")
    vistos = set()
    for q in entregas:
        print("Bob recibe:"); mostrar(q); k = tuple(sorted(q.items()))
        try: (ok, t), ms, kib = medir(M["b"], q, ctx)
        except Exception as e: ok, t, ms, kib = False, "Rechazado (%s)" % type(e).__name__, 0, 0
        if ok and k in vistos: t += " ATENCIÓN: paquete repetido aceptado; sin contador o nonce el replay no se detecta."
        vistos.add(k); print("   %s: %s\n   Recursos: %.3f ms | pico de memoria Python %.1f KiB" % ("ACEPTADO" if ok else "RECHAZADO", t, ms, kib))
    print("\nNota: la memoria se mide con tracemalloc y no incluye lo que reservan las bibliotecas nativas (OpenSSL); es una subestimación.")
def main():
    if hasattr(sys.stdout, "reconfigure"): sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(ARTE); cats = list(CATS)
    while True:
        print("\n=== MENÚ PRINCIPAL ===")
        for i, c in enumerate(cats, 1): print("  %d. %s" % (i, c))
        print("  4. Demostraciones (ataques y manipulaciones)\n  0. Salir")
        o = pedir("Opción: ", 4)
        if o == 0: break
        demostraciones() if o == 4 else laboratorio(cats[o - 1])
        input("\nEnter para volver al menú...")
if __name__ == "__main__": main()
