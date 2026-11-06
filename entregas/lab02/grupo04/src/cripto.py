
import argparse
import hashlib
import hmac
import sys


# ---------------------------------------------------------------------------
# B.1 — Cifrado XOR
# ---------------------------------------------------------------------------

def xor_repetido(datos: bytes, clave: bytes) -> bytes:
    """
    Aplica XOR utilizando una clave repetida.

    La misma función permite cifrar y descifrar, ya que XOR es reversible.
    """
    if not clave:
        raise ValueError("La clave no puede estar vacía.")

    return bytes(
        byte ^ clave[i % len(clave)]
        for i, byte in enumerate(datos)
    )


def xor_cifrar(texto: str, clave: str) -> bytes:
    """Cifra un texto utilizando XOR con clave repetida."""
    return xor_repetido(texto.encode("utf-8"), clave.encode("utf-8"))


def xor_descifrar(cifrado: bytes, clave: str) -> str:
    """Descifra un texto cifrado con XOR de clave repetida."""
    resultado = xor_repetido(cifrado, clave.encode("utf-8"))
    return resultado.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# B.1.2 — Romper XOR de un byte mediante análisis de frecuencia
# ---------------------------------------------------------------------------

def puntuar_texto(texto: bytes) -> float:
    """
    Calcula una puntuación para estimar qué tan probable es que un texto
    corresponda a un mensaje en español o inglés.

    Se favorecen letras, espacios y caracteres imprimibles.
    """
    puntuacion = 0.0

    frecuencias = " etaoinshrdluETAOINSHRDLU"
    for caracter in texto:
        if chr(caracter) in frecuencias:
            puntuacion += 2.0
        elif 32 <= caracter <= 126:
            puntuacion += 0.5
        elif caracter in (9, 10, 13):
            puntuacion += 0.2
        else:
            puntuacion -= 5.0

    return puntuacion


def romper_xor_1byte(cifrado: bytes) -> tuple[int, str]:
    """
    Prueba las 256 claves posibles de un byte y selecciona aquella
    que produce el texto con mayor puntuación de frecuencia.
    """
    if not cifrado:
        raise ValueError("El texto cifrado no puede estar vacío.")

    mejor_clave = 0
    mejor_texto = ""
    mejor_puntuacion = float("-inf")

    for clave in range(256):
        candidato = bytes(byte ^ clave for byte in cifrado)
        puntuacion = puntuar_texto(candidato)

        if puntuacion > mejor_puntuacion:
            mejor_puntuacion = puntuacion
            mejor_clave = clave
            mejor_texto = candidato.decode("utf-8", errors="replace")

    return mejor_clave, mejor_texto


# ---------------------------------------------------------------------------
# B.2 — Autenticación de mensajes
# ---------------------------------------------------------------------------

def mac_ingenuo(clave: str, mensaje: str) -> str:
    """
    MAC insegura: SHA-256(clave || mensaje).

    Es vulnerable a ataques de length-extension debido a la construcción
    utilizada. Se conserva únicamente con fines didácticos.
    """
    datos = (clave + mensaje).encode("utf-8")
    return hashlib.sha256(datos).hexdigest()


def mac_hmac(clave: str, mensaje: str) -> str:
    """
    MAC segura utilizando HMAC-SHA256.

    HMAC combina la clave con los valores ipad y opad para evitar
    los problemas de la concatenación directa de clave y mensaje.
    """
    return hmac.new(
        key=clave.encode("utf-8"),
        msg=mensaje.encode("utf-8"),
        digestmod=hashlib.sha256
    ).hexdigest()


def verificar_mac(
    clave: str,
    mensaje: str,
    mac_recibida: str,
    modo: str = "hmac"
) -> bool:
    """
    Verifica que el MAC recibido corresponda al mensaje y a la clave.

    Utiliza hmac.compare_digest para evitar comparaciones con
    cortocircuitos dependientes del contenido.

    modo: "hmac" (recomendado) o "ingenuo" (solo demostración).
    """
    if modo not in ("hmac", "ingenuo"):
        raise ValueError("Modo inválido. Utilice 'hmac' o 'ingenuo'.")

    if modo == "hmac":
        mac_esperada = mac_hmac(clave, mensaje)
    else:
        mac_esperada = mac_ingenuo(clave, mensaje)

    if not isinstance(mac_recibida, str):
        return False

    if len(mac_recibida) != len(mac_esperada):
        return False

    try:
        bytes.fromhex(mac_recibida)
    except ValueError:
        return False

    return hmac.compare_digest(
        mac_esperada,
        mac_recibida.lower()
    )


# ---------------------------------------------------------------------------
# Interfaz de línea de comandos (CLI)
# ---------------------------------------------------------------------------

def cmd_xor(args):
    """Ejecuta el cifrado y descifrado XOR."""
    cifrado = xor_cifrar(args.texto, args.clave)

    print(f"Cifrado (hex): {cifrado.hex()}")

    descifrado = xor_descifrar(cifrado, args.clave)

    print(f"Descifrado:    {descifrado}")


def cmd_romper(args):
    """Ejecuta el ataque por frecuencia sobre XOR de un byte."""
    try:
        cifrado = bytes.fromhex(args.hex)
    except ValueError:
        print(
            "[!] El argumento --hex no es hexadecimal válido.",
            file=sys.stderr
        )
        sys.exit(1)

    try:
        clave, texto = romper_xor_1byte(cifrado)
    except ValueError as error:
        print(f"[!] {error}", file=sys.stderr)
        sys.exit(1)

    print(f"Clave encontrada: 0x{clave:02x} ({clave})")
    print(f"Texto en claro:\n{texto}")


def cmd_mac(args):
    """Genera un MAC y verifica su autenticidad."""
    if args.modo == "hmac":
        tag = mac_hmac(args.clave, args.msg)
        print(f"HMAC-SHA256: {tag}")
    else:
        tag = mac_ingenuo(args.clave, args.msg)
        print(f"MAC ingenua (SHA256(k||m)): {tag}")

    ok = verificar_mac(
        args.clave,
        args.msg,
        tag,
        modo=args.modo
    )

    print(f"Verificación: {'OK ✓' if ok else 'FALLO ✗'}")


def main():
    """Configura y ejecuta los comandos disponibles."""
    parser = argparse.ArgumentParser(
        description="Lab02 — Criptografía"
    )

    sub = parser.add_subparsers(dest="comando")

    # Comando XOR
    p_xor = sub.add_parser(
        "xor",
        help="Cifrar/descifrar con XOR de clave repetida"
    )
    p_xor.add_argument("--texto", required=True)
    p_xor.add_argument("--clave", required=True)

    # Comando para romper XOR
    p_romper = sub.add_parser(
        "romper",
        help="Romper XOR de 1 byte por frecuencia"
    )
    p_romper.add_argument(
        "--hex",
        required=True,
        help="Texto cifrado en hexadecimal"
    )

    # Comando MAC
    p_mac = sub.add_parser(
        "mac",
        help="Generar y verificar MAC"
    )
    p_mac.add_argument("--clave", required=True)
    p_mac.add_argument("--msg", required=True)
    p_mac.add_argument(
        "--modo",
        choices=["ingenuo", "hmac"],
        default="hmac"
    )

    args = parser.parse_args()

    if args.comando == "xor":
        cmd_xor(args)
    elif args.comando == "romper":
        cmd_romper(args)
    elif args.comando == "mac":
        cmd_mac(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
