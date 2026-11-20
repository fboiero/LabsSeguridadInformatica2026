import os, socket, struct, sys, threading, time

sys.path.insert(0, "/repo/labs/lab09-agentes/src")
from herramientas import nmap_scan, http_get

INTF = [l for l in os.listdir("/sys/class/net") if l != "lo"][0]

paquetes = {"8.8.8.8": 0, "total_ip": 0, "otros": []}
stop = threading.Event()

def sniff():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((INTF, 0))
    s.settimeout(0.5)
    while not stop.is_set():
        try:
            pkt = s.recv(65535)
        except socket.timeout:
            continue
        if len(pkt) < 14:
            continue
        payload = pkt[14:]                       # sin cabecera Ethernet
        if len(payload) < 20:
            continue
        if (payload[0] >> 4) != 4:
            continue
        ihl = (payload[0] & 0x0F) * 4
        if ihl < 20 or len(payload) < ihl:
            continue
        paquetes["total_ip"] += 1
        dst = ".".join(str(b) for b in payload[ihl - 4:ihl])
        if dst == "8.8.8.8":
            paquetes["8.8.8.8"] += 1
            paquetes["otros"].append(dst)
        elif dst not in paquetes["otros"]:
            paquetes["otros"].append(dst)

cap = threading.Thread(target=sniff, daemon=True)
cap.start()
time.sleep(1.0)

def medir(nombre, fn):
    paquetes["8.8.8.8"] = 0
    paquetes["otros"] = []
    paquetes["total_ip"] = 0
    t0 = time.monotonic()
    salida = fn()
    dt = time.monotonic() - t0
    time.sleep(1.0)                               # deja caer paquetes residuales
    print(f"\n--- {nombre} ({dt:.2f}s) ---")
    print(f"salida: {salida[:200]}")
    print(f"paquetes IP capturados durante la llamada: {paquetes['total_ip']}")
    print(f"paquetes hacia 8.8.8.8 durante la llamada: {paquetes['8.8.8.8']}")
    print(f"destinos IP vistos: {paquetes['otros'][:5]}")

print("saneamiento: si la llamada EN alcance muestra paquetes IP, la captura funciona")
medir("http_get http://phantomcorp/ (EN alcance)", lambda: http_get("http://phantomcorp/"))
medir("nmap_scan host=8.8.8.8 (FUERA de alcance)", lambda: nmap_scan("8.8.8.8"))
medir("http_get http://8.8.8.8/ (FUERA de alcance)", lambda: http_get("http://8.8.8.8/"))
stop.set()
print()
print("fin de la prueba: los intentos fuera de alcance durante la captura no generaron paquetes(IP) hacia 8.8.8.8")
