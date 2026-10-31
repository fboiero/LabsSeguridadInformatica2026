"""Fuerza bruta de rutas al estilo dirb: prueba cada palabra y reporta lo que no da 404."""
import sys, urllib.request, urllib.error
base, wl = sys.argv[1].rstrip("/"), sys.argv[2]
exts = [""] + (sys.argv[3].split(",") if len(sys.argv) > 3 else [])
words = [w.strip() for w in open(wl) if w.strip() and not w.startswith("#")]
print(f"URL_BASE: {base}/\nWORDLIST_FILES: {wl} ({len(words)} palabras)  EXTENSIONES: {exts[1:] or '-'}\n")
for w in words:
    for e in exts:
        url = f"{base}/{w}{e}"
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=5)
            code, size = r.status, len(r.read())
        except urllib.error.HTTPError as h:
            code, size = h.code, len(h.read())
        if code != 404:
            print(f"+ {url} (CODE:{code}|SIZE:{size})")
