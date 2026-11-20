"""Pruebas HTTP locales de D4; no modifica el módulo bajo prueba."""
import importlib.util
import json
import pathlib
import sqlite3
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request

source = pathlib.Path(sys.argv[1]).resolve()
mode = sys.argv[2]
spec = importlib.util.spec_from_file_location('objetivo', source)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
with tempfile.TemporaryDirectory(prefix='extra3-p3-') as tmp:
    app.DB = str(pathlib.Path(tmp) / 'test.db')
    app.DESCARGAS = str(pathlib.Path(tmp) / 'descargas')
    app.init_db()
    with sqlite3.connect(app.DB) as db:
        db.execute('INSERT INTO usuarios VALUES (?, ?)', ("o'connor", "clave'valida"))
    db.close()
    server = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    def get(path):
        try:
            response = urllib.request.urlopen(f'http://127.0.0.1:{server.server_port}' + path, timeout=3)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            return response.status, response.read().decode()
    try:
        print(f'Objetivo: {source}; modo: {mode}; servidor solo loopback; datos temporales aislados')
        cases = [('admin legitimo','admin','sup3r-s3cr3t0',200),
                 ('password incorrecta','admin','incorrecta',401),
                 ('usuario inexistente','nadie','x',401),
                 ('comentario SQL en usuario',"admin'--",'x',401),
                 ('tautologia en password','x',"' OR 1=1 --",401),
                 ('tautologia en usuario',"' OR '1'='1' --",'x',401)]
        if mode == 'despues':
            cases += [('apostrofes legitimos',"o'connor","clave'valida",200),
                      ('apostrofe aislado',"'",'x',401),
                      ('campos vacios','','',401)]
        for label, user, password, expected in cases:
            path='/login?' + urllib.parse.urlencode({'user':user, 'pass':password})
            status, body=get(path)
            print(json.dumps({'prueba':label,'GET':path,'status':status,'body':body},ensure_ascii=False))
            if mode == 'despues' or label in ('admin legitimo','password incorrecta','usuario inexistente'):
                assert status == expected, (label,status,expected)
            else:
                assert status == 200 and 'Bienvenido' in body
        for path, content in [('/', 'Portal de empleados.'),('/descargar?archivo=manual.txt','Manual de la intranet PhantomCorp.')]:
            status,body=get(path)
            print(json.dumps({'GET':path,'status':status,'body':body},ensure_ascii=False))
            assert status==200 and content in body
        # Revisión de D5: centinela propio, nunca archivos del sistema.
        pathlib.Path(tmp,'centinela-p3.txt').write_text('CENTINELA_FUERA_DE_DESCARGAS',encoding='utf-8')
        status,body=get('/descargar?archivo=../centinela-p3.txt')
        print(json.dumps({'revision_D5':'centinela fuera de descargas','status':status,'body':body},ensure_ascii=False))
        print('Pruebas D4 y regresiones: OK. D5 se registra como observacion independiente.')
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
