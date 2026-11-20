"""Prueba aislada P3. No reemplaza la integración de P1/P2/P5."""
import hashlib
import importlib.util
import pathlib
import sys
import time

source, caso, usuario = map(pathlib.Path, sys.argv[1:4])
spec = importlib.util.spec_from_file_location('cracker', source)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
for word in ('luna', 'LuNa', '', '123', 'ñandú'):
    result=m.aplicar_reglas(word)
    assert isinstance(result,list) and result[0]==word
    assert len(result)==len(set(result)) and len(result)<=28
    assert result==m.aplicar_reglas(word)
    assert all(isinstance(x,str) for x in result)
    assert word+'2026' in result and word.capitalize()+'123' in result
    print(repr(word), '->', result)
print('Contrato, orden, deduplicación y variantes: OK')
rows=[line.split(':') for line in (caso/'sombra.txt').read_text(encoding='utf-8').splitlines() if line and not line.startswith('#')]
row=next(row for row in rows if row[0]==str(usuario))
name, algo, salt, target=row
assert algo=='sha256', 'Esta prueba aislada se limita a SHA-256 del caso'
words=(caso/'diccionario.txt').read_text(encoding='utf-8').splitlines()
found=None
for rules in (False,True):
    start=time.perf_counter()
    attempts=0
    found=None
    for word in words:
        for candidate in (m.aplicar_reglas(word) if rules else [word]):
            attempts+=1
            if hashlib.sha256(bytes.fromhex(salt)+candidate.encode()).hexdigest()==target:
                found=candidate
                break
        if found is not None:
            break
    elapsed=time.perf_counter()-start
    print(f'Prueba AISLADA usuario={name} reglas={rules} intentos={attempts} segundos={elapsed:.9f} hallada={found!r}')
    if not rules:
        assert found is None
    else:
        assert found is not None
        print('Base de diccionario:',repr(word))
        print('Longitud:',len(found),'mayúscula:',any(c.isupper() for c in found),'minúscula:',any(c.islower() for c in found),'dígito:',any(c.isdigit() for c in found))
        print('Loot mediante descifrar_loot de la copia:')
        print(m.descifrar_loot((caso/'loot'/f'{name}.enc').read_text(),found))
