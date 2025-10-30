# Log Analyzer (Hersec)

Herramienta educativa para análisis básico de logs. Ideal para prácticas de DFIR y para aprender a buscar IOCs (IPs, errores, patrones).
**Uso responsable:** solo analices logs que te pertenezcan o para los que tengas permiso.

## Funcionalidades
- Contar ocurrencias de palabras clave.
- Mostrar top N direcciones IP encontradas.
- Buscar líneas por patrón regex (grep).
- Exportar un resumen a CSV (top IPs + keywords).
- Detección básica de timestamps (para ver rango temporal de eventos).

## Archivos
- `log_analyzer.py` - script principal (CLI).
- `example.log` - archivo de ejemplo con entradas simuladas.
- `README.md` - este archivo.

## Requisitos
- Python 3.8+ (no se requieren dependencias externas).

## Uso
```bash
# Mostrar resumen
python log_analyzer.py analyze --file example.log --top-ips 5

# Buscar líneas con pattern
python log_analyzer.py grep --file example.log --pattern "ERROR|Exception"

# Contar palabras clave
python log_analyzer.py keywords --file example.log --words "error,failed,timeout"

# Exportar resumen
python log_analyzer.py export --file example.log --out summary.csv --top-ips 10


[+] Lines read: 120
[+] Top 5 IPs:
    192.168.0.5 — 12
    10.0.0.8 — 7
[+] Sample timestamps found (first 5): ['2024-10-01T12:34:56', '2024-10-01 12:35:01']
