# REKON

REKON 1.1 es un orquestador Bash de reconocimiento y enumeración para
laboratorios y pentests expresamente autorizados. Recibe una única IPv4, IPv6,
hostname o FQDN, instala de forma consentida las dependencias que falten,
selecciona automáticamente los diccionarios adecuados y genera un expediente
reproducible con evidencias, comandos, tiempos, errores, informes y hashes.

No es un framework de explotación. Deliberadamente no incorpora fuerza bruta de
credenciales, spraying, payloads, explotación, persistencia, DoS, OAST ni métodos
HTTP con escritura.

## Qué cubre

1. Validación estricta de objetivo, autorización, alcance, concurrencia y tasa.
2. Instalación previa y auditable con el gestor de paquetes, PDTM/Go y `pipx`.
3. DNS directo/inverso, WHOIS/RIR, registros, fuentes pasivas, wildcard, fuerza
   de nombres y pruebas AXFR.
4. Descubrimiento TCP rápido con Naabu; Masscan como respaldo para IP; validación,
   servicios, SO y NSE `safe` con Nmap.
5. Escaneo UDP con Nmap, detección ligera de versión y NSE `safe` cuando existen
   privilegios raw.
6. Enumeración segura de RPC, NFS, claves SSH, SMB anónimo y RootDSE LDAP anónimo.
7. Descubrimiento HTTP multipuerto, cabeceras, tecnologías, WAF y capturas.
8. Crawling con Katana; Hakrawler complementario en `deep`; URLs históricas con
   gau y waybackurls.
9. FFUF para directorios, ficheros, parámetros GET y vhosts. En `deep`,
   Feroxbuster añade recursión acotada, Gobuster contrasta vhosts y Arjun valida
   parámetros GET con pocas solicitudes agrupadas.
10. TLS con testssl.sh, sslscan u OpenSSL y observaciones Nuclei limitadas a
    `tech`, `exposure` y `misconfig` sin Interactsh.
11. Informe Markdown/JSON, HTML opcional, inventario antes/después de instalar,
    política de escaneo, comandos reproducibles y `SHA256SUMS`.

## Inicio rápido

```bash
chmod +x rekon.sh
./rekon.sh
```

El asistente solicita:

1. objetivo exacto;
2. directorio raíz de diccionarios, con `/usr/share/seclists` por defecto;
3. perfil;
4. confirmación literal `LAB AUTORIZADO`;
5. permiso para instalar herramientas que falten;
6. permiso separado para usar `sudo` únicamente en SYN, UDP y detección de SO.

El FQDN introducido es la raíz exacta del alcance. Si introduces
`app.lab.example`, se aceptan ese nombre y `*.app.lab.example`, pero no
`vpn.lab.example`. No se aceptan CIDR, rangos, comodines ni listas de objetivos.

Ejemplo no interactivo completo:

```bash
./rekon.sh \
  --target app.lab.example \
  --wordlists /usr/share/seclists \
  --profile balanced \
  --output ./rekon-output \
  --install-deps \
  --sudo-scans \
  --accept-authorized-use \
  --non-interactive
```

En modo no interactivo no se instala ni se usa `sudo` de forma implícita: debes
indicar `--install-deps` y `--sudo-scans`. Para revisar todo sin instalar ni
emitir tráfico:

```bash
./rekon.sh -t app.lab.example -w /usr/share/seclists -p deep \
  --install-deps --sudo-scans --dry-run \
  --accept-authorized-use --non-interactive
```

## Instalación de dependencias

REKON instala primero y después enumera. La fase es idempotente: conserva las
herramientas ya presentes e intenta completar únicamente la pila ausente.

- Kali, Debian, Parrot y Ubuntu: pila amplia mediante `apt-get`.
- Fedora/RHEL: dependencias base mediante `dnf`.
- Arch: dependencias base mediante `pacman`.
- ProjectDiscovery: `subfinder`, `dnsx`, `httpx`, `naabu`, `katana` y `nuclei`
  mediante PDTM en el directorio del usuario.
- Herramientas Go adicionales: FFUF, Gobuster, Assetfinder, gau, waybackurls,
  Hakrawler, Gowitness y Puredns.
- Arjun: entorno aislado mediante `pipx`.

No ejecuta `curl | sh`, no modifica `.bashrc`/`.zshrc` y no descarga binarios
precompilados sin verificación desde URLs improvisadas. Los binarios de usuario
se guardan en `~/.local/bin`, o en `REKON_BIN_DIR` si defines esa variable, y el
`PATH` solo se ajusta para la ejecución actual.

Cada instalación queda en `logs/commands.tsv`; sus salidas están en `logs/` y
los inventarios comparables en `00-meta/tools-before-install.tsv` y
`00-meta/tools.tsv`. Un fallo opcional no borra el trabajo: REKON registra el
error, usa el fallback disponible y continúa. El manifiesto auditable está en
[`requirements-tools.tsv`](requirements-tools.tsv).

Opciones relacionadas:

```bash
--install-deps   # autoriza instalación en modo no interactivo
--no-install     # no pregunta ni instala
--doctor         # inventario local, sin instalar ni escanear
```

La disponibilidad y versiones dependen de la distribución. Gobuster actual
requiere una versión reciente de Go; si la del repositorio es antigua, el fallo
queda registrado y FFUF/Feroxbuster siguen disponibles cuando se instalaron.

## Perfiles TCP y UDP

| Perfil | TCP | UDP | Web/DNS | Límites iniciales |
|---|---|---|---|---|
| `passive` | No | No | OSINT y consultas básicas | 8 hilos, 10/s, 50 hosts |
| `balanced` | top 1000 | top 50 con privilegios | listas medianas, FFUF | 20 hilos, 50/s, 100 hosts |
| `deep` | 1–65535 | top 200 con privilegios | listas grandes y motores complementarios | 35 hilos, 100/s, 300 hosts |

Puedes sustituir ambos conjuntos:

```bash
# Puertos concretos y rangos
./rekon.sh -t 192.168.56.20 -w /usr/share/seclists \
  --tcp-ports 22,80,443,8000-9000 \
  --udp-ports 53,67-69,123,161,500 \
  --sudo-scans --accept-authorized-use --non-interactive

# Valores admitidos: none, all, top50, top100, top200 y top1000
--tcp-ports top1000
--udp-ports top200
```

Sin privilegios, Nmap usa TCP connect (`-sT`) y UDP se omite con un aviso
explícito. Con `--sudo-scans` o ejecutando ya como root, usa SYN (`-sS`), UDP
(`-sU`) y detección de SO. `--no-sudo-scans` desactiva esas capacidades incluso
si la sesión ya es privilegiada.

Los topes duros son 200 hilos, 10.000 operaciones/s y 5.000 hosts. Ajustes:

```bash
--threads 15 --rate 30 --max-hosts 20
```

## Herramienta elegida por tarea

| Tarea | Principal | Complemento o fallback |
|---|---|---|
| Pasivo | Subfinder | Assetfinder, Amass, Findomain, crt.sh |
| DNS masivo | Puredns + Massdns + resolvers | Dnsx, Gobuster, Dnsrecon |
| TCP | Naabu | Masscan para IP si falta Naabu; Nmap valida siempre |
| UDP/servicios/SO | Nmap | — |
| HTTP | httpx | Curl, WhatWeb, WAFW00F |
| Crawling | Katana | Hakrawler, gau, waybackurls |
| Directorios/ficheros | FFUF | Feroxbuster profundo, Gobuster fallback |
| Vhosts | FFUF | Gobuster en `deep` |
| Parámetros | FFUF | Arjun GET en `deep` |
| TLS | testssl.sh | sslscan, OpenSSL |
| Observaciones | Nuclei no intrusivo | — |
| Capturas | Gowitness | — |

La combinación se elige por función. No se ejecutan dos escáneres completos de
puertos sin motivo: Naabu/Masscan descubren y Nmap valida; los motores web
adicionales se reservan al perfil `deep` o funcionan como fallback.

## Selección automática de diccionarios

REKON recorre una sola vez el árbol indicado y puntúa los candidatos por nombre,
ruta, tamaño y perfil. Reconoce `.txt`, `.lst`, `.dic`, `.wordlist` y `.words`.

| Rol | Patrones favorecidos |
|---|---|
| Subdominios/vhosts | `subdomains-top1million-*`, `dns-Jhaddix`, `bitquark` |
| Directorios | `raft-medium-directories`, `directory-list-2.3-medium`, `common.txt` |
| Ficheros | `raft-medium-files`, `raft-medium-words`, `quickhits` |
| Parámetros | `burp-parameter-names`, `parameters`, `params` |
| Resolvers | `resolvers.txt`, `public-dns`, rutas `dnsvalidator` |

Las listas de contraseñas, credenciales, hashes y fugas se excluyen. Cada lista
elegida se limpia, limita y copia dentro del expediente. Puredns solo se usa si
también encuentra Massdns y una lista de resolvers; de lo contrario usa Dnsx.
Para nombres internos/especiales no utiliza Puredns con resolvers públicos. La
persona operadora debe revisar que la lista de resolvers sea apropiada para su
alcance. La decisión queda en `00-meta/selected-wordlists.tsv`.

## Control por módulos

```bash
# Solo superficie web al reanudar una ejecución
./rekon.sh -t app.lab.example -w /usr/share/seclists \
  --resume ./rekon-output/app_lab_example_20260819T080000Z \
  --only http,crawl,fuzz,tls,report \
  --no-install --accept-authorized-use --non-interactive

# Todo excepto Nuclei y capturas
./rekon.sh -t 192.168.56.20 -w /usr/share/seclists \
  --skip observations,screenshots \
  --accept-authorized-use --non-interactive
```

Módulos: `target`, `passive`, `dns`, `ports`, `services`, `http`, `crawl`,
`fuzz`, `tls`, `observations`, `screenshots`, `report`. La reanudación reutiliza
marcadores `.done` y rechaza mezclar un directorio con otro objetivo.

Las fuentes externas reciben necesariamente el dominio consultado. Se omiten
para sufijos internos/especiales (`.local`, `.test`, `.invalid`, `.internal`,
`.lan`, `.home.arpa`, etc.). Para desactivarlas en cualquier dominio:

```bash
--no-external-osint
```

## Estructura de resultados

```text
objetivo_TIMESTAMP/
├── 00-meta/              objetivo, perfil, herramientas, política y listas
├── 01-target/            DNS base, WHOIS/RIR
├── 02-passive/           fuentes pasivas y hosts normalizados
├── 03-dns/               resolución, registros, fuerza DNS y AXFR
├── 04-ports/             Naabu/Masscan/Nmap TCP y Nmap UDP
├── 05-services/          matriz y enumeración segura por protocolo
├── 06-http/              httpx, cabeceras, fingerprint, WAF y capturas
├── 07-crawl/             endpoints, JavaScript y candidatos API
├── 08-fuzzing/           FFUF, Feroxbuster, Gobuster y Arjun
├── 09-tls/               certificados y configuración TLS
├── 10-observations/      Nuclei no intrusivo
├── logs/                 comandos, stdout/stderr, estados y tiempos
├── report/               REKON-report.md, summary.json y HTML opcional
└── SHA256SUMS            integridad de las evidencias
```

## Pruebas

```bash
bash -n rekon.sh
bash rekon.sh --self-test
bash tests/smoke.sh
shellcheck -x rekon.sh tests/smoke.sh
```

Las pruebas de humo usan dominios reservados y `--dry-run`: no instalan paquetes
ni generan tráfico. Verifican instalación planificada, perfiles TCP/UDP, motores
web profundos, rutas con espacios, informes y exclusiones Nuclei.

## Decisiones de seguridad

- Todos los comandos usan arrays y argumentos citados; no se usa `eval`.
- La instalación requiere consentimiento y los privilegios de escaneo tienen una
  autorización independiente.
- HTTP se limita a GET/HEAD; Arjun se ejecuta solo en modo GET.
- NSE se limita a `safe` y excluye `brute`, `dos`, `exploit`, `intrusive` y
  `fuzzer`.
- Nuclei excluye `dos`, `fuzzing`, `bruteforce`, `intrusive`, `exploit`, `code`,
  `headless` y `oast`, y desactiva Interactsh.
- SMB y LDAP solo intentan consultas anónimas; no se adivinan credenciales ni
  comunidades SNMP.
- Los resultados son observaciones, no vulnerabilidades confirmadas; requieren
  validación manual.

Un TCP completo o UDP amplio puede durar horas y generar mucho tráfico. Empieza
con `balanced`, reduce `--rate` cuando el laboratorio sea pequeño y usa `deep`
solo cuando la ventana y el alcance lo permitan.

## Documentación oficial de instalación y uso

- [ProjectDiscovery Tool Manager](https://docs.projectdiscovery.io/opensource/pdtm/install)
- [Naabu](https://docs.projectdiscovery.io/opensource/naabu/running)
- [Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/running)
- [FFUF](https://github.com/ffuf/ffuf)
- [Gobuster](https://github.com/OJ/gobuster)
- [Feroxbuster](https://epi052.github.io/feroxbuster-docs/docs/installation/install-kali/)
- [Arjun](https://github.com/s0md3v/Arjun)
- [Hakrawler](https://github.com/hakluke/hakrawler)
- [Puredns](https://github.com/d3mondev/puredns)
- [Nmap NSE](https://nmap.org/book/nse-usage.html)

## Mejoras futuras

- lockfile opcional con versiones y hashes fijados;
- contenedor reproducible para entornos sin gestor compatible;
- diff entre ejecuciones y exportación SARIF/HTML enriquecido;
- perfiles separados para Active Directory, API, cloud y OT;
- fuentes pasivas con API keys gestionadas por el usuario.

## Licencia y responsabilidad

MIT. Utiliza REKON únicamente sobre sistemas propios o con autorización escrita.
La persona operadora conserva la responsabilidad sobre alcance, ventana, tasa y
tratamiento de evidencias.
