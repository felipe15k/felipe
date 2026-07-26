#!/usr/bin/env python3
"""
recon_pro.py - Analisador passivo de arquivos JS para bug bounty.

Descobre subdomínios, coleta URLs de arquivos JS/JSON (gau/waybackurls/katana),
opcionalmente cruza com padrões do `gf`, e analisa o conteúdo em busca de
segredos vazados (com filtro de entropia) e endpoints sensíveis.

Requisitos externos (opcionais, mas recomendados):
    subfinder, gau, waybackurls, katana, gf

Uso:
    python3 recon_pro.py -u alvo.com
    python3 recon_pro.py -l dominios.txt --scope escopo.txt --threads 20 --delay 0.5
"""

import argparse
import base64
import hashlib
import json
import logging
import math
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin

import requests

try:
    import requests_cache
    HAS_REQUESTS_CACHE = True
except ImportError:
    HAS_REQUESTS_CACHE = False

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn,
        TimeElapsedColumn, TimeRemainingColumn, MofNCompleteColumn,
    )
    from rich.console import Console
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# --- CONFIGURAÇÃO PADRÃO ---
OUTPUT_DIR = "recon_pro_output"
REPORT_JSON = "intelligence_report.json"
TEMP_JS_DIR = "temp_js_files"
LOG_FILE = "recon.log"
DEFAULT_MAX_WORKERS = 10
DEFAULT_TIMEOUT = 8
DEFAULT_RETRIES = 2
DEFAULT_DELAY = 0.0
DEFAULT_TOOL_TIMEOUT = 600  # gau/waybackurls/katana em lote podem demorar bastante em alvos grandes
DEFAULT_KATANA_CONCURRENCY = 25
MIN_ENTROPY = 3.5  # fallback p/ padrões sem threshold específico

# Thresholds de entropia por tipo de segredo (cada formato tem "aleatoriedade" natural diferente)
ENTROPY_THRESHOLDS = {
    "AWS Secret Key": 4.0,
    "Google API Key": 3.9,
    "Generic JWT": 4.2,
    "Generic Secret Assignment": 3.7,
    "Slack Token": 3.5,
    "Stripe Live Secret Key": 3.5,
    "Stripe Live Publishable Key": 3.5,
    "SendGrid API Key": 3.8,
    "Twilio API Key": 3.3,       # hex puro tem entropia teórica menor que base64/alfanumérico misto
    "Twilio Account SID": 3.0,   # idem -- hex puro
    "npm Access Token": 3.8,
    "GitHub Token (outros escopos)": 3.8,
    "GitHub Fine-grained PAT": 3.8,
    "Azure Client Secret": 3.9,
    "Mailgun API Key": 3.7,
    "Generic Bearer Token": 3.8,
}

# Padrões cujo match inteiro é estrutural (URL fixa + token, connection string, JSON
# marker) e não um blob aleatório -- medir entropia da string INTEIRA nesses casos
# derruba o score artificialmente por causa da parte fixa (ex: "https://discord.com/
# api/webhooks/" tem muita repetição de char legível). A validade já vem do formato
# batido pelo regex, não faz sentido filtrar por entropia aqui.
ENTROPY_EXEMPT_TYPES = {
    "Private Key", "Discord Webhook", "Database Connection String",
    "Azure Storage Connection String", "Firebase/GCP Service Account",
    "Heroku API Key",
}

EXTERNAL_TOOLS = ["subfinder", "gau", "waybackurls", "katana"]  # gf é opcional à parte

# Padrões de Segredos (Alta Precisão)
SECRET_PATTERNS = {
    "AWS Access Key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token": r"ghp_[A-Za-z0-9]{36}",
    "GitHub Token (outros escopos)": r"gh[oprsu]_[A-Za-z0-9]{36}",
    "GitHub Fine-grained PAT": r"github_pat_[A-Za-z0-9_]{22,}",
    "Generic JWT": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "Private Key": r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z-]{10,48}",
    "Stripe Live Secret Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Live Publishable Key": r"pk_live_[0-9a-zA-Z]{24,}",
    "SendGrid API Key": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twilio Account SID": r"AC[a-f0-9]{32}",
    "npm Access Token": r"npm_[A-Za-z0-9]{36}",
    "Azure Storage Connection String": r"DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{20,}",
    "Azure Client Secret": r"(?i)client_secret\s*[:=]\s*['\"][A-Za-z0-9_.\-~]{34,40}['\"]",
    "Firebase/GCP Service Account": r'"type":\s*"service_account"',
    "Heroku API Key": r"(?i)heroku[a-z0-9_\-]{0,20}\s*[:=]\s*['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
    "OpenAI API Key": r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
    "Anthropic API Key": r"sk-ant-(?:api03-)?[A-Za-z0-9_\-]{90,}",
    "Database Connection String": r"(?i)(postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[A-Za-z0-9_.\-]+:[^@\s'\"]{4,}@[A-Za-z0-9_.\-]+(?::\d+)?/[A-Za-z0-9_.\-]*",
    "Generic Bearer Token": r"(?i)bearer\s+[A-Za-z0-9_\-.=]{20,}",
    "Generic Secret Assignment": r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"]([A-Za-z0-9_\-/+=]{16,})['\"]",
}

# Valores que batem no regex mas são exemplos oficiais de documentação, placeholders
# de tutorial, ou "secrets de exemplo" amplamente conhecidos -- não são vazamentos reais.
# Comparação é case-insensitive.
KNOWN_PLACEHOLDER_SECRETS = {
    # AWS -- exemplos oficiais da documentação da AWS
    "akiaiosfodnn7example",
    "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
    # Google -- placeholder usado em inúmeros tutoriais/exemplos copiados
    "aizasyabcdefghijklmnopqrstuvwxyz1234567",
    # GitHub -- placeholders comuns em READMEs/exemplos de configuração
    "ghp_000000000000000000000000000000000",
    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    # JWT de exemplo do jwt.io (o token de demonstração oficial do site)
    "eyjhbgcioijiuzi1niisinr5cci6ikpxvcj9.eyjzdwiioiixmjm0ntY3odkwiiwibmftzsi6ikpvag4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    # Genéricos que aparecem demais em exemplos de código
    "your_api_key_here",
    "your-api-key-here",
    "changeme",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "0000000000000000000000000000000000000000",
}

# Padrões de Endpoints (Foco em API e Admin)
API_PATTERNS = [
    r'["\'](/api/v\d+/[^"\']+)["\']',
    r'["\'](/graphql[^"\']*)["\']',
    r'["\'](/rest/[^"\']+)["\']',
    r'["\'](/internal/[^"\']+)["\']',
    r'["\'](/admin/[^"\']+)["\']',
    r'["\'](/manage/[^"\']+)["\']',
    r'["\'](/auth/[^"\']+)["\']',
    r'["\'](wss?://[^"\']+)["\']',
]

# Buckets/blobs de cloud storage referenciados no bundle. Achado de alto valor
# à parte de endpoint de API normal -- bucket mal configurado (list/write público)
# é uma classe de vuln própria, então extraímos e reportamos separado em vez de
# forçar no mesmo formato de "endpoint" de rota de API.
STORAGE_BUCKET_PATTERNS = {
    "AWS S3": r"([a-z0-9.\-]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com|s3\.amazonaws\.com/[a-z0-9.\-]+)",
    "Google Cloud Storage": r"storage\.googleapis\.com/[a-z0-9._\-]+",
    "Azure Blob Storage": r"[a-z0-9]+\.blob\.core\.windows\.net(?:/[a-z0-9._\-]+)?",
}

HIGH_VALUE_KEYWORDS = [
    "admin", "root", "superuser", "config", "secret", "backup",
    "db", "database", "token", "key", "password", "internal",
]

NOISE_MARKERS = ['.css', '.js', '.png', '.jpg', '.svg', '/static/', '/assets/', 'cdn', 'analytics']

# Segmentos de path que, isolados, indicam telemetria/analytics/observabilidade --
# não rota de negócio. Diferente de KNOWN_LIBRARY_SIGNATURES (que exige várias
# assinaturas batendo pra CONFIRMAR uma lib específica), isso rebaixa qualquer
# endpoint que bata em UM desses termos, mesmo sem confirmar de qual lib é.
# É o que resolve o caso real do "/api/v1/track" do gmp-lib aparecendo como HIGH
# em 15 arquivos diferentes sem nunca bater o limiar de 3 assinaturas do Segment.
TELEMETRY_PATH_MARKERS = [
    "/track", "/telemetry", "/beacon", "/metrics", "/pixel", "/collect",
    "/analytics", "/event", "/log", "/ping", "/heartbeat", "/sampling",
]

# --- Heurísticas anti-ruído ---

# Bate com identificadores tipo CONSTANT_NAME / Redux action type
# (ex: "REQUEST_CHANGE_PASSWORD", "PRIORITY_FEE_DISCOUNT_SOURCE_TYPE_TOKEN").
# Esses valores batem no regex "Generic Secret Assignment" só porque a
# palavra "token"/"password"/"secret" aparece dentro do NOME da constante --
# não são segredos, são nomes simbólicos. Secret de verdade quase nunca é
# UPPER_SNAKE_CASE puro (token/hash/chave costuma ter case misto, dígitos
# intercalados, ou charset base64/hex). Exige >=2 underscores pra evitar
# derrubar siglas curtas legítimas tipo "API_KEY" isolado.
CONSTANT_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){2,}$")

# Bate com string que é claramente um path de rota (ex: "/signup/reset_password"),
# não um valor de secret. O regex de "Generic Secret Assignment" casa em cima do
# NOME da variável (token/secret/password/key), então uma linha de código tipo
# `path: "/signup/reset_password"` é capturada mesmo sem ter secret nenhum --
# a palavra "password" está no path, não no conteúdo sensível.
LOOKS_LIKE_PATH_PATTERN = re.compile(r"^/[\w\-.]+(?:/[\w\-.:{}]*)+/?$")

# Bate com identificador camelCase puro (só letras, sem dígito/símbolo), tipo
# "resetPasswordToken" ou "authBypassFlag" -- mesma ideia do CONSTANT_NAME_PATTERN,
# só que pro estilo de nome de variável em vez de UPPER_SNAKE_CASE. Secret real
# (token/hash/chave gerada) quase sempre tem dígito ou símbolo misturado por causa
# do charset base64/hex/random; um valor 100% alfabético com case misto e sem
# nenhum dígito é muito mais provável ser um identificador de código.
CAMEL_CASE_IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-zA-Z]*[A-Z][a-zA-Z]*$")

# Tipos de "secret" que são client-side público por design -- a proteção
# real é a restrição configurada no provedor (domínio/referrer/API habilitada),
# não o sigilo do valor. Não descartamos (pode ainda valer checar se está
# sem restrição), só rebaixamos a confiança e anotamos o motivo.
PUBLIC_BY_DESIGN_SECRET_TYPES = {
    "Google API Key",
    "Stripe Live Publishable Key",  # "publishable" é literalmente pra ser público
    "Twilio Account SID",           # SID identifica a conta, não autentica sozinho (o Auth Token sim)
}

# Marcadores de host/path que indicam página de documentação pública de API
# (não endpoint interno vazado). Usado pra rebaixar severidade de endpoints
# encontrados em JS servido por essas origens.
DOC_PAGE_MARKERS = [
    "developer.", "developers.", "docs.", "api-docs", "apidocs",
    "/swagger", "/redoc", "/openapi", "readme.io",
]

# Se um ÚNICO arquivo JS despeja mais endpoints "high severity" do que isso,
# é mais provável que seja a superfície de API COMPLETA de uma lib vendorizada
# (SDK de pagamento, block explorer, etc.) empacotada no bundle inteira, e não
# rotas custom do backend do alvo escritas ali de propósito.
VENDORED_LIBRARY_ENDPOINT_THRESHOLD = 15

# Assinaturas (substrings de path) de APIs de libs/serviços de terceiros bem
# conhecidas. Se um arquivo tem várias dessas batendo ao mesmo tempo, dá pra
# CONFIRMAR que é uma lib vendorizada específica (não só "muito endpoint junto"
# por volume). MIN_LIBRARY_SIGNATURE_MATCHES = quantas substrings distintas
# da mesma lib precisam bater pra considerar confirmado.
MIN_LIBRARY_SIGNATURE_MATCHES = 3

KNOWN_LIBRARY_SIGNATURES = {
    "Blockscout (block explorer)": [
        "smart-contracts/verification", "optimism/output-roots", "validators/zilliqa",
        "tokens/bridged", "internal-transactions", "config/backend-version", "config/celo",
    ],
    "Stripe API/Elements": [
        "/v1/payment_intents", "/v1/setup_intents", "/v1/sources", "/v1/tokens", "/v1/payment_methods",
    ],
    "Auth0": [
        "/oauth/token", "/userinfo", "/.well-known/jwks.json", "/dbconnections/", "/passwordless/",
    ],
    "Algolia": [
        "/1/indexes/", "/1/keys", "/1/clusters",
    ],
    "Segment Analytics": [
        "/v1/batch", "/v1/identify", "/v1/track", "/v1/page", "/v1/alias",
    ],
    "Auth0/Firebase Identity Toolkit": [
        "/identitytoolkit/v3/", "/securetoken/v1/",
    ],
}

# Fetch e re-scan de source maps expostos (ver check_source_map). Limites pra
# não deixar um único bundle com map gigante explodir tempo/memória do scan.
SOURCE_MAP_MAX_SOURCES_TO_SCAN = 40
SOURCE_MAP_MAX_CONTENT_LEN = 200_000


# --------------------------------------------------------------------------
# Setup / utilidades
# --------------------------------------------------------------------------

def sanitize_folder_name(name):
    """Transforma um domínio/identificador em nome de pasta seguro."""
    name = name.strip().lower()
    name = re.sub(r"^https?://", "", name)
    name = name.rstrip("/")
    name = re.sub(r"[^a-z0-9._-]", "_", name)
    return name or "recon_run"


HISTORY_DIRNAME = ".recon_history"  # sobrevive à limpeza de pastas antigas -- guarda o último relatório por alvo p/ diff


def resolve_run_dir(base_dir, args):
    """Decide o nome da pasta desta execução (baseado no domínio/lista) e,
    por padrão, apaga pastas de execuções anteriores dentro de base_dir,
    mantendo só a desta execução. Use --keep-old pra desativar a limpeza.
    Roda antes do logging estar configurado, por isso usa print()."""
    if args.u:
        raw = args.u if not args.u.startswith("http") else urlparse(args.u).netloc
        run_name = sanitize_folder_name(raw)
    else:
        run_name = sanitize_folder_name(os.path.splitext(os.path.basename(args.l))[0])

    os.makedirs(base_dir, exist_ok=True)

    if not args.keep_old:
        for entry in os.listdir(base_dir):
            if entry == HISTORY_DIRNAME:
                continue  # nunca apaga o histórico de diffs entre execuções
            entry_path = os.path.join(base_dir, entry)
            if entry == run_name or not os.path.isdir(entry_path):
                continue
            try:
                shutil.rmtree(entry_path)
                print(f"[*] Pasta de execução anterior removida: {entry_path}")
            except OSError as e:
                print(f"[!] Não foi possível remover pasta antiga {entry_path}: {e}")

    run_dir = os.path.join(base_dir, run_name)
    if os.path.isdir(run_dir):
        # Mesmo domínio rodado de novo: começa limpo em vez de misturar dados velhos/novos
        try:
            shutil.rmtree(run_dir)
            print(f"[*] Execução anterior para '{run_name}' removida, começando do zero.")
        except OSError as e:
            print(f"[!] Não foi possível limpar pasta existente {run_dir}: {e}")

    os.makedirs(run_dir, exist_ok=True)
    return run_dir, run_name


def setup_logging(output_dir, verbose):
    os.makedirs(output_dir, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(message)s"

    logger = logging.getLogger("recon_pro")
    logger.setLevel(level)
    logger.handlers.clear()

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter(fmt, "%H:%M:%S"))
    ch.setLevel(level)
    logger.addHandler(ch)

    fh = logging.FileHandler(os.path.join(output_dir, LOG_FILE))
    fh.setFormatter(logging.Formatter(fmt))
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)

    return logger


def check_tools(tools, logger):
    """Verifica quais ferramentas externas estão disponíveis no PATH."""
    available = {}
    for tool in tools:
        path = shutil.which(tool)
        available[tool] = path is not None
        if path:
            logger.debug(f"Ferramenta encontrada: {tool} -> {path}")
        else:
            logger.warning(f"Ferramenta ausente no PATH: {tool} (funcionalidades relacionadas serão puladas)")
    return available


def load_scope(scope_file, logger):
    """Carrega lista de domínios/regex de escopo permitido. Retorna None se não usado (sem filtro)."""
    if not scope_file:
        return None
    if not os.path.isfile(scope_file):
        logger.error(f"Arquivo de escopo não encontrado: {scope_file}")
        sys.exit(1)
    with open(scope_file) as f:
        entries = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    logger.info(f"Escopo carregado: {len(entries)} entradas")
    return entries


def is_in_scope(host, scope_entries):
    """host bate com alguma entrada de escopo (match exato ou subdomínio)."""
    if scope_entries is None:
        return True
    host = host.lower()
    for entry in scope_entries:
        entry = entry.lower().lstrip("*.")
        if host == entry or host.endswith("." + entry):
            return True
    return False


def shannon_entropy(s):
    """Calcula entropia de Shannon de uma string. Strings aleatórias/tokens têm entropia alta."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def load_hash_cache(output_dir, logger):
    """Carrega cache de hashes de JS já processados, pra pular duplicatas entre execuções."""
    cache_path = os.path.join(output_dir, "hash_cache.json")
    if os.path.exists(cache_path):
        try:
            with open(cache_path) as f:
                cache = json.load(f)
            logger.debug(f"Cache de hashes carregado: {len(cache)} entradas")
            return cache
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Cache de hashes corrompido, ignorando: {e}")
    return {}


def save_hash_cache(cache, output_dir, logger):
    cache_path = os.path.join(output_dir, "hash_cache.json")
    try:
        with open(cache_path, "w") as f:
            json.dump(cache, f, indent=2)
        logger.debug(f"Cache de hashes salvo: {len(cache)} entradas")
    except OSError as e:
        logger.warning(f"Não foi possível salvar cache de hashes: {e}")


def decode_jwt_header(token):
    """Decodifica o header (1º segmento) de um JWT candidato. Devolve o dict
    decodificado se parecer plausível (tem 'alg' ou 'typ'), senão None."""
    import base64
    parts = token.split(".")
    if len(parts) < 2:
        return None
    header = parts[0]
    padded = header + "=" * (-len(header) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded)
        obj = json.loads(decoded)
        return obj if ("alg" in obj or "typ" in obj) else None
    except Exception:
        return None


def looks_like_jwt(token):
    return decode_jwt_header(token) is not None


# --------------------------------------------------------------------------
# UI helpers (rich > tqdm > texto simples)
# --------------------------------------------------------------------------

_console = Console() if HAS_RICH else None


def make_rich_progress(indeterminate=False):
    """Cria um objeto rich.Progress configurado. indeterminate=True omite a
    barra percentual/ETA (usado quando não sabemos o total de antemão, ex:
    saída de gau/waybackurls indo até o timeout)."""
    if not HAS_RICH:
        return None
    columns = [SpinnerColumn(), TextColumn("[progress.description]{task.description}")]
    if indeterminate:
        columns += [TextColumn("[cyan]{task.fields[count]} coletado(s)"), TimeElapsedColumn()]
    else:
        columns += [
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
        ]
    return Progress(*columns, console=_console)


# --------------------------------------------------------------------------
# Descoberta de ativos
# --------------------------------------------------------------------------

def run_cmd(cmd, timeout=60):
    """Recebe lista de argumentos (preferido) ou string (é splitada). Devolve stdout,
    string vazia em caso de timeout ou binário ausente."""
    if isinstance(cmd, str):
        cmd = cmd.split()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""
    except FileNotFoundError:
        return ""


def run_cmd_streaming(cmd, input_str=None, timeout=600, logger=None, label="tool", progress_every=200):
    """Roda UM processo (não um por alvo) e lê a saída linha a linha em tempo real,
    mostrando progresso conforme os resultados chegam. Ferramentas como gau/waybackurls/katana
    já paralelizam internamente quando recebem uma lista de alvos de uma vez (via stdin ou
    -list), então isso evita spawnar milhares de subprocessos sequenciais.

    Total de resultados é desconhecido de antemão, então o progresso é um spinner com
    contador ao vivo (rich, se disponível) em vez de uma barra percentual.

    Um watchdog (threading.Timer) mata o processo se ele exceder o timeout, mesmo que
    esteja bloqueado esperando rede sem produzir nenhuma linha nova."""
    lines = []
    if not shutil.which(cmd[0]):
        if logger:
            logger.warning(f"[{label}] binário '{cmd[0]}' não encontrado, pulando")
        return lines

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if input_str is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        if logger:
            logger.warning(f"[{label}] binário não encontrado")
        return lines

    timed_out = {"flag": False}

    def _kill_on_timeout():
        timed_out["flag"] = True
        proc.kill()

    watchdog = threading.Timer(timeout, _kill_on_timeout)
    watchdog.start()

    if input_str is not None:
        def _feed():
            try:
                proc.stdin.write(input_str)
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        threading.Thread(target=_feed, daemon=True).start()

    progress = make_rich_progress(indeterminate=True)
    task_id = None
    if progress:
        progress.start()
        task_id = progress.add_task(f"[bold]{label}[/bold]", count=0)

    try:
        for line in proc.stdout:
            line = line.strip()
            if line:
                lines.append(line)
                if progress:
                    progress.update(task_id, count=len(lines))
                elif logger and len(lines) % progress_every == 0:
                    logger.info(f"[{label}] {len(lines)} resultado(s) coletado(s) até agora...")
    finally:
        watchdog.cancel()
        proc.wait(timeout=5)
        if progress:
            progress.update(task_id, description=f"[bold]{label}[/bold] concluído")
            progress.stop()

    if timed_out["flag"] and logger:
        logger.warning(f"[{label}] excedeu timeout de {timeout}s, interrompido com {len(lines)} resultado(s)")

    return lines


# Paths de arquivo sensível bem conhecidos que às vezes acabam publicados por
# engano em deploy (configuração de CI copiando .env junto, .git não removido
# do build de produção, etc). Isso é leitura passiva de path público conhecido --
# mesma categoria de checagem que ferramentas como nuclei fazem em templates
# "exposures/", não é exploração de nada. Uma request por ALVO (domínio), não
# por arquivo JS, então o custo é baixo mesmo em escopo grande.
WELL_KNOWN_SENSITIVE_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.production",
    "/.env.local",
    "/.aws/credentials",
    "/config.json.bak",
    "/wp-config.php.bak",
    "/docker-compose.yml",
    "/.DS_Store",
    "/backup.sql",
    "/.vscode/sftp.json",
]

# Marcadores de conteúdo que confirmam que a resposta É o arquivo esperado (não
# um fallback de SPA/página de erro custom devolvendo 200 com HTML genérico pra
# tudo). Sem isso, "status 200" sozinho gera falso positivo maciço em SPAs.
SENSITIVE_PATH_CONTENT_MARKERS = {
    "/.git/HEAD": ["ref:"],
    "/.git/config": ["[core]", "[remote"],
    "/.env": ["="],
    "/.env.production": ["="],
    "/.env.local": ["="],
    "/.aws/credentials": ["aws_access_key_id"],
    "/docker-compose.yml": ["version:", "services:"],
    "/.vscode/sftp.json": ["\"host\""],
}


def _response_signature(resp):
    """Assinatura barata pra comparar respostas: status + content-type + tamanho
    do corpo arredondado. Serve pra identificar 'catch-all' (servidor que devolve
    sempre a mesma coisa pra path inexistente, independente do path)."""
    body_len = len(resp.content) if resp.content else 0
    return (resp.status_code, resp.headers.get("Content-Type", "").split(";")[0].strip().lower(), body_len)


def check_well_known_exposures(session, base_url, timeout, logger):
    """Checa presença de arquivos sensíveis bem conhecidos na raiz do alvo.
    GET read-only, sem nenhuma tentativa de escrita/exploração -- só confirma
    se o arquivo está acessível publicamente.

    Antes de checar qualquer path real, pega a assinatura de resposta de um path
    aleatório GARANTIDAMENTE inexistente (baseline de 404/catch-all). Muita API
    devolve 200 + JSON de erro genérico pra QUALQUER rota desconhecida (em vez de
    404), o que não é fallback de HTML e passaria despercebido pelo filtro de SPA
    sozinho -- por isso o filtro de Content-Type:text/html não é suficiente aqui,
    e a comparação contra o baseline é o que realmente evita o falso positivo em
    massa (mesmo host "achando" .DS_Store, backup.sql, wp-config.php.bak etc de
    uma vez só é a assinatura clássica de catch-all, não achado real)."""
    canary_path = f"/__recon_canary_{uuid.uuid4().hex[:12]}.txt"
    try:
        baseline_resp = session.get(urljoin(base_url, canary_path), timeout=timeout)
        baseline_sig = _response_signature(baseline_resp)
    except requests.RequestException as e:
        logger.debug(f"Falha ao pegar baseline de 404 em {base_url}: {e}")
        return []

    found = []
    for path in WELL_KNOWN_SENSITIVE_PATHS:
        try:
            full = urljoin(base_url, path)
            resp = session.get(full, timeout=timeout)
            if resp.status_code != 200:
                continue
            if _response_signature(resp) == baseline_sig:
                # mesma assinatura do path aleatório que não existe -- catch-all, ignora
                continue
            content_type = resp.headers.get("Content-Type", "").lower()
            if "text/html" in content_type:
                # provável fallback de SPA -- servidor devolve 200+HTML pra qualquer coisa.
                continue
            body = resp.text[:2000]
            markers = SENSITIVE_PATH_CONTENT_MARKERS.get(path)
            if markers and not any(m in body for m in markers):
                continue
            found.append({"path": path, "url": full, "content_type": content_type})
            logger.warning(f"[EXPOSED FILE] {full}")
        except requests.RequestException as e:
            logger.debug(f"Falha ao checar {path} em {base_url}: {e}")
    return found


def check_cors_misconfiguration(session, base_url, timeout, logger):
    """Checagem passiva: manda um Origin arbitrário e vê se o servidor reflete
    ele de volta em Access-Control-Allow-Origin (em vez de um allowlist fixo)
    E permite credenciais junto -- essa combinação é uma vuln clássica (qualquer
    site pode ler resposta autenticada da API via fetch com credentials:'include').
    Não tenta explorar nada, só observa os headers da resposta a uma request
    GET normal com um header Origin custom -- isso não é diferente do que
    QUALQUER site já faz normalmente numa request cross-origin."""
    probe_origin = "https://recon-cors-probe.invalid"
    try:
        resp = session.get(base_url, timeout=timeout, headers={"Origin": probe_origin})
    except requests.RequestException as e:
        logger.debug(f"Falha na checagem de CORS em {base_url}: {e}")
        return None

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == probe_origin and acac == "true":
        logger.warning(f"[CORS MISCONFIG] {base_url}: reflete Origin arbitrário "
                        f"COM Allow-Credentials=true")
        return {"url": base_url, "severity": "CRITICAL",
                "detail": "Access-Control-Allow-Origin reflete qualquer Origin enviado "
                           "e Access-Control-Allow-Credentials=true -- qualquer site "
                           "pode ler respostas autenticadas via fetch()."}
    if acao == "*":
        # com * simples (sem credentials) o impacto é bem menor -- só dados já públicos
        return {"url": base_url, "severity": "MEDIUM",
                "detail": "Access-Control-Allow-Origin: * (sem credentials -- impacto "
                           "limitado a endpoints que não dependem de autenticação)."}
    return None


def discover_assets(domain, tools_available, scope_entries, logger):
    subs = {domain}
    if tools_available.get("subfinder"):
        logger.info(f"Rodando subfinder em {domain}...")
        out = run_cmd(["subfinder", "-d", domain, "-silent"], timeout=120)
        found = [s.strip() for s in out.splitlines() if s.strip()]
        subs.update(found)
        logger.info(f"subfinder encontrou {len(found)} subdomínios")
    else:
        logger.warning("subfinder indisponível, usando apenas o domínio raiz")

    in_scope = [s for s in subs if is_in_scope(s, scope_entries)]
    dropped = len(subs) - len(in_scope)
    if dropped:
        logger.warning(f"{dropped} subdomínio(s) descartado(s) por estarem fora do escopo")

    return [f"https://{s}" for s in in_scope]


def get_js_urls(targets, tools_available, gf_available, args, logger):
    all_js = set()
    all_urls = set()

    # Lista de hosts "nus" (sem esquema) pra alimentar gau/waybackurls via stdin,
    # e lista de URLs completas (com https://) pro -list do katana.
    hosts = [t.replace("https://", "").replace("http://", "") for t in targets]
    hosts_stdin = "\n".join(hosts)

    logger.info(f"Coletando URLs históricas/crawl para {len(targets)} alvo(s) em lote "
                f"(1 processo por ferramenta, não 1 por subdomínio)...")

    if tools_available.get("gau"):
        logger.info("Rodando gau em lote...")
        lines = run_cmd_streaming(["gau"], input_str=hosts_stdin, timeout=args.tool_timeout,
                                   logger=logger, label="gau")
        all_urls.update(lines)
        logger.info(f"gau retornou {len(lines)} URL(s)")

    if tools_available.get("waybackurls"):
        logger.info("Rodando waybackurls em lote...")
        lines = run_cmd_streaming(["waybackurls"], input_str=hosts_stdin, timeout=args.tool_timeout,
                                   logger=logger, label="waybackurls")
        all_urls.update(lines)
        logger.info(f"waybackurls retornou {len(lines)} URL(s)")

    if tools_available.get("katana"):
        targets_file = os.path.join(args.output_dir, "katana_targets.txt")
        with open(targets_file, "w") as f:
            f.write("\n".join(targets))
        logger.info(f"Rodando katana em lote (-list, concorrência={args.katana_concurrency})...")
        cmd = [
            "katana", "-list", targets_file, "-d", "2", "-silent",
            "-ef", "woff,css,png,jpg,svg,map",
            "-c", str(args.katana_concurrency),
        ]
        lines = run_cmd_streaming(cmd, timeout=args.tool_timeout, logger=logger, label="katana")
        all_urls.update(lines)
        logger.info(f"katana retornou {len(lines)} URL(s)")

    # Normaliza: algumas ferramentas ocasionalmente devolvem host/path sem esquema
    all_urls = {
        (u if u.startswith(("http://", "https://")) else f"https://{u}")
        for u in all_urls
    }

    # Filtra JS/JSON diretamente
    for url in all_urls:
        if url.endswith((".js", ".json")):
            all_js.add(url)

    # Cruza com padrões do gf (ex: gf urls, gf endpoints) se disponível
    if gf_available and all_urls:
        logger.info("Cruzando URLs coletadas com padrões do gf...")
        try:
            proc = subprocess.run(
                ["gf", "urls"],
                input="\n".join(all_urls),
                capture_output=True,
                text=True,
                timeout=60,
            )
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line.endswith((".js", ".json")):
                    all_js.add(line)
        except Exception as e:
            logger.debug(f"gf falhou ou não configurado corretamente: {e}")

    logger.info(f"Total de arquivos JS/JSON únicos: {len(all_js)}")
    return list(all_js)


# --------------------------------------------------------------------------
# Análise de conteúdo
# --------------------------------------------------------------------------

def classify_endpoint(endpoint):
    ep_lower = endpoint.lower()
    if any(kw in ep_lower for kw in HIGH_VALUE_KEYWORDS):
        return "CRITICAL"
    if "/api/" in ep_lower or "/graphql" in ep_lower:
        return "HIGH"
    return "MEDIUM"


def is_likely_doc_page(url):
    """Heurística: o JS que originou o achado veio de um subdomínio/path típico
    de portal de documentação de API pública (ex: developer.exemplo.com,
    docs.exemplo.com, /swagger, readme.io)? Se sim, os "endpoints" ali dentro
    provavelmente são a própria doc da API pública sendo renderizada como SPA,
    não uma listagem de rotas internas vazadas."""
    u_lower = url.lower()
    return any(marker in u_lower for marker in DOC_PAGE_MARKERS)


def verify_endpoint(session, base_url, endpoint, timeout, logger):
    """Validação ativa leve: HEAD request pra confirmar se o endpoint existe de fato
    (em vez de ser só uma string morta dentro do JS minificado).

    Detecta também o caso clássico de SPA: o servidor devolve 200 + text/html
    (a própria index.html) pra QUALQUER rota não mapeada, porque o roteamento
    real acontece no client-side. Isso NÃO significa que o endpoint de API
    existe -- só que o servidor não deu 404 pra ele. Retorna a string especial
    "SPA_FALLBACK" nesse caso em vez do código 200, pra não ser tratado como
    confirmação de achado real."""
    try:
        full = urljoin(base_url, endpoint)
        resp = session.head(full, timeout=timeout, allow_redirects=True)
        status = resp.status_code
        content_type = resp.headers.get("Content-Type", "").lower()
        looks_like_api_path = "/api/" in endpoint or "/graphql" in endpoint
        if status == 200 and "text/html" in content_type and looks_like_api_path:
            return "SPA_FALLBACK"
        return status
    except requests.RequestException as e:
        logger.debug(f"Falha ao validar endpoint {endpoint}: {e}")
        return None


def extract_secrets(data, logger, source_label=None):
    """Extrai secrets de um blob de texto (JS minificado OU código-fonte original
    vindo de source map), aplicando todos os filtros anti-ruído. source_label é
    opcional -- usado quando o texto veio de dentro de um source map, pra marcar
    de qual arquivo original ele saiu."""
    found = []

    for name, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, data):
            # Regexes com grupo de captura (ex: prefixo AWS, algoritmo da chave privada,
            # nome da variável) fariam re.findall devolver só o grupo em vez do match
            # inteiro. Usar finditer + group(N) explícito evita isso.
            if name == "Generic Secret Assignment":
                clean = match.group(2)  # grupo 2 = valor real do secret, não o nome da chave
            else:
                clean = match.group(0)  # match completo (a maioria dos padrões não tem grupo útil pro valor)
            clean = clean.strip()

            if len(clean) <= 5:
                continue

            if clean.lower() in KNOWN_PLACEHOLDER_SECRETS:
                logger.debug(f"Descartado por ser placeholder/exemplo conhecido ({name}): {clean[:30]}...")
                continue

            jwt_header = None
            if name == "Generic JWT":
                jwt_header = decode_jwt_header(clean)
                if jwt_header is None:
                    continue
            elif name not in ENTROPY_EXEMPT_TYPES:
                # entropia só faz sentido pra segredos "tipo token"; padrões estruturais
                # (connection strings, webhooks, chaves privadas) têm marcador fixo próprio
                threshold = ENTROPY_THRESHOLDS.get(name, MIN_ENTROPY)
                if shannon_entropy(clean) < threshold:
                    logger.debug(f"Descartado por baixa entropia ({name}, limiar={threshold}): {clean[:20]}...")
                    continue

            if name == "Generic Secret Assignment":
                # "Generic Secret Assignment" captura o NOME da chave (token/secret/password)
                # e o VALOR atribuído. Quando o valor em si parece um identificador simbólico
                # -- UPPER_SNAKE_CASE (Redux action type/enum) ou camelCase puro sem dígito
                # (nome de variável) -- é quase certo que é nome de código, não secret real.
                if CONSTANT_NAME_PATTERN.match(clean):
                    logger.debug(f"Descartado por parecer nome de constante/action-type, não secret: {clean[:40]}")
                    continue
                if CAMEL_CASE_IDENTIFIER_PATTERN.match(clean):
                    logger.debug(f"Descartado por parecer identificador camelCase, não secret: {clean[:40]}")
                    continue
                # mesma lógica, mas pra path de rota -- ex: path: "/signup/reset_password"
                # bate no regex por causa da palavra "password", mas o valor capturado é
                # uma rota, não um secret
                if LOOKS_LIKE_PATH_PATTERN.match(clean):
                    logger.debug(f"Descartado por parecer path de rota, não secret: {clean[:40]}")
                    continue

            secret_entry = {"type": name, "value": clean, "confidence": "HIGH"}
            if source_label:
                secret_entry["source_file"] = source_label

            if jwt_header is not None:
                alg = str(jwt_header.get("alg", "")).lower()
                if alg == "none":
                    secret_entry["note"] = (
                        "JWT com alg:none -- se o backend não rejeitar explicitamente esse "
                        "algoritmo, a assinatura pode ser removida e o payload forjado livremente."
                    )
                elif alg in ("hs256", "hs384", "hs512"):
                    secret_entry["note"] = (
                        f"JWT assinado com {alg.upper()} (segredo simétrico compartilhado). "
                        "Vale checar client-side se algum secret de assinatura vazou junto no bundle."
                    )

            # Chaves client-side públicas por design (ex: Google API Key, Stripe
            # publishable key): a chave em si não é sigilosa, a proteção é a
            # restrição configurada no provedor. Reporta com confiança rebaixada
            # em vez de tratar como vazamento equivalente a uma AWS secret key.
            if name in PUBLIC_BY_DESIGN_SECRET_TYPES:
                secret_entry["confidence"] = "INFO"
                secret_entry["note"] = (
                    "Chave/ID client-side, público por design. Não é vazamento por si só -- "
                    "verifique se está com restrição de domínio/referrer/API configurada no provedor."
                )

            found.append(secret_entry)

    # Dedup: o mesmo valor pode bater em mais de um padrão (ex: "Generic Secret Assignment"
    # E um padrão específico tipo "Stripe Live Secret Key" pro mesmo valor). Nesse caso,
    # o tipo específico é estritamente mais informativo -- mantém só ele.
    by_value = {}
    for item in found:
        key = item["value"].lower()
        existing = by_value.get(key)
        if existing is None or existing["type"] == "Generic Secret Assignment":
            by_value[key] = item
    return list(by_value.values())


def extract_endpoints(data, from_doc_page, source_label=None):
    """Extrai e classifica endpoints de um blob de texto. Não faz validação HTTP
    ativa aqui -- isso fica a cargo de quem chama (só faz sentido pro JS original
    servido de fato, não pra conteúdo reconstruído de source map)."""
    found = []
    seen = set()

    for pattern in API_PATTERNS:
        for m in re.findall(pattern, data):
            endpoint = m.strip()
            if any(x in endpoint.lower() for x in NOISE_MARKERS):
                continue
            if endpoint in seen:
                continue
            seen.add(endpoint)

            severity = classify_endpoint(endpoint)
            entry = {"path": endpoint, "severity": severity, "status": "UNKNOWN"}
            if source_label:
                entry["source_file"] = source_label

            # Endpoint de telemetria/analytics batendo em /api/ vira HIGH só pelo
            # classify_endpoint genérico -- rebaixa e marca, em vez de tratar como
            # rota de negócio real. Não descarta: ainda pode valer checar (ex: endpoint
            # de tracking aceitando payload arbitrário sem auth), só não infla a
            # contagem de achados "reais" com ruído repetido de SDK vendorizado.
            if any(marker in endpoint.lower() for marker in TELEMETRY_PATH_MARKERS):
                downgrade = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "MEDIUM"}
                if severity != downgrade[severity]:
                    entry["severity"] = severity = downgrade[severity]
                entry["likely_telemetry"] = True

            # JS servido a partir de um portal de documentação pública (developer.*,
            # docs.*, /swagger, etc.) provavelmente só está renderizando a doc da
            # API pública, não expondo rotas internas. Rebaixa um nível de severidade
            # e marca a origem em vez de tratar como achado equivalente a um endpoint
            # admin encontrado em bundle de produto comum.
            if from_doc_page:
                downgrade = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "MEDIUM"}
                severity = downgrade[severity]
                entry["severity"] = severity
                entry["note"] = "Encontrado em página que parece portal de documentação pública de API"

            found.append(entry)

    return found


def extract_storage_buckets(data, logger):
    """Extrai referências a buckets/blobs de cloud storage no bundle. Só extrai --
    não valida se está com listagem/escrita pública (isso é achado ativo, fora do
    escopo de recon passivo). O valor de reportar é: sabemos que o bucket existe e
    é referenciado pelo frontend, o que já vira alvo pra checagem manual/nuclei."""
    found = []
    seen = set()
    for provider, pattern in STORAGE_BUCKET_PATTERNS.items():
        for match in re.finditer(pattern, data, re.IGNORECASE):
            bucket = match.group(0).strip().rstrip("/\"'")
            if bucket in seen:
                continue
            seen.add(bucket)
            found.append({"provider": provider, "value": bucket})
    if found:
        logger.debug(f"{len(found)} referência(s) de storage bucket encontrada(s)")
    return found


def detect_known_library(endpoint_paths):
    """Confirma (não só suspeita) se o conjunto de paths bate com a API de uma
    lib/serviço de terceiros conhecida. Retorna o nome da lib ou None."""
    joined = " ".join(p.lower() for p in endpoint_paths)
    best_name, best_count = None, 0
    for lib_name, markers in KNOWN_LIBRARY_SIGNATURES.items():
        count = sum(1 for m in markers if m.lower() in joined)
        if count > best_count:
            best_name, best_count = lib_name, count
    if best_count >= MIN_LIBRARY_SIGNATURE_MATCHES:
        return best_name
    return None


def flag_vendored_library_endpoints(endpoints):
    """Se um único arquivo despeja endpoints demais, é mais provável que seja a
    API surface completa de uma lib vendorizada (SDK de pagamento, block explorer,
    etc.) empacotada no bundle inteira -- não rotas custom escritas pro backend do
    alvo. Primeiro tenta CONFIRMAR contra assinaturas conhecidas (mais confiável);
    se não bater com nenhuma mas o volume ainda for suspeito, marca como suspeita
    genérica (sem nome). Não descarta nenhum dos dois casos -- só anota, pra não
    tratar cada rota como achado isolado de mesmo peso."""
    paths = [e["path"] for e in endpoints]
    known_match = detect_known_library(paths)
    if known_match:
        for e in endpoints:
            e["vendored_library"] = known_match
        return known_match

    non_medium = [e for e in endpoints if e["severity"] in ("CRITICAL", "HIGH")]
    if len(non_medium) > VENDORED_LIBRARY_ENDPOINT_THRESHOLD:
        for e in endpoints:
            e["likely_vendored_library"] = True
        return True
    return False


def find_source_map_comment(data):
    """Procura o comentário //# sourceMappingURL=... (geralmente na última linha
    do bundle). Retorna o valor cru (pode ser URL relativa ou data: URI inline)."""
    matches = re.findall(r"//[#@]\s*sourceMappingURL=(\S+)", data)
    return matches[-1] if matches else None


def fetch_source_map(session, js_url, comment_value, timeout, logger):
    """Resolve e busca o source map. Se for inline (data: URI em base64), decodifica
    direto sem request de rede. Retorna (dict_parseado_ou_None, url_do_map_ou_None)."""
    if comment_value.startswith("data:"):
        try:
            _, b64data = comment_value.split(",", 1)
            raw = base64.b64decode(b64data)
            return json.loads(raw), "(inline data URI)"
        except (ValueError, json.JSONDecodeError, base64.binascii.Error) as e:
            logger.debug(f"Source map inline inválido em {js_url}: {e}")
            return None, None

    map_url = urljoin(js_url, comment_value)
    try:
        resp = session.get(map_url, timeout=timeout)
        if resp.status_code != 200:
            return None, map_url
        return json.loads(resp.text), map_url
    except (requests.RequestException, json.JSONDecodeError) as e:
        logger.debug(f"Falha ao buscar/parsear source map {map_url}: {e}")
        return None, map_url


def check_source_map(session, js_url, js_data, from_doc_page, args, logger):
    """Detecta e processa source map exposto. Um .map exposto em produção já é,
    por si só, um achado de disclosure (estrutura de pastas/nomes de arquivo
    originais ficam visíveis). Se o map ainda tiver `sourcesContent` embutido,
    é um ganho MUITO maior: dá pra rodar a extração de secrets/endpoints em
    cima do código-fonte ORIGINAL, não-minificado -- sem precisar adivinhar
    contexto a partir de nome de variável ofuscado (a, b, c...)."""
    comment = find_source_map_comment(js_data)
    if not comment:
        return None

    parsed, map_url = fetch_source_map(session, js_url, comment, args.timeout, logger)
    if not parsed:
        return {"map_url": map_url, "accessible": False}

    sources = parsed.get("sources") or []
    contents = parsed.get("sourcesContent") or []

    result = {
        "map_url": map_url,
        "accessible": True,
        "source_count": len(sources),
        "sample_sources": sources[:15],  # amostra -- não despeja centenas de paths no relatório
        "has_source_contents": bool(contents),
        "extra_secrets": [],
        "extra_endpoints": [],
    }

    if not contents:
        return result

    scanned = 0
    for path, content in zip(sources, contents):
        if not content:
            continue
        if scanned >= SOURCE_MAP_MAX_SOURCES_TO_SCAN:
            logger.debug(f"Source map de {js_url}: limite de {SOURCE_MAP_MAX_SOURCES_TO_SCAN} arquivos-fonte atingido, parando.")
            break
        scanned += 1
        content = content[:SOURCE_MAP_MAX_CONTENT_LEN]

        result["extra_secrets"].extend(extract_secrets(content, logger, source_label=path))
        result["extra_endpoints"].extend(extract_endpoints(content, from_doc_page, source_label=path))

    return result


def analyze_content(session, url, data, args, logger):
    findings = {"url": url, "secrets": [], "endpoints": [], "high_value": [], "storage_buckets": []}

    findings["secrets"] = extract_secrets(data, logger)
    findings["storage_buckets"] = extract_storage_buckets(data, logger)

    from_doc_page = is_likely_doc_page(url)
    raw_endpoints = extract_endpoints(data, from_doc_page)

    # Fonte de source map exposto: reprocessa o código-fonte original quando disponível
    # e mescla os achados extra (marcados por source_file, pra saber que vieram de lá).
    if not args.skip_sourcemaps:
        source_map_info = check_source_map(session, url, data, from_doc_page, args, logger)
        if source_map_info:
            findings["source_map"] = {k: v for k, v in source_map_info.items()
                                       if k not in ("extra_secrets", "extra_endpoints")}
            if source_map_info.get("extra_secrets"):
                logger.warning(f"  [SOURCE MAP] {url}: {len(source_map_info['extra_secrets'])} secret(s) extra no código-fonte original")
            findings["secrets"].extend(source_map_info.get("extra_secrets", []))
            raw_endpoints.extend(source_map_info.get("extra_endpoints", []))
            # re-dedup depois de mesclar (source map pode reafirmar algo já visto no bundle
            # minificado) -- mesma regra: tipo específico ganha de Generic Secret Assignment
            by_value = {}
            for item in findings["secrets"]:
                key = item["value"].lower()
                existing = by_value.get(key)
                if existing is None or existing["type"] == "Generic Secret Assignment":
                    by_value[key] = item
            findings["secrets"] = list(by_value.values())

    flag_vendored_library_endpoints(raw_endpoints)

    for entry in raw_endpoints:
        endpoint = entry["path"]
        severity = entry["severity"]

        should_verify = args.verify_endpoints and "source_file" not in entry
        if should_verify and not args.verify_all:
            # Por padrão, não gasta request em ruído já identificado (vendorizado/
            # telemetria) nem em MEDIUM -- foca o custo de rede no que de fato
            # importaria confirmar antes de reportar.
            is_noise = entry.get("likely_vendored_library") or entry.get("vendored_library") \
                or entry.get("likely_telemetry")
            if severity not in ("CRITICAL", "HIGH") or is_noise:
                should_verify = False

        if should_verify:
            # validação ativa só faz sentido pro endpoint achado no JS de verdade
            # servido pela rede -- não pra path reconstruído de dentro de um source map
            status = verify_endpoint(session, url, endpoint, args.timeout, logger)
            entry["status"] = status if status else "FAILED"
            # se pedimos validação e o endpoint nem responde (FAILED), dá 404, ou é
            # só o fallback HTML de SPA, é string morta / rota inexistente -- não
            # vale reportar como achado real
            if status in (None, 404, "SPA_FALLBACK"):
                continue

        findings["endpoints"].append(entry)
        if severity == "CRITICAL":
            findings["high_value"].append(endpoint)

    return findings if findings["secrets"] or findings["endpoints"] or findings["storage_buckets"] else None


def fetch_with_retry(session, url, timeout, retries, delay, logger):
    last_exc = None
    for attempt in range(1, retries + 2):  # 1 tentativa inicial + N retries
        try:
            if delay:
                time.sleep(delay)
            resp = session.get(url, timeout=timeout)
            return resp
        except requests.RequestException as e:
            last_exc = e
            logger.debug(f"Tentativa {attempt} falhou para {url}: {e}")
            time.sleep(min(2 ** attempt, 10))  # backoff exponencial simples
    logger.debug(f"Desistindo de {url} após {retries + 1} tentativas ({last_exc})")
    return None


def process_js(session, url, args, logger, hash_cache, cache_lock):
    resp = fetch_with_retry(session, url, args.timeout, args.retries, args.delay, logger)
    if resp is None or resp.status_code != 200:
        return None

    data = resp.text
    if len(data) < 100:
        return None

    # Dedup por conteúdo: mesmo JS servido via CDN/redirect/mirror não precisa ser
    # baixado e analisado de novo.
    file_hash = hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()
    with cache_lock:
        already_seen = hash_cache.get(file_hash)
        if already_seen:
            logger.info(f"Duplicado por hash, pulando: {url} (já processado como {already_seen})")
            return None
        hash_cache[file_hash] = url

    try:
        os.makedirs(os.path.join(args.output_dir, TEMP_JS_DIR), exist_ok=True)
        filepath = os.path.join(args.output_dir, TEMP_JS_DIR, f"{file_hash}.js")
        with open(filepath, "w", encoding="utf-8", errors="ignore") as f:
            f.write(data)
    except OSError as e:
        logger.warning(f"Não foi possível salvar cópia local de {url}: {e}")

    return analyze_content(session, url, data, args, logger)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="Recon passivo de JS para bug bounty")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", help="domínio ou URL único alvo")
    target_group.add_argument("-l", help="arquivo com lista de domínios (um por linha)")

    parser.add_argument("--scope", help="arquivo com domínios em escopo (filtra subdomínios fora dele)")
    parser.add_argument("--threads", type=int, default=DEFAULT_MAX_WORKERS, help="threads paralelas p/ análise de JS")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="timeout por request (s)")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="tentativas extra por request")
    parser.add_argument(
        "--tool-timeout", type=int, default=DEFAULT_TOOL_TIMEOUT,
        help="timeout (s) para CADA execução em lote de gau/waybackurls/katana (alvos grandes precisam de mais tempo)",
    )
    parser.add_argument(
        "--katana-concurrency", type=int, default=DEFAULT_KATANA_CONCURRENCY,
        help="concorrência interna do katana (-c) ao rastrear a lista de alvos",
    )
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="delay entre requests por thread (s)")
    parser.add_argument("--output-dir", default=OUTPUT_DIR, help="diretório base de saída (cada execução ganha uma subpasta por domínio)")
    parser.add_argument(
        "--keep-old", action="store_true",
        help="não apaga pastas de execuções anteriores de outros domínios (por padrão, mantém só a execução atual)",
    )
    parser.add_argument(
        "--verify-endpoints", action="store_true",
        help="faz HEAD request pra confirmar existência real do endpoint. Por padrão, só "
             "verifica CRITICAL/HIGH que não foram marcados como vendorizado/telemetria "
             "(a maior parte do custo de rede em request cego não compensa pra ruído já "
             "identificado). Use --verify-all pra forçar verificação de tudo, incluindo MEDIUM.",
    )
    parser.add_argument(
        "--verify-all", action="store_true",
        help="junto com --verify-endpoints, verifica TODOS os endpoints (inclusive MEDIUM e "
             "os já marcados vendorizado/telemetria), não só CRITICAL/HIGH não-ruído",
    )
    parser.add_argument(
        "--skip-sourcemaps", action="store_true",
        help="desativa a checagem de source maps expostos (//# sourceMappingURL). "
             "Por padrão a ferramenta tenta buscar o .map de cada JS e, se ele tiver "
             "sourcesContent embutido, re-escaneia o código-fonte original em busca "
             "de secrets/endpoints -- geralmente o achado de maior qualidade do scan.",
    )
    parser.add_argument(
        "--validate-secrets", action="store_true",
        help="ATIVO (não é 100%% passivo): faz 1 chamada read-only por secret único contra a "
             "API oficial do provedor (GitHub/Slack/Stripe/SendGrid/npm) pra confirmar se a "
             "chave ainda é válida. Muda confidence pra CONFIRMED (validado, funciona) ou "
             "INVALID (validado, não funciona mais). Desligado por padrão.",
    )
    parser.add_argument(
        "--http-cache", action="store_true",
        help="ativa cache de requests em disco (requer 'pip install requests-cache'); acelera reruns",
    )
    parser.add_argument(
        "--nuclei", action="store_true",
        help="ao final, roda 'nuclei -t exposed-panels/' (detecção passiva) sobre os endpoints achados, "
             "se o binário 'nuclei' estiver disponível. NÃO roda templates de exploração/CVE automaticamente.",
    )
    parser.add_argument(
        "--skip-exposure-checks", action="store_true",
        help="desativa a checagem de arquivos sensíveis bem conhecidos (.git/HEAD, .env, etc) "
             "e de CORS mal configurado na raiz de cada alvo. Ligado por padrão -- é 1 GET a "
             "mais por path conhecido, por alvo (não por arquivo JS), custo baixo.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="log detalhado (DEBUG)")
    return parser.parse_args()


def load_domains(args, logger):
    if args.u:
        raw = args.u
        domain = raw if not raw.startswith("http") else urlparse(raw).netloc
        return [domain]

    if not os.path.isfile(args.l):
        logger.error(f"Arquivo de domínios não encontrado: {args.l}")
        sys.exit(1)
    with open(args.l) as f:
        domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return domains


def run_nuclei_exposed_panels(report_path, args, logger):
    """Roda nuclei (se disponível) SOMENTE com o template category 'exposed-panels',
    que é detecção passiva de painéis administrativos expostos -- não roda templates
    de CVE/exploração. Isso é opt-in via --nuclei."""
    if not shutil.which("nuclei"):
        logger.warning("--nuclei pedido mas o binário 'nuclei' não foi encontrado no PATH.")
        return

    try:
        with open(report_path) as f:
            report = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.error(f"Não foi possível ler o relatório pra alimentar o nuclei: {e}")
        return

    # Monta lista de URLs completas (base_url + endpoint) a partir do próprio relatório,
    # sem depender de shell/pipe/jq.
    targets = set()
    for entry in report:
        base = entry.get("url", "")
        for ep in entry.get("endpoints", []):
            path = ep.get("path")
            if path:
                targets.add(urljoin(base, path))

    if not targets:
        logger.info("Nenhum endpoint pra alimentar o nuclei. Pulando.")
        return

    targets_file = os.path.join(args.output_dir, "nuclei_targets.txt")
    with open(targets_file, "w") as f:
        f.write("\n".join(sorted(targets)))

    nuclei_output = os.path.join(args.output_dir, "nuclei_report.json")
    logger.info(f"Rodando nuclei (exposed-panels) em {len(targets)} endpoint(s)...")

    cmd = [
        "nuclei", "-l", targets_file,
        "-t", "exposed-panels/",
        "-silent", "-jsonl", "-o", nuclei_output,
    ]
    try:
        subprocess.run(cmd, timeout=600, check=False)
        logger.info(f"Resultado do nuclei salvo em: {nuclei_output}")
    except subprocess.TimeoutExpired:
        logger.warning("nuclei excedeu o timeout de 600s e foi interrompido.")
    except Exception as e:
        logger.error(f"Erro ao rodar nuclei: {e}")


def _validate_github(value, timeout, logger):
    try:
        r = requests.get("https://api.github.com/user",
                          headers={"Authorization": f"token {value}"}, timeout=timeout)
        if r.status_code == 200:
            return True
        if r.status_code == 401:
            return False
        return None  # rate-limited, erro de rede etc -- inconclusivo
    except requests.RequestException as e:
        logger.debug(f"Validação GitHub falhou: {e}")
        return None


def _validate_slack(value, timeout, logger):
    try:
        r = requests.post("https://slack.com/api/auth.test",
                           headers={"Authorization": f"Bearer {value}"}, timeout=timeout)
        return bool(r.json().get("ok"))
    except (requests.RequestException, ValueError) as e:
        logger.debug(f"Validação Slack falhou: {e}")
        return None


def _validate_stripe(value, timeout, logger):
    try:
        # Stripe usa Basic Auth com a secret key como "username" e senha vazia
        r = requests.get("https://api.stripe.com/v1/charges?limit=1",
                          auth=(value, ""), timeout=timeout)
        if r.status_code == 200:
            return True
        if r.status_code == 401:
            return False
        return None
    except requests.RequestException as e:
        logger.debug(f"Validação Stripe falhou: {e}")
        return None


def _validate_sendgrid(value, timeout, logger):
    try:
        r = requests.get("https://api.sendgrid.com/v3/scopes",
                          headers={"Authorization": f"Bearer {value}"}, timeout=timeout)
        if r.status_code == 200:
            return True
        if r.status_code == 401:
            return False
        return None
    except requests.RequestException as e:
        logger.debug(f"Validação SendGrid falhou: {e}")
        return None


def _validate_npm(value, timeout, logger):
    try:
        r = requests.get("https://registry.npmjs.org/-/npm/v1/user",
                          headers={"Authorization": f"Bearer {value}"}, timeout=timeout)
        if r.status_code == 200:
            return True
        if r.status_code in (401, 403):
            return False
        return None
    except requests.RequestException as e:
        logger.debug(f"Validação npm falhou: {e}")
        return None


# Só cobre tipos onde 1 valor sozinho é suficiente pra autenticar (não precisa
# de um segundo secret pareado, ex: AWS access key + secret key juntos, ou
# Twilio API Key SID + secret separado -- esses ficam sem validador aqui).
SECRET_VALIDATORS = {
    "GitHub Token": _validate_github,
    "GitHub Token (outros escopos)": _validate_github,
    "GitHub Fine-grained PAT": _validate_github,
    "Slack Token": _validate_slack,
    "Stripe Live Secret Key": _validate_stripe,
    "SendGrid API Key": _validate_sendgrid,
    "npm Access Token": _validate_npm,
}


def validate_secrets_in_results(results, args, logger):
    """Validação ATIVA (opt-in via --validate-secrets): faz uma chamada read-only
    de baixo custo contra a API oficial do provedor pra confirmar se a chave
    ainda é válida, em vez de só confirmar que o FORMATO bate. Transforma
    confidence HIGH em CONFIRMED (testado e funciona -- achado real garantido)
    ou INVALID (testado e não funciona mais -- provavelmente já rotacionado/
    revogado, não precisa de ação urgente). Roda só uma vez por valor único,
    não por ocorrência, pra economizar chamadas."""
    unique_targets = {}
    for res in results:
        for s in res.get("secrets", []):
            if s.get("confidence") != "HIGH":
                continue
            validator = SECRET_VALIDATORS.get(s["type"])
            if not validator:
                continue
            unique_targets[(s["type"], s["value"])] = validator

    if not unique_targets:
        return results

    logger.info(f"Validando ativamente {len(unique_targets)} secret(s) único(s) com validador disponível...")
    outcomes = {}
    for (stype, value), validator in unique_targets.items():
        outcome = validator(value, args.timeout, logger)
        outcomes[(stype, value)] = outcome
        if outcome is True:
            logger.warning(f"  [CONFIRMADO] {stype}: {value[:20]}... ainda é válido")
        elif outcome is False:
            logger.info(f"  [INVÁLIDO] {stype}: {value[:20]}... não é mais válido (revogado/rotacionado)")

    for res in results:
        for s in res.get("secrets", []):
            key = (s.get("type"), s.get("value"))
            if key not in outcomes:
                continue
            outcome = outcomes[key]
            if outcome is True:
                s["confidence"] = "CONFIRMED"
                s["note"] = "Validado ativamente contra a API oficial do provedor -- a chave ainda funciona AGORA."
            elif outcome is False:
                s["confidence"] = "INVALID"
                s["note"] = "Validado ativamente: a chave NÃO é mais válida (revogada/rotacionada/expirada)."
            # outcome is None: inconclusivo (rate limit, erro de rede) -- deixa como HIGH, sem nota

    return results


def deduplicate_global_secrets(results, logger, threshold=5):
    """Passada final sobre TODOS os arquivos já processados: se o mesmo valor
    de secret aparece idêntico em muitos arquivos diferentes (>= threshold),
    isso não é "N segredos vazados" -- é a assinatura de uma constante
    injetada em tempo de build (ex: write-key de SDK client-side tipo
    Segment/Statsig, replicada em todo bundle via variável de ambiente
    compartilhada). Um secret vazado por acidente normalmente aparece em
    UM lugar, não em centenas de chunks de produtos diferentes.

    Não descarta o achado (ainda pode valer conferir), só rebaixa a
    confiança e anota quantos arquivos compartilham o mesmo valor, pra
    quem for triar saber que é 1 achado repetido, não N achados distintos.
    """
    value_files = {}
    for res in results:
        for s in res.get("secrets", []):
            value_files.setdefault(s["value"], set()).add(res["url"])

    downgraded = 0
    for res in results:
        for s in res.get("secrets", []):
            n_files = len(value_files[s["value"]])
            if s.get("confidence", "HIGH") == "HIGH" and n_files >= threshold:
                s["confidence"] = "LOW"
                s["note"] = (
                    f"Mesmo valor idêntico encontrado em {n_files} arquivos diferentes -- "
                    "provável constante de build/SDK client-side compartilhada entre bundles, "
                    "não secret vazado isoladamente. Confirmar contexto antes de reportar."
                )
                downgraded += 1

    unique_values = len(value_files)
    total_occurrences = sum(len(res.get("secrets", [])) for res in results)
    if downgraded:
        logger.info(
            f"Dedup global: {total_occurrences} ocorrências de secret / {unique_values} valores únicos "
            f"-- {downgraded} ocorrências rebaixadas p/ confiança LOW (valor repetido em >= {threshold} arquivos)"
        )
    return results


def _snapshot_path(base_dir, run_name):
    return os.path.join(base_dir, HISTORY_DIRNAME, f"{run_name}.json")


def load_previous_snapshot(base_dir, run_name, logger):
    """Carrega o relatório da execução ANTERIOR pra este mesmo alvo (se existir),
    salvo fora da pasta de execução (que é apagada a cada rerun), pra permitir
    diff entre execuções."""
    path = _snapshot_path(base_dir, run_name)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(f"Snapshot anterior corrompido, ignorando pro diff: {e}")
        return None


def save_snapshot(base_dir, run_name, results, logger):
    path = _snapshot_path(base_dir, run_name)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(results, f)
        logger.debug(f"Snapshot desta execução salvo em {path} (usado pro diff da próxima vez)")
    except OSError as e:
        logger.warning(f"Não foi possível salvar snapshot pra diff futuro: {e}")


# Casa números tipo 1.4.7 / 2.0.19 / 1.5.28 dentro do path da URL -- padrão de
# versionamento semver usado nos nomes de arquivo de bundles CDN.
VERSION_TOKEN_PATTERN = re.compile(r"\d+\.\d+(?:\.\d+){0,2}")


def _version_family_key(url):
    """Normaliza a URL removendo o número de versão, pra agrupar diferentes versões
    do MESMO bundle (ex: .../gmp-lib/umd-min/1.4.7/gmp-lib.min.js e .../1.5.29/...
    caem na mesma família 'gmp-lib.min.js' apesar de terem hosts/paths quase iguais)."""
    parsed = urlparse(url)
    normalized_path = VERSION_TOKEN_PATTERN.sub("{version}", parsed.path)
    return f"{parsed.netloc}{normalized_path}"


def _extract_version_tuple(url):
    match = VERSION_TOKEN_PATTERN.search(urlparse(url).path)
    if not match:
        return None
    try:
        return tuple(int(p) for p in match.group(0).split("."))
    except ValueError:
        return None


def analyze_version_families(results, logger):
    """CDNs costumam manter várias versões do mesmo bundle vendorizado acessíveis
    simultaneamente (cache antigo não invalidado, ou versionamento intencional na
    URL). Isso é uma oportunidade: agrupamos arquivos que são versões diferentes do
    MESMO bundle e comparamos a mais recente contra as mais antigas. Endpoint/secret
    que só aparece na versão mais nova é sinal de mudança recente no código --
    superfície de ataque provavelmente menos testada e menos monitorada do que rotas
    que já existem há várias releases. Isso não existe no diff temporal entre
    execuções (que compara o alvo com ele mesmo ao longo do tempo); aqui é um diff
    DENTRO da mesma execução, entre versões co-hospedadas agora."""
    families = {}
    for res in results:
        version = _extract_version_tuple(res["url"])
        if version is None:
            continue
        key = _version_family_key(res["url"])
        families.setdefault(key, []).append((version, res))

    findings = []
    for key, members in families.items():
        if len(members) < 2:
            continue
        members.sort(key=lambda pair: pair[0])
        latest_version, latest_res = members[-1]

        older_endpoint_paths = set()
        older_secret_values = set()
        for _, res in members[:-1]:
            older_endpoint_paths.update(e["path"] for e in res.get("endpoints", []))
            older_secret_values.update(s["value"].lower() for s in res.get("secrets", []))

        latest_endpoints = {e["path"] for e in latest_res.get("endpoints", [])}
        latest_secrets_by_value = {s["value"].lower(): s for s in latest_res.get("secrets", [])}

        new_endpoints = sorted(latest_endpoints - older_endpoint_paths)
        new_secrets = [s for val, s in latest_secrets_by_value.items() if val not in older_secret_values]

        if not new_endpoints and not new_secrets:
            continue

        findings.append({
            "family": key,
            "versions_seen": [".".join(str(p) for p in v) for v, _ in members],
            "latest_version": ".".join(str(p) for p in latest_version),
            "latest_url": latest_res["url"],
            "new_in_latest_version": {"endpoints": new_endpoints, "secrets": new_secrets},
        })
        logger.warning(
            f"[VERSION DRIFT] {key}: versão {'.'.join(str(p) for p in latest_version)} tem "
            f"{len(new_endpoints)} endpoint(s) e {len(new_secrets)} secret(s) que NÃO aparecem "
            f"em nenhuma das {len(members) - 1} versão(ões) mais antiga(s) co-hospedada(s)"
        )

    return findings


def diff_results(old_results, new_results):
    """Compara duas execuções do mesmo alvo. Secrets comparados por (tipo, valor);
    endpoints por path -- ignora ruído de severidade/confidence ter mudado, foca
    em O QUE APARECEU/SUMIU desde a última vez, que é o que importa pra tracking
    contínuo (não precisa reler o relatório inteiro toda vez)."""
    def secret_keys(results):
        return {(s["type"], s["value"]) for res in results for s in res.get("secrets", [])}

    def endpoint_keys(results):
        return {e["path"] for res in results for e in res.get("endpoints", [])}

    old_secrets, new_secrets = secret_keys(old_results), secret_keys(new_results)
    old_endpoints, new_endpoints = endpoint_keys(old_results), endpoint_keys(new_results)

    return {
        "new_secrets": sorted(f"[{t}] {v}" for t, v in (new_secrets - old_secrets)),
        "resolved_secrets": sorted(f"[{t}] {v}" for t, v in (old_secrets - new_secrets)),
        "new_endpoints": sorted(new_endpoints - old_endpoints),
        "resolved_endpoints": sorted(old_endpoints - new_endpoints),
    }


def print_diff_summary(diff, logger):
    if not any(diff.values()):
        logger.info("Diff com a execução anterior: nada mudou.")
        return
    logger.info("=" * 50)
    logger.info("DIFF COM A EXECUÇÃO ANTERIOR")
    logger.info("=" * 50)
    if diff["new_secrets"]:
        logger.warning(f"Secrets NOVOS desde a última vez ({len(diff['new_secrets'])}):")
        for s in diff["new_secrets"][:20]:
            logger.warning(f"  + {s}")
    if diff["resolved_secrets"]:
        logger.info(f"Secrets que SUMIRAM desde a última vez ({len(diff['resolved_secrets'])}, possível rotação/fix):")
        for s in diff["resolved_secrets"][:20]:
            logger.info(f"  - {s}")
    if diff["new_endpoints"]:
        logger.warning(f"Endpoints NOVOS desde a última vez ({len(diff['new_endpoints'])}):")
        for e in diff["new_endpoints"][:20]:
            logger.warning(f"  + {e}")
    if diff["resolved_endpoints"]:
        logger.info(f"Endpoints que SUMIRAM desde a última vez ({len(diff['resolved_endpoints'])}):")
        for e in diff["resolved_endpoints"][:20]:
            logger.info(f"  - {e}")
    logger.info("=" * 50)


def print_summary(results, logger):
    """Resumo final: contagem por severidade de endpoint e por tipo de secret,
    pra dar uma visão de triagem rápida sem precisar abrir o JSON."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    secret_type_counts = {}
    total_secrets = 0
    total_secrets_info = 0       # confiança INFO (ex: chave pública por design) -- não conta como achado forte
    total_secrets_low = 0        # confiança LOW (dedup global: valor repetido em muitos arquivos)
    total_secrets_confirmed = 0  # validado ativamente: a chave FUNCIONA agora
    total_secrets_invalid = 0    # validado ativamente: a chave NÃO funciona mais
    total_endpoints = 0
    files_with_secrets = 0
    files_with_high_value = 0
    files_with_exposed_sourcemap = 0
    files_with_sourcemap_contents = 0
    files_with_vendored_endpoints = 0
    known_library_matches = {}
    total_buckets = 0
    bucket_provider_counts = {}

    for res in results:
        endpoints = res.get("endpoints", [])
        secrets = res.get("secrets", [])
        buckets = res.get("storage_buckets", [])
        total_buckets += len(buckets)
        for b in buckets:
            provider = b.get("provider", "Desconhecido")
            bucket_provider_counts[provider] = bucket_provider_counts.get(provider, 0) + 1
        real_secrets = [s for s in secrets if s.get("confidence", "HIGH") in ("HIGH", "CONFIRMED")]
        low_secrets = [s for s in secrets if s.get("confidence") == "LOW"]
        info_secrets = [s for s in secrets if s.get("confidence") == "INFO"]
        confirmed_secrets = [s for s in secrets if s.get("confidence") == "CONFIRMED"]
        invalid_secrets = [s for s in secrets if s.get("confidence") == "INVALID"]
        total_endpoints += len(endpoints)
        total_secrets += len(real_secrets)
        total_secrets_low += len(low_secrets)
        total_secrets_info += len(info_secrets)
        total_secrets_confirmed += len(confirmed_secrets)
        total_secrets_invalid += len(invalid_secrets)

        if real_secrets:
            files_with_secrets += 1
        if res.get("high_value"):
            files_with_high_value += 1

        sm = res.get("source_map")
        if sm and sm.get("accessible"):
            files_with_exposed_sourcemap += 1
            if sm.get("has_source_contents"):
                files_with_sourcemap_contents += 1

        if any(ep.get("likely_vendored_library") for ep in endpoints):
            files_with_vendored_endpoints += 1
        for ep in endpoints:
            lib = ep.get("vendored_library")
            if lib:
                known_library_matches[lib] = known_library_matches.get(lib, 0) + 1

        for ep in endpoints:
            sev = ep.get("severity", "MEDIUM")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for s in real_secrets:
            t = s.get("type", "Desconhecido")
            secret_type_counts[t] = secret_type_counts.get(t, 0) + 1

    logger.info("=" * 50)
    logger.info("RESUMO DA EXECUÇÃO")
    logger.info("=" * 50)
    logger.info(f"Arquivos JS com algum achado: {len(results)}")
    logger.info(f"Arquivos com secrets: {files_with_secrets}")
    logger.info(f"Arquivos com endpoint CRITICAL: {files_with_high_value}")
    if files_with_exposed_sourcemap:
        logger.info(f"Arquivos com source map exposto: {files_with_exposed_sourcemap} "
                     f"({files_with_sourcemap_contents} com sourcesContent -- código-fonte original recuperável)")
    if known_library_matches:
        logger.info("Bibliotecas de terceiros identificadas por assinatura (endpoints não são do backend do alvo):")
        for lib, count in sorted(known_library_matches.items(), key=lambda x: -x[1]):
            logger.info(f"  {lib}: {count} endpoint(s)")
    if files_with_vendored_endpoints:
        logger.info(f"Arquivos com endpoints marcados 'likely_vendored_library' (suspeita por volume, sem assinatura confirmada): {files_with_vendored_endpoints}")
    if total_buckets:
        logger.info(f"Referências a storage buckets encontradas: {total_buckets} "
                    "(não validado -- checar manualmente permissão de list/write pública)")
        for provider, count in sorted(bucket_provider_counts.items(), key=lambda x: -x[1]):
            logger.info(f"  {provider}: {count}")
    logger.info("")
    logger.info(f"Endpoints encontrados: {total_endpoints}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        if severity_counts.get(sev):
            logger.info(f"  {sev}: {severity_counts[sev]}")
    logger.info("")
    logger.info(f"Secrets encontrados: {total_secrets}")
    for t, count in sorted(secret_type_counts.items(), key=lambda x: -x[1]):
        logger.info(f"  {t}: {count}")
    if total_secrets_confirmed:
        logger.info(f"  >>> CONFIRMADOS por validação ativa (funcionam AGORA): {total_secrets_confirmed}")
    if total_secrets_invalid:
        logger.info(f"Secrets INVALID (testados ativamente, não funcionam mais): {total_secrets_invalid}")
    if total_secrets_low:
        logger.info(f"Secrets confiança LOW (valor repetido em muitos arquivos, provável constante de build): {total_secrets_low}")
    if total_secrets_info:
        logger.info(f"Secrets confiança INFO (chaves públicas por design, revisar à parte): {total_secrets_info}")
    logger.info("=" * 50)


def main():
    args = parse_args()

    base_dir = args.output_dir
    run_dir, run_name = resolve_run_dir(base_dir, args)
    args.output_dir = run_dir  # a partir daqui, todo o resto do script já usa a subpasta certa

    logger = setup_logging(args.output_dir, args.verbose)
    logger.info(f"Diretório desta execução: {run_dir}")

    logger.info("=== recon_pro iniciado ===")
    if HAS_RICH:
        logger.debug("rich disponível -- barras de progresso ativadas")
    elif HAS_TQDM:
        logger.debug("rich indisponível, usando tqdm como fallback")
    else:
        logger.debug("rich e tqdm indisponíveis -- progresso será só texto (pip install rich)")

    tools_available = check_tools(EXTERNAL_TOOLS, logger)
    gf_available = shutil.which("gf") is not None
    if not gf_available:
        logger.warning("gf não encontrado no PATH — etapa de cruzamento de padrões será pulada")

    scope_entries = load_scope(args.scope, logger)
    domains = load_domains(args, logger)
    logger.info(f"Domínios alvo: {domains}")

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    })

    all_targets = []
    for domain in domains:
        if scope_entries and not is_in_scope(domain, scope_entries):
            logger.warning(f"Domínio '{domain}' fora do escopo definido, pulando")
            continue
        all_targets.extend(discover_assets(domain, tools_available, scope_entries, logger))

    all_targets = list(set(all_targets))
    if not all_targets:
        logger.error("Nenhum alvo válido dentro do escopo. Encerrando.")
        return

    exposure_findings = {"exposed_files": [], "cors_issues": []}
    if not args.skip_exposure_checks:
        logger.info(f"Checando arquivos sensíveis bem conhecidos e CORS em {len(all_targets)} alvo(s) "
                    f"com {args.threads} threads...")

        def _check_one_target(target):
            exposed = check_well_known_exposures(session, target, args.timeout, logger)
            for e in exposed:
                e["target"] = target
            cors = check_cors_misconfiguration(session, target, args.timeout, logger)
            return exposed, cors

        exposure_progress = make_rich_progress(indeterminate=False)
        exposure_task = None
        if exposure_progress:
            exposure_progress.start()
            exposure_task = exposure_progress.add_task("[bold]Checando exposição/CORS[/bold]", total=len(all_targets))

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_target = {executor.submit(_check_one_target, t): t for t in all_targets}
            completed_iter = as_completed(future_to_target)
            if not exposure_progress and HAS_TQDM:
                completed_iter = tqdm(completed_iter, total=len(future_to_target),
                                       desc="Checando exposição/CORS", unit="alvo")
            for future in completed_iter:
                target = future_to_target[future]
                try:
                    exposed, cors = future.result()
                except Exception as e:
                    logger.debug(f"Falha na checagem de exposição em {target}: {e}")
                    if exposure_progress:
                        exposure_progress.advance(exposure_task)
                    continue
                exposure_findings["exposed_files"].extend(exposed)
                if cors:
                    exposure_findings["cors_issues"].append(cors)
                if exposure_progress:
                    exposure_progress.advance(exposure_task)

        if exposure_progress:
            exposure_progress.stop()

    js_urls = get_js_urls(all_targets, tools_available, gf_available, args, logger)
    if not js_urls:
        logger.warning("Nenhum arquivo JS/JSON encontrado.")
        return

    logger.info(f"Analisando {len(js_urls)} arquivos com {args.threads} threads...")

    # Cache HTTP em disco (opcional) -- reduz drasticamente requests repetidas em reruns
    if args.http_cache:
        if HAS_REQUESTS_CACHE:
            requests_cache.install_cache(
                os.path.join(args.output_dir, "requests_cache"),
                expire_after=3600,
                allowable_methods=["GET", "HEAD", "OPTIONS"],
            )
            logger.info("Cache HTTP ativado (expira em 1h)")
        else:
            logger.warning("--http-cache pedido mas 'requests-cache' não instalado. Rode: pip install requests-cache")

    results = []

    hash_cache = load_hash_cache(args.output_dir, logger)
    cache_lock = threading.Lock()

    js_progress = make_rich_progress(indeterminate=False)
    js_task = None
    if js_progress:
        js_progress.start()
        js_task = js_progress.add_task("[bold]Analisando JS[/bold]", total=len(js_urls))
    elif not HAS_TQDM:
        logger.info("Dica: instale 'rich' ou 'tqdm' (pip install rich) pra ver uma barra de progresso.")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(process_js, session, url, args, logger, hash_cache, cache_lock): url
            for url in js_urls
        }

        completed_iter = as_completed(futures)
        if not js_progress and HAS_TQDM:
            completed_iter = tqdm(completed_iter, total=len(futures), desc="Analisando JS", unit="arquivo")

        total = len(futures)
        done_count = 0
        for future in completed_iter:
            url = futures[future]
            try:
                res = future.result()
            except Exception as e:
                logger.error(f"Erro inesperado processando {url}: {e}")
                if js_progress:
                    js_progress.advance(js_task)
                continue

            if res:
                results.append(res)
                logger.info(f"ACHADO: {res['url']}")
                if res["high_value"]:
                    logger.warning(f"  [CRITICAL] Endpoints de alto valor: {res['high_value']}")
                if res["secrets"]:
                    logger.warning(f"  [SECRET] {len(res['secrets'])} segredo(s) encontrado(s)")

            if js_progress:
                js_progress.advance(js_task)
            elif not HAS_TQDM:
                done_count += 1
                if done_count % 10 == 0 or done_count == total:
                    print(f"[*] Progresso: {done_count}/{total} arquivos analisados", file=sys.stderr)

    if js_progress:
        js_progress.stop()

    save_hash_cache(hash_cache, args.output_dir, logger)

    if args.validate_secrets:
        results = validate_secrets_in_results(results, args, logger)

    results = deduplicate_global_secrets(results, logger, threshold=5)

    os.makedirs(args.output_dir, exist_ok=True)
    report_path = os.path.join(args.output_dir, REPORT_JSON)
    with open(report_path, "w") as f:
        json.dump(results, f, indent=4)

    logger.info(f"Relatório salvo em: {report_path}")

    if exposure_findings["exposed_files"] or exposure_findings["cors_issues"]:
        exposure_path = os.path.join(args.output_dir, "exposure_findings.json")
        try:
            with open(exposure_path, "w") as f:
                json.dump(exposure_findings, f, indent=2)
            logger.warning(f"{len(exposure_findings['exposed_files'])} arquivo(s) sensível(is) exposto(s), "
                           f"{len(exposure_findings['cors_issues'])} issue(s) de CORS -- detalhes em: {exposure_path}")
        except OSError as e:
            logger.warning(f"Não foi possível salvar exposure_findings.json: {e}")

    print_summary(results, logger)

    version_findings = analyze_version_families(results, logger)
    if version_findings:
        version_path = os.path.join(args.output_dir, "version_drift.json")
        try:
            with open(version_path, "w") as f:
                json.dump(version_findings, f, indent=2)
            logger.info(f"{len(version_findings)} família(s) de bundle com drift entre versões "
                        f"co-hospedadas -- detalhes em: {version_path}")
        except OSError as e:
            logger.warning(f"Não foi possível salvar version_drift.json: {e}")

    previous_results = load_previous_snapshot(base_dir, run_name, logger)
    if previous_results is not None:
        diff = diff_results(previous_results, results)
        print_diff_summary(diff, logger)
        diff_path = os.path.join(args.output_dir, "diff_report.json")
        try:
            with open(diff_path, "w") as f:
                json.dump(diff, f, indent=2)
            logger.info(f"Diff salvo em: {diff_path}")
        except OSError as e:
            logger.warning(f"Não foi possível salvar diff_report.json: {e}")
    else:
        logger.info("Sem execução anterior pra este alvo -- diff será possível a partir da próxima vez.")
    save_snapshot(base_dir, run_name, results, logger)

    if args.nuclei:
        run_nuclei_exposed_panels(report_path, args, logger)


if __name__ == "__main__":
    main()
