"""
PhantomFix — Normalizer
Versão: 1.0
Autor: Rafael Pedro

Descrição:
Fase mecânica de pré-processamento que roda ANTES da correlação e do LLM.

Responsabilidades:
  1. Normalizar severidade de todos os scanners para escala unificada:
       CRITICAL → HIGH → MEDIUM → LOW → INFO
  2. Extrair / inferir CWE a partir do tipo e do check_id de cada scanner
  3. Gerar fingerprint único por finding: sha256(arquivo:linha:cwe:tipo_norm)
  4. Deduplicar findings com mesmo fingerprint, acumulando origens confirmadas
  5. Suprimir falsos ruídos: paths de teste, devDependencies, arquivos gerados

Pipeline esperado:
    scanner.py → normalizer.normalizar(vulns) → analyser.py (correlação + LLM)
"""

import hashlib
import re
from pathlib import Path

# ══════════════════════════════════════════════════════════════════════════════
# 1. MAPEAMENTO DE SEVERIDADE
# Cada scanner usa sua própria nomenclatura. Aqui normalizamos tudo para
# cinco níveis canônicos em maiúsculo.
# ══════════════════════════════════════════════════════════════════════════════

_MAPA_SEVERIDADE: dict[str, str] = {
    # Semgrep
    "error":        "HIGH",
    "warning":      "MEDIUM",
    "info":         "INFO",
    # Trivy / Grype / Checkov
    "critical":     "CRITICAL",
    "high":         "HIGH",
    "medium":       "MEDIUM",
    "low":          "LOW",
    "negligible":   "LOW",
    "unknown":      "INFO",
    # ZAP (usa palavras em inglês com sufixo de risco)
    "high risk":    "HIGH",
    "medium risk":  "MEDIUM",
    "low risk":     "LOW",
    "informational":"INFO",
    # Nuclei
    "critical":     "CRITICAL",
    "high":         "HIGH",
    "medium":       "MEDIUM",
    "low":          "LOW",
    "info":         "INFO",
    # Hadolint
    "style":        "INFO",
    # Gitleaks / TruffleHog (sem severidade própria → HIGH por padrão)
    "":             "HIGH",
}

SEVERIDADES_ORDENADAS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _normalizar_severidade(raw: str) -> str:
    """Retorna o nível canônico para qualquer string de severidade de entrada."""
    if not raw:
        return "HIGH"   # secrets scanners não declaram severidade
    chave = raw.strip().lower()
    # tenta match direto
    if chave in _MAPA_SEVERIDADE:
        return _MAPA_SEVERIDADE[chave]
    # tenta match parcial (ex: "High Risk (3)")
    for k, v in _MAPA_SEVERIDADE.items():
        if k and k in chave:
            return v
    return "INFO"


# ══════════════════════════════════════════════════════════════════════════════
# 2. EXTRAÇÃO DE CWE
# Muitos scanners já embutem o CWE no check_id ou na descrição.
# Tentamos extraí-lo antes de cair no mapeamento estático.
# ══════════════════════════════════════════════════════════════════════════════

# Mapeamento estático: tipo/categoria → lista de CWEs canônicos
_MAPA_CWE: dict[str, list[str]] = {
    # Injeção
    "sqli":                   ["CWE-89"],
    "sql":                    ["CWE-89"],
    "sql-injection":          ["CWE-89"],
    "nosqli":                 ["CWE-943"],
    "xss":                    ["CWE-79"],
    "cross-site-scripting":   ["CWE-79"],
    "ssti":                   ["CWE-94"],
    "template-injection":     ["CWE-94"],
    "rce":                    ["CWE-78"],
    "command-injection":      ["CWE-78"],
    "os-command":             ["CWE-78"],
    "ssrf":                   ["CWE-918"],
    "xxe":                    ["CWE-611"],
    "ldap-injection":         ["CWE-90"],
    "xpath-injection":        ["CWE-643"],
    "header-injection":       ["CWE-113"],
    "log-injection":          ["CWE-117"],
    # Path / Traversal
    "path-traversal":         ["CWE-22"],
    "directory-traversal":    ["CWE-22"],
    "zipslip":                ["CWE-22"],
    # Autenticação / Autorização
    "auth":                   ["CWE-287"],
    "authentication":         ["CWE-287"],
    "broken-auth":            ["CWE-287"],
    "hardcoded-credentials":  ["CWE-798"],
    "hardcoded-password":     ["CWE-798"],
    "default-credentials":    ["CWE-1392"],
    "idor":                   ["CWE-639"],
    "insecure-direct":        ["CWE-639"],
    "privilege-escalation":   ["CWE-269"],
    "csrf":                   ["CWE-352"],
    # Exposição de dados
    "sensitive-data":         ["CWE-312"],
    "cleartext":              ["CWE-312"],
    "secret":                 ["CWE-312"],
    "secrets":                ["CWE-312"],
    "information-disclosure": ["CWE-200"],
    "disclosure":             ["CWE-200"],
    "debug":                  ["CWE-489"],
    # Criptografia
    "weak-crypto":            ["CWE-327"],
    "insecure-hash":          ["CWE-328"],
    "weak-random":            ["CWE-338"],
    "weak-ssl":               ["CWE-326"],
    "tls":                    ["CWE-326"],
    # Deserialização
    "deserialization":        ["CWE-502"],
    "unsafe-deserialization": ["CWE-502"],
    # Race condition
    "race-condition":         ["CWE-362"],
    "toctou":                 ["CWE-362"],
    # Configuração
    "misconfiguration":       ["CWE-16"],
    "cors":                   ["CWE-942"],
    "open-redirect":          ["CWE-601"],
    "redirect":               ["CWE-601"],
    "security-headers":       ["CWE-693"],
    "missing-header":         ["CWE-693"],
    "clickjacking":           ["CWE-1021"],
    # Dependências / SCA
    "outdated":               ["CWE-1104"],
    "vulnerable-dependency":  ["CWE-1104"],
    # Upload
    "file-upload":            ["CWE-434"],
    "unrestricted-upload":    ["CWE-434"],
    # Memória (C/C++/Rust)
    "buffer-overflow":        ["CWE-120"],
    "use-after-free":         ["CWE-416"],
    "null-pointer":           ["CWE-476"],
    "integer-overflow":       ["CWE-190"],
}

_RE_CWE = re.compile(r'\b(CWE-\d+)\b', re.IGNORECASE)


def _extrair_cwe(vuln: dict) -> list[str]:
    """
    Tenta extrair CWE(s) de um finding pela seguinte ordem de prioridade:
      1. Campo 'cwe' explícito no finding
      2. Regex no check_id / tipo
      3. Regex na descrição
      4. Mapeamento estático por tipo normalizado
    """
    # 1 – campo explícito
    existente = vuln.get("cwe", [])
    if isinstance(existente, str) and existente:
        return [existente]
    if isinstance(existente, list) and existente:
        return existente

    # 2 – regex no check_id (Semgrep, Nuclei, etc.)
    check_id = vuln.get("check_id", vuln.get("tipo", ""))
    encontrados = _RE_CWE.findall(check_id)
    if encontrados:
        return [c.upper() for c in encontrados]

    # 3 – regex na descrição
    descricao = vuln.get("descricao", "")
    encontrados = _RE_CWE.findall(descricao)
    if encontrados:
        return [c.upper() for c in encontrados]

    # 4 – mapeamento estático
    tipo_norm = _normalizar_tipo_para_cwe(vuln.get("tipo", ""))
    for chave, cwes in _MAPA_CWE.items():
        if chave in tipo_norm:
            return cwes

    return []


def _normalizar_tipo_para_cwe(tipo: str) -> str:
    """Aplana o tipo para comparação com as chaves do mapa CWE."""
    return tipo.lower().replace("_", "-").replace(" ", "-")


# ══════════════════════════════════════════════════════════════════════════════
# 3. GERAÇÃO DE FINGERPRINT
# Identifica o mesmo problema encontrado por ferramentas distintas ou
# em execuções repetidas do scan.
#
# Composto por: arquivo + linha + cwe[0] + tipo_normalizado
# Para findings sem localização (ZAP, Trivy sem arquivo), usa descrição.
# ══════════════════════════════════════════════════════════════════════════════

def _gerar_fingerprint(vuln: dict) -> str:
    """
    Gera um fingerprint de 16 caracteres (sha256 truncado) para o finding.
    Determinístico: o mesmo finding em scans diferentes produz o mesmo hash.
    """
    arquivo  = vuln.get("arquivo", "").strip()
    linha    = str(vuln.get("linha", 0))
    tipo     = vuln.get("tipo", "").lower().strip()
    cwes     = vuln.get("cwe", [])
    cwe      = cwes[0] if cwes else ""

    # Findings sem localização (DAST, SCA global) usam tipo + descrição
    if not arquivo and not linha:
        descricao = vuln.get("descricao", "")[:120]
        chave = f"{tipo}:{cwe}:{descricao}"
    else:
        # Normaliza o caminho para remover prefixo absoluto variável entre runs
        try:
            arq_norm = Path(arquivo).name
        except Exception:
            arq_norm = arquivo
        chave = f"{arq_norm}:{linha}:{tipo}:{cwe}"

    return hashlib.sha256(chave.encode()).hexdigest()[:16]


# ══════════════════════════════════════════════════════════════════════════════
# 4. SUPRESSÃO DE RUÍDO
# Findings em paths de teste, build ou gerados por ferramentas têm impacto
# real zero em produção e enchem o relatório. São filtrados antes da dedup.
# ══════════════════════════════════════════════════════════════════════════════

_PATHS_SUPRIMIDOS = [
    # Dependências / build artifacts
    "node_modules", ".venv", "venv", "site-packages",
    "__pycache__", "dist", "build", ".next", ".nuxt",
    "vendor/", "target/", "out/",
    # Testes
    "/test/", "/tests/", "/spec/", "/specs/",
    "_test.go", "_test.py", ".test.ts", ".test.js",
    ".spec.ts", ".spec.js",
    # Gerados
    ".min.js", ".bundle.js", "generated/", "migrations/",
    # Fixtures / mocks
    "fixtures/", "mocks/", "stubs/", "__mocks__/",
    # IaC gerenciado remotamente
    ".terraform/",
]


def _deve_suprimir(vuln: dict) -> bool:
    """
    Retorna True se o finding deve ser descartado antes da deduplicação.
    Critério: arquivo em path de ruído E severidade não-CRITICAL.
    (Críticos em node_modules ainda são reportados — podem ser reachable.)
    """
    sev = vuln.get("severidade_normalizada", "INFO")
    if sev == "CRITICAL":
        return False

    arquivo = vuln.get("arquivo", "").replace("\\", "/").lower()
    return any(p in arquivo for p in _PATHS_SUPRIMIDOS)


# ══════════════════════════════════════════════════════════════════════════════
# 5. DEDUPLICAÇÃO
# Findings com mesmo fingerprint são fundidos num único registro.
# O finding de maior severidade vence; as origens são acumuladas.
# ══════════════════════════════════════════════════════════════════════════════

def _indice_severidade(sev: str) -> int:
    """Menor índice = maior severidade."""
    try:
        return SEVERIDADES_ORDENADAS.index(sev)
    except ValueError:
        return len(SEVERIDADES_ORDENADAS)


def _fundir(primario: dict, duplicata: dict) -> dict:
    """
    Funde a duplicata no primário:
      - Mantém a maior severidade
      - Acumula origens e tags de correlação sem repetição
      - Incrementa contador de ferramentas confirmadoras
    """
    sev_p = _indice_severidade(primario.get("severidade_normalizada", "INFO"))
    sev_d = _indice_severidade(duplicata.get("severidade_normalizada", "INFO"))

    if sev_d < sev_p:
        # Duplicata tem severidade maior: promove seus campos descritivos
        for campo in ("severidade", "severidade_normalizada", "descricao",
                      "trecho_do_codigo", "score_base"):
            if duplicata.get(campo):
                primario[campo] = duplicata[campo]

    # Acumula origens
    origens = primario.get("origens_confirmadas", [primario.get("origem", "")])
    nova_origem = duplicata.get("origem", "")
    if nova_origem and nova_origem not in origens:
        origens.append(nova_origem)
    primario["origens_confirmadas"] = origens
    primario["ferramentas_confirmaram"] = len(origens)

    # Acumula tags de correlação
    tags_existentes = set(primario.get("tags_correlacao", []))
    tags_existentes.update(duplicata.get("tags_correlacao", []))
    if len(origens) > 1:
        tags_existentes.add("confirmado_por_multiplas_ferramentas")
    primario["tags_correlacao"] = sorted(tags_existentes)

    return primario


def deduplicar(vulns: list[dict]) -> tuple[list[dict], dict]:
    """
    Deduplica a lista de findings por fingerprint.

    Retorna:
        (findings_unicos, stats) onde stats contém contagens de diagnóstico.
    """
    vistos: dict[str, dict]  = {}   # fingerprint → finding canônico
    suprimidos = 0
    duplicatas = 0

    for v in vulns:
        if _deve_suprimir(v):
            suprimidos += 1
            continue

        fp = v.get("fingerprint") or _gerar_fingerprint(v)
        v["fingerprint"] = fp

        if fp not in vistos:
            vistos[fp] = v
            vistos[fp].setdefault("origens_confirmadas", [v.get("origem", "")])
            vistos[fp]["ferramentas_confirmaram"] = 1
        else:
            _fundir(vistos[fp], v)
            duplicatas += 1

    return list(vistos.values()), {
        "total_entrada":    len(vulns),
        "suprimidos":       suprimidos,
        "duplicatas":       duplicatas,
        "unicos":           len(vistos),
    }


# ══════════════════════════════════════════════════════════════════════════════
# 6. PONTO DE ENTRADA PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def normalizar(vulns: list[dict]) -> tuple[list[dict], dict]:
    """
    Normaliza, extrai metadados e deduplica a lista de findings brutos.

    Etapas:
      1. Normalização de severidade para escala canônica
      2. Extração de CWE(s)
      3. Geração de fingerprint determinístico
      4. Supressão de paths de ruído
      5. Deduplicação por fingerprint

    Retorna:
        (findings_normalizados, stats)
    """
    # Passo 1-3: enriquecer cada finding individualmente
    for v in vulns:
        v["severidade_normalizada"] = _normalizar_severidade(
            v.get("severidade", "")
        )
        if not v.get("cwe"):
            v["cwe"] = _extrair_cwe(v)
        v["fingerprint"] = _gerar_fingerprint(v)

    # Passo 4-5: suprimir e deduplicar
    unicos, stats = deduplicar(vulns)

    return unicos, stats
