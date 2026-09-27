"""
PhantomFix — Enricher
Versão: 1.0
Autor: Rafael Pedro

Descrição:
Enriquece findings com dados externos de exploitabilidade antes do LLM.
Roda APÓS normalização e correlação mecânica.

Fontes:
  NVD   — CVSS v3 base score + vetor (https://services.nvd.nist.gov)
  EPSS  — Probabilidade de exploração nos próximos 30 dias (https://api.first.org)
  CISA KEV — Lista de vulnerabilidades com exploração ativa confirmada

Rate limits:
  NVD sem chave: 5 req/30s   → sleep 6s entre chamadas
  NVD com chave: 50 req/30s  → sleep 0.6s entre chamadas  (env NVD_API_KEY)
  EPSS: sem limite declarado  → sleep 1s por precaução
  KEV:  1 download por scan   → cache em memória durante a execução

Campos adicionados por finding:
  cvss_v3          float | None   — score base CVSS v3 (ex: 9.8)
  cvss_vetor       str   | None   — vetor CVSS (ex: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
  epss             float | None   — probabilidade 0-1 de exploração em 30 dias
  epss_percentil   float | None   — percentil do score EPSS (0-1)
  kev              bool  | None   — está na lista CISA KEV?
  kev_data_adicao  str   | None   — data de adição ao KEV (ISO 8601)
  enriquecido_em   str           — timestamp do enriquecimento
"""

import json
import os
import time
from datetime import datetime, timezone
from typing import Optional

import requests

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO
# ══════════════════════════════════════════════════════════════════════════════

NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_BASE    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE   = "https://api.first.org/data/v1/epss"
KEV_URL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

NVD_SLEEP   = 0.7 if NVD_API_KEY else 6.1   # segundos entre chamadas NVD
EPSS_SLEEP  = 1.0
HTTP_TIMEOUT = 15   # segundos

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "PhantomFix/1.0 (security-research)"})
if NVD_API_KEY:
    _SESSION.headers.update({"apiKey": NVD_API_KEY})


# ══════════════════════════════════════════════════════════════════════════════
# CACHE EM MEMÓRIA (válido durante a execução do scan)
# ══════════════════════════════════════════════════════════════════════════════

_cache_nvd:  dict[str, Optional[dict]] = {}
_cache_epss: dict[str, Optional[dict]] = {}
_cache_kev:  Optional[set[str]]        = None   # conjunto de CVE IDs no KEV
_cache_kev_meta: dict[str, str]        = {}      # cve_id → data_adicao


# ══════════════════════════════════════════════════════════════════════════════
# 1. NVD — CVSS v3
# ══════════════════════════════════════════════════════════════════════════════

def _buscar_nvd(cve_id: str) -> Optional[dict]:
    """
    Retorna {'score': float, 'vetor': str} ou None em caso de erro/ausência.
    Respeita cache e rate limit.
    """
    cve_upper = cve_id.upper()
    if cve_upper in _cache_nvd:
        return _cache_nvd[cve_upper]

    try:
        resp = _SESSION.get(
            NVD_BASE,
            params={"cveId": cve_upper},
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        dados = resp.json()

        vulns = dados.get("vulnerabilities", [])
        if not vulns:
            _cache_nvd[cve_upper] = None
            return None

        cve_data = vulns[0].get("cve", {})

        # Prefere CVSSv3.1, cai para v3.0, ignora v2
        metrics = cve_data.get("metrics", {})
        for chave in ("cvssMetricV31", "cvssMetricV30"):
            lista = metrics.get(chave, [])
            if lista:
                cvss_data = lista[0].get("cvssData", {})
                resultado = {
                    "score":  cvss_data.get("baseScore"),
                    "vetor":  cvss_data.get("vectorString"),
                }
                _cache_nvd[cve_upper] = resultado
                return resultado

        _cache_nvd[cve_upper] = None
        return None

    except Exception as e:
        print(f"    ⚠ NVD [{cve_upper}]: {e}")
        _cache_nvd[cve_upper] = None
        return None
    finally:
        time.sleep(NVD_SLEEP)


# ══════════════════════════════════════════════════════════════════════════════
# 2. EPSS — Probabilidade de exploração (FIRST.org)
# ══════════════════════════════════════════════════════════════════════════════

def _buscar_epss_batch(cve_ids: list[str]) -> dict[str, dict]:
    """
    Busca EPSS para um batch de CVEs em uma única chamada (API suporta múltiplos).
    Retorna {cve_id: {'epss': float, 'percentil': float}}.
    """
    if not cve_ids:
        return {}

    # Filtra os que já estão em cache
    novos = [c for c in cve_ids if c.upper() not in _cache_epss]
    if not novos:
        return {c.upper(): _cache_epss[c.upper()] for c in cve_ids if _cache_epss.get(c.upper())}

    resultado: dict[str, dict] = {}

    # EPSS aceita até ~10 CVEs por chamada com segurança
    BATCH = 10
    for i in range(0, len(novos), BATCH):
        lote = novos[i : i + BATCH]
        try:
            resp = _SESSION.get(
                EPSS_BASE,
                params={"cve": ",".join(lote)},
                timeout=HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            dados = resp.json()

            for item in dados.get("data", []):
                cve   = item.get("cve", "").upper()
                entry = {
                    "epss":      float(item.get("epss", 0)),
                    "percentil": float(item.get("percentile", 0)),
                }
                _cache_epss[cve] = entry
                resultado[cve]   = entry

            # Marca os não encontrados como None
            for c in lote:
                if c.upper() not in _cache_epss:
                    _cache_epss[c.upper()] = None

        except Exception as e:
            print(f"    ⚠ EPSS batch erro: {e}")
            for c in lote:
                _cache_epss[c.upper()] = None

        time.sleep(EPSS_SLEEP)

    # Retorna tudo que estava em cache (novos + antigos)
    return {
        c.upper(): _cache_epss[c.upper()]
        for c in cve_ids
        if _cache_epss.get(c.upper())
    }


# ══════════════════════════════════════════════════════════════════════════════
# 3. CISA KEV — Exploração ativa confirmada
# ══════════════════════════════════════════════════════════════════════════════

def _carregar_kev() -> None:
    """
    Baixa o catálogo CISA KEV uma única vez por execução e popula o cache.
    Em caso de falha, _cache_kev permanece None e verificações retornam None.
    """
    global _cache_kev, _cache_kev_meta
    if _cache_kev is not None:   # já carregado
        return

    try:
        resp = _SESSION.get(KEV_URL, timeout=30)
        resp.raise_for_status()
        catalogo = resp.json()

        _cache_kev = set()
        for vuln in catalogo.get("vulnerabilities", []):
            cve = vuln.get("cveID", "").upper()
            if cve:
                _cache_kev.add(cve)
                _cache_kev_meta[cve] = vuln.get("dateAdded", "")

        print(f"  CISA KEV: {len(_cache_kev)} CVEs carregados")

    except Exception as e:
        print(f"  ⚠ Falha ao carregar CISA KEV: {e}")
        _cache_kev = set()   # vazio mas não None — não tenta de novo


def _verificar_kev(cve_id: str) -> tuple[bool, Optional[str]]:
    """
    Retorna (está_no_kev, data_adicao).
    data_adicao é None se o CVE não estiver no KEV.
    """
    _carregar_kev()
    cve_upper = cve_id.upper()
    esta = cve_upper in _cache_kev
    data = _cache_kev_meta.get(cve_upper) if esta else None
    return esta, data


# ══════════════════════════════════════════════════════════════════════════════
# 4. PONTO DE ENTRADA PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def _extrair_cves(vuln: dict) -> list[str]:
    """Extrai todos os CVE IDs de um finding (pode ter zero, um ou vários)."""
    cves = []
    # Campo direto
    if vuln.get("cve_id"):
        cves.append(vuln["cve_id"])
    # Campo da lista (Grype, Trivy com múltiplos CVEs)
    for campo in ("cve_ids", "cves"):
        val = vuln.get(campo, [])
        if isinstance(val, list):
            cves.extend(val)
        elif isinstance(val, str) and val:
            cves.append(val)
    # Extrai CVE da descrição como fallback
    if not cves:
        import re
        matches = re.findall(r'\bCVE-\d{4}-\d{4,}\b', vuln.get("descricao", ""), re.IGNORECASE)
        cves.extend(matches)

    # Normaliza e deduplica
    return list({c.upper() for c in cves if c.upper().startswith("CVE-")})


def enriquecer(vulns: list[dict]) -> tuple[list[dict], dict]:
    """
    Enriquece a lista de findings com dados de NVD, EPSS e CISA KEV.

    Estratégia:
      - Coleta todos os CVE IDs únicos
      - Baixa KEV uma vez só
      - Busca EPSS em batch
      - Busca NVD individualmente (respeitando rate limit)
      - Aplica dados nos findings correspondentes

    Retorna:
        (findings_enriquecidos, stats)
    """
    ts = datetime.now(timezone.utc).isoformat()

    # ── Coleta CVEs únicos ────────────────────────────────────────────────────
    todos_cves: set[str] = set()
    mapa_finding_cves: dict[int, list[str]] = {}   # índice → lista de CVEs

    for idx, v in enumerate(vulns):
        cves = _extrair_cves(v)
        mapa_finding_cves[idx] = cves
        todos_cves.update(cves)

    total_cves = len(todos_cves)
    print(f"\n[Enriquecimento] {total_cves} CVE(s) únicos encontrados nos findings")

    if total_cves == 0:
        # Nenhum CVE → apenas carimba o timestamp e retorna
        for v in vulns:
            v["enriquecido_em"] = ts
            v.setdefault("cvss_v3", None)
            v.setdefault("cvss_vetor", None)
            v.setdefault("epss", None)
            v.setdefault("epss_percentil", None)
            v.setdefault("kev", None)
            v.setdefault("kev_data_adicao", None)
        return vulns, {"total_cves": 0, "nvd_ok": 0, "epss_ok": 0, "kev_count": 0}

    # ── KEV (1 download) ──────────────────────────────────────────────────────
    print("  Baixando CISA KEV...")
    _carregar_kev()

    # ── EPSS (batch) ─────────────────────────────────────────────────────────
    lista_cves = list(todos_cves)
    print(f"  Buscando EPSS para {len(lista_cves)} CVE(s)...")
    epss_map = _buscar_epss_batch(lista_cves)

    # ── NVD (individual, com rate limit) ─────────────────────────────────────
    print(f"  Buscando NVD (CVSS) para {len(lista_cves)} CVE(s)...")
    if not NVD_API_KEY:
        print(f"    (sem NVD_API_KEY → {NVD_SLEEP}s entre chamadas)")
    nvd_map: dict[str, Optional[dict]] = {}
    for i, cve in enumerate(lista_cves, 1):
        print(f"    [{i}/{len(lista_cves)}] {cve}", end="\r", flush=True)
        nvd_map[cve] = _buscar_nvd(cve)

    print()   # quebra linha após o \r

    # ── Aplica nos findings ───────────────────────────────────────────────────
    nvd_ok = epss_ok = kev_count = 0

    for idx, v in enumerate(vulns):
        cves = mapa_finding_cves.get(idx, [])

        # Inicializa campos
        v["enriquecido_em"]  = ts
        v["cvss_v3"]         = None
        v["cvss_vetor"]      = None
        v["epss"]            = None
        v["epss_percentil"]  = None
        v["kev"]             = False
        v["kev_data_adicao"] = None

        if not cves:
            v["kev"] = None   # indeterminado (sem CVE)
            continue

        # Para findings com múltiplos CVEs, usa o de maior CVSS
        melhor_cvss = None
        for cve in cves:
            nvd = nvd_map.get(cve)
            if nvd and (melhor_cvss is None or nvd["score"] > melhor_cvss["score"]):
                melhor_cvss = nvd
                v["cvss_v3"]    = nvd["score"]
                v["cvss_vetor"] = nvd["vetor"]

        if melhor_cvss:
            nvd_ok += 1
            # Usa CVSS como score_base se a correlação não definiu um
            if not v.get("score_base") or v["score_base"] == 0:
                v["score_base"] = melhor_cvss["score"]

        # EPSS: usa o maior percentil entre os CVEs do finding
        melhor_epss = None
        for cve in cves:
            ep = epss_map.get(cve)
            if ep and (melhor_epss is None or ep["percentil"] > melhor_epss["percentil"]):
                melhor_epss = ep
        if melhor_epss:
            v["epss"]           = melhor_epss["epss"]
            v["epss_percentil"] = melhor_epss["percentil"]
            epss_ok += 1

        # KEV: basta um dos CVEs estar no catálogo
        for cve in cves:
            esta, data = _verificar_kev(cve)
            if esta:
                v["kev"]             = True
                v["kev_data_adicao"] = data
                kev_count += 1
                # KEV confirma exploração ativa → eleva score_base ao mínimo 9.0
                if (v.get("score_base") or 0) < 9.0:
                    v["score_base"] = 9.0
                    v.setdefault("tags_correlacao", [])
                    if "kev_exploracao_ativa" not in v["tags_correlacao"]:
                        v["tags_correlacao"].append("kev_exploracao_ativa")
                break   # já encontrou KEV, não precisa continuar

    stats = {
        "total_cves":   total_cves,
        "nvd_ok":       nvd_ok,
        "epss_ok":      epss_ok,
        "kev_count":    kev_count,
    }

    print(
        f"  Enriquecimento concluído: "
        f"NVD {nvd_ok}/{total_cves} · "
        f"EPSS {epss_ok}/{total_cves} · "
        f"KEV {kev_count} findings"
    )

    return vulns, stats
