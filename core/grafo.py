   # PhantomFix — Copyright (C) 2025–2026 Rafael Pedro, Bernardo Coroa,
   # Giovanna Esmelardi, Gustavo Enrique
   # SPDX-License-Identifier: GPL-3.0-or-later
   # Licenciado sob a GNU GPL v3. Veja LICENSE.md na raiz do repositório.
"""
PhantomFix — grafo.py
Versão: 1.2.0

Constrói o grafo de ataque em NetworkX a partir dos findings enriquecidos,
correlaciona findings de origens diferentes que descrevem o mesmo problema,
calcula reachability de cada finding e deriva o PhantomScore auditável.

Dependência: pip install networkx

Encaixe no pipeline (core/main.py), DEPOIS do Analyser e ANTES de salvar
o relatório inicial:

    vulnerabilidades, _ = correlacionar_cross_origem(vulnerabilidades)
    grafo, reachability = construir_grafo(vulnerabilidades)
    vulnerabilidades    = calcular_phantom_score_batch(vulnerabilidades, reachability)

PhantomScore (0–10), soma ponderada — NÃO multiplicativa:

    40% CVSS (NVD) ou score do Analyser
    20% EPSS (FIRST) — se o finding não tem CVE, usa 0.5 (neutro)
    15% KEV  (CISA)  — 1.0 se está na lista, 0.0 se não
    25% reachability do grafo

Multiplicar por EPSS zeraria todo SAST sem CVE. Soma ponderada + EPSS
neutro mantém SQL injection crítico no topo da fila.

Reachability NÃO é taint analysis. É heurística de co-localização +
categoria (entrada / impacto / amplificador) + origem do scanner.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import networkx as nx


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════

SCORE_MAX_ANALYSER = 10.0

W_CVSS  = 0.40
W_EPSS  = 0.20
W_KEV   = 0.15
W_REACH = 0.25

REACHABILITY_ORIGEM: dict[str, float] = {
    "zap":        1.0,
    "nuclei":     1.0,
    "gitleaks":   0.9,
    "trufflehog": 0.85,
    "trivy":      0.8,
    "grype":      0.8,
    "semgrep":    0.7,
    "spectral":   0.6,
    "checkov":    0.5,
    "hadolint":   0.4,
}

CATEGORIAS_ENTRADA = {
    "sql injection", "injeção de sql", "injeção sql", "sqli",
    "xss", "cross-site scripting",
    "open redirect",
    "path traversal", "directory traversal",
    "shell injection", "injeção de comando", "command injection",
    "code injection", "execução de código arbitrário",
    "cors", "misconfiguração de cors",
    "rce", "execução remota de código",
    "ssrf", "ssti", "xxe",
    "prototype pollution",
    "remote property injection",
    "information disclosure", "divulgação de informação",
}

CATEGORIAS_IMPACTO = {
    "exposição de segredo", "exposição de credenciais", "exposição de chave privada",
    "vazamento de credenciais", "exposição de segredos",
    "supply chain", "cadeia de suprimentos",
    "log injection",
}

CATEGORIAS_AMPLIFICADOR = {
    "configuração insegura", "configuração de segurança",
    "configuração incorreta", "cabeçalhos de segurança ausentes",
    "configuração de transporte inseguro",
    "configuração tls inadequada", "configuração insegura de tls",
    "logging and monitoring", "logging e monitoramento",
}

ORIGENS_SECRETS = {"gitleaks", "trufflehog"}

_CWE_INJECTION = {
    "CWE-22", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-90",
    "CWE-91", "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98",
    "CWE-352", "CWE-601", "CWE-611", "CWE-917", "CWE-918", "CWE-943",
}

_KW_INJECTION = (
    "injection", "injeção", "injecao", "xss", "sqli", "sql injection",
    "command injection", "rce", "ssrf", "ssti", "xxe", "path traversal",
    "directory traversal", "open redirect", "code injection",
    "template injection", "os command", "shell injection",
    "injeção de sql", "injeção de comando",
)

_TIPOS_SECRETS_NORM: dict[str, str] = {
    "private-key":             "private-key",
    "privatekey":              "private-key",
    "private_key":             "private-key",
    "generic-api-key":         "generic-api-key",
    "generic_api_key":         "generic-api-key",
    "detected-generic-secret": "generic-secret",
    "jwt":                     "jwt",
    "detected-jwt-token":      "jwt",
}


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _categoria_normalizada(finding: dict) -> str:
    return (finding.get("categoria") or "").lower().strip()


def _cwes(finding: dict) -> list[str]:
    raw = finding.get("cwe") or finding.get("cwes") or finding.get("cwe_ids") or []
    if isinstance(raw, str):
        raw = [raw]
    return [str(c).upper() for c in raw if c]


def _eh_injection(finding: dict) -> bool:
    """True se CWE, tipo ou categoria indicam vetor de injeção/entrada."""
    if any(c in _CWE_INJECTION for c in _cwes(finding)):
        return True
    texto = f"{finding.get('tipo', '')} {finding.get('categoria', '')}".lower()
    return any(k in texto for k in _KW_INJECTION)


def _eh_segredo(finding: dict) -> bool:
    if (finding.get("origem") or "").lower() in ORIGENS_SECRETS:
        return True
    texto = f"{finding.get('tipo', '')} {finding.get('categoria', '')}".lower()
    return any(
        k in texto
        for k in ("secret", "segredo", "credencial", "password", "private-key",
                  "api-key", "apikey", "token", "hardcoded")
    )


def _tipo_no(finding: dict) -> str:
    """Classifica o finding em: entrada | impacto | amplificador | intermediario."""
    if _eh_injection(finding):
        return "entrada"
    cat = _categoria_normalizada(finding)
    for c in CATEGORIAS_ENTRADA:
        if c in cat:
            return "entrada"
    for c in CATEGORIAS_IMPACTO:
        if c in cat:
            return "impacto"
    if _eh_segredo(finding):
        return "impacto"
    for c in CATEGORIAS_AMPLIFICADOR:
        if c in cat:
            return "amplificador"
    return "intermediario"


def _arquivo_base(arquivo: str) -> str:
    """Caminho relativo ao repo — remove prefixo do job no servidor."""
    if not arquivo:
        return ""
    arquivo = arquivo.replace("\\", "/")
    if "/repo/" in arquivo:
        return arquivo.split("/repo/", 1)[-1]
    m = re.search(r"/repo/(.+)$", arquivo)
    return m.group(1) if m else arquivo.lstrip("/")


def _mesmo_arquivo(a: str, b: str) -> bool:
    return _arquivo_base(a) == _arquivo_base(b) and bool(_arquivo_base(a))


def _mesmo_modulo(a: str, b: str) -> bool:
    pa = Path(_arquivo_base(a))
    pb = Path(_arquivo_base(b))
    return pa.parent == pb.parent and str(pa.parent) not in (".", "")


def _score_base(finding: dict) -> float:
    cvss = finding.get("cvss_v3")
    if cvss is not None:
        try:
            return min(float(cvss), 10.0)
        except (TypeError, ValueError):
            pass
    s = finding.get("score")
    if s is not None:
        try:
            return min(float(s), SCORE_MAX_ANALYSER)
        except (TypeError, ValueError):
            pass
    sev = (finding.get("severidade") or finding.get("severidade_normalizada") or "").upper()
    return {
        "ERROR": 7.0, "CRITICAL": 9.0, "HIGH": 7.0,
        "WARNING": 5.0, "MEDIUM": 5.0, "INFO": 2.0, "LOW": 2.0,
    }.get(sev, 3.0)


def _tipo_secret_norm(tipo: str) -> str:
    return _TIPOS_SECRETS_NORM.get(tipo.lower(), tipo.lower())


def _melhor_score(a: dict, b: dict) -> dict:
    return a if _score_base(a) >= _score_base(b) else b


# ══════════════════════════════════════════════════════════════════════════════
# CORRELAÇÃO CROSS-ORIGEM
# ══════════════════════════════════════════════════════════════════════════════

def correlacionar_cross_origem(
    vulnerabilidades: list[dict],
) -> tuple[list[dict], list[dict]]:
    """
    Três regras:

    1. Merge secrets (gitleaks × trufflehog, mesmo arquivo, tipo compatível)
    2. Merge SAST mesma linha (semgrep × semgrep)
    3. Anotação (sem merge): segredo + injeção no mesmo arquivo
       — casada por CWE/categoria, não por check_id do Semgrep JS
    """
    suprimidos: list[dict] = []
    suprimidos_ids: set[str] = set()

    por_arquivo: dict[str, list[dict]] = defaultdict(list)
    for v in vulnerabilidades:
        por_arquivo[_arquivo_base(v.get("arquivo", ""))].append(v)

    # ── Regra 1: merge secrets cross-origem ──────────────────────────────────
    for _arq, grupo in por_arquivo.items():
        secrets_grupo = [
            v for v in grupo
            if _eh_segredo(v) and v.get("id") not in suprimidos_ids
        ]
        por_tipo: dict[str, list[dict]] = defaultdict(list)
        for v in secrets_grupo:
            por_tipo[_tipo_secret_norm(v.get("tipo", ""))].append(v)

        for _tipo_norm, candidatos in por_tipo.items():
            if len(candidatos) < 2:
                continue
            origens_presentes = {(c.get("origem") or "").lower() for c in candidatos}
            if len(origens_presentes) < 2:
                continue

            sobrevivente = candidatos[0]
            for c in candidatos[1:]:
                sobrevivente = _melhor_score(sobrevivente, c)
            absorvidos = [c for c in candidatos if c.get("id") != sobrevivente.get("id")]

            todas_origens = list({
                o
                for c in candidatos
                for o in (c.get("origens_confirmadas") or [c.get("origem", "")])
                if o
            })
            sobrevivente["origens_confirmadas"]     = todas_origens
            sobrevivente["ferramentas_confirmaram"] = len(todas_origens)
            sobrevivente["correlacao_ids"]          = [c.get("id") for c in absorvidos]
            sobrevivente["correlacao_relacao"]      = "merge_secrets_cross_origem"

            for absorvido in absorvidos:
                absorvido["_suprimido_por"] = sobrevivente.get("id")
                absorvido["_motivo"]        = "merge_secrets_cross_origem"
                suprimidos.append(absorvido)
                suprimidos_ids.add(absorvido.get("id"))

    # ── Regra 2: merge SAST mesma linha ──────────────────────────────────────
    for _arq, grupo in por_arquivo.items():
        sast_grupo = [
            v for v in grupo
            if (v.get("origem") or "").lower() == "semgrep"
            and v.get("id") not in suprimidos_ids
        ]
        por_linha: dict[int, list[dict]] = defaultdict(list)
        for v in sast_grupo:
            try:
                linha = int(v.get("linha") or 0)
            except (TypeError, ValueError):
                linha = 0
            por_linha[linha].append(v)

        for linha, candidatos in por_linha.items():
            if len(candidatos) < 2 or linha == 0:
                continue

            sobrevivente = candidatos[0]
            for c in candidatos[1:]:
                sobrevivente = _melhor_score(sobrevivente, c)
            absorvidos = [c for c in candidatos if c.get("id") != sobrevivente.get("id")]

            sobrevivente["tipos_detectados"]        = list({c.get("tipo", "") for c in candidatos})
            sobrevivente["origens_confirmadas"]     = list({
                o for c in candidatos
                for o in (c.get("origens_confirmadas") or [c.get("origem", "")])
                if o
            })
            sobrevivente["ferramentas_confirmaram"] = max(
                int(sobrevivente.get("ferramentas_confirmaram") or 1), len(candidatos)
            )
            sobrevivente["correlacao_ids"]          = [c.get("id") for c in absorvidos]
            sobrevivente["correlacao_relacao"]      = "merge_sast_mesma_linha"

            for absorvido in absorvidos:
                absorvido["_suprimido_por"] = sobrevivente.get("id")
                absorvido["_motivo"]        = "merge_sast_mesma_linha"
                suprimidos.append(absorvido)
                suprimidos_ids.add(absorvido.get("id"))

    # ── Regra 3: segredo × injeção no mesmo arquivo (anota, não funde) ───────
    for _arq, grupo in por_arquivo.items():
        if not _arq:
            continue
        ativos = [v for v in grupo if v.get("id") not in suprimidos_ids]
        secrets_no_arquivo    = [v for v in ativos if _eh_segredo(v)]
        injections_no_arquivo = [v for v in ativos if _eh_injection(v)]
        if not secrets_no_arquivo or not injections_no_arquivo:
            continue

        ids_secrets    = [v.get("id") for v in secrets_no_arquivo]
        ids_injections = [v.get("id") for v in injections_no_arquivo]

        for v in secrets_no_arquivo:
            v.setdefault("correlacao_relacao", "credencial_em_endpoint_vulneravel")
            v["correlacao_par_ids"] = ids_injections
        for v in injections_no_arquivo:
            v.setdefault("correlacao_relacao", "credencial_em_endpoint_vulneravel")
            v["correlacao_par_ids"] = ids_secrets

    ativos = [v for v in vulnerabilidades if v.get("id") not in suprimidos_ids]
    print(
        f"  [correlação] {len(vulnerabilidades)} findings → "
        f"{len(ativos)} ativos + {len(suprimidos)} suprimidos"
    )
    return ativos, suprimidos


# ══════════════════════════════════════════════════════════════════════════════
# CONSTRUÇÃO DO GRAFO
# ══════════════════════════════════════════════════════════════════════════════

def construir_grafo(
    vulnerabilidades: list[dict],
) -> tuple[nx.DiGraph, dict[str, float]]:
    """
    Nós: findings (por id).
    Aresta A → B: "A facilita ou expõe B".

    Regras:
      1. Mesmo arquivo, linha próxima (≤ 50) — co-localização
      2. Mesmo módulo e categorias complementares
      3. Entrada → Impacto
      4. Amplificador → vizinhos no mesmo módulo
    """
    G = nx.DiGraph()

    for v in vulnerabilidades:
        vid = v.get("id") or ""
        if not vid:
            continue
        G.add_node(
            vid,
            tipo=_tipo_no(v),
            origem=(v.get("origem") or "semgrep").lower(),
            arquivo=v.get("arquivo", ""),
            linha=v.get("linha") or 0,
            score_base=_score_base(v),
            kev=bool(v.get("kev")),
            epss=float(v.get("epss") or 0.0),
            ferramentas=int(v.get("ferramentas_confirmaram") or 1),
            categoria=_categoria_normalizada(v),
        )

    ids = [n for n in G.nodes]
    nodes = dict(G.nodes(data=True))

    for i, id_a in enumerate(ids):
        na = nodes.get(id_a, {})
        for id_b in ids[i + 1:]:
            nb = nodes.get(id_b, {})
            arq_a  = na.get("arquivo", "")
            arq_b  = nb.get("arquivo", "")
            try:
                lin_a = int(na.get("linha") or 0)
                lin_b = int(nb.get("linha") or 0)
            except (TypeError, ValueError):
                lin_a, lin_b = 0, 0
            tipo_a = na.get("tipo", "")
            tipo_b = nb.get("tipo", "")

            peso = 0.0
            if _mesmo_arquivo(arq_a, arq_b) and abs(lin_a - lin_b) <= 50:
                peso = max(peso, 0.8)
            elif _mesmo_modulo(arq_a, arq_b):
                peso = max(peso, 0.4)

            if tipo_a == "entrada" and tipo_b == "impacto":
                G.add_edge(id_a, id_b, peso=max(peso, 0.6), relacao="entrada_para_impacto")
                continue
            if tipo_b == "entrada" and tipo_a == "impacto":
                G.add_edge(id_b, id_a, peso=max(peso, 0.6), relacao="entrada_para_impacto")
                continue

            if tipo_a == "amplificador" and peso > 0:
                G.add_edge(id_a, id_b, peso=peso * 0.7, relacao="amplifica")
            elif tipo_b == "amplificador" and peso > 0:
                G.add_edge(id_b, id_a, peso=peso * 0.7, relacao="amplifica")
            elif peso > 0:
                G.add_edge(id_a, id_b, peso=peso * 0.5, relacao="co-localizado")
                G.add_edge(id_b, id_a, peso=peso * 0.5, relacao="co-localizado")

    nos_em_caminho = _nos_em_caminho_ataque(G, nodes)

    reachability: dict[str, float] = {}
    for vid in ids:
        na = nodes.get(vid, {})
        origem = na.get("origem", "semgrep")
        base = REACHABILITY_ORIGEM.get(origem, 0.6)

        ferramentas = na.get("ferramentas", 1)
        if ferramentas >= 2:
            base = min(base + 0.1 * (ferramentas - 1), 1.0)

        grau_entrada = G.in_degree(vid)
        if grau_entrada > 0:
            base = min(base + 0.05 * grau_entrada, 1.0)

        if vid in nos_em_caminho:
            base = min(base + 0.15, 1.0)

        reachability[vid] = round(base, 4)

    return G, reachability


def _nos_em_caminho_ataque(G: nx.DiGraph, nodes: dict) -> set[str]:
    """Nós que estão entre alguma entrada e algum impacto. O(V+E), não O(n² has_path)."""
    entradas = [n for n, d in nodes.items() if d.get("tipo") == "entrada"]
    impactos = [n for n, d in nodes.items() if d.get("tipo") == "impacto"]
    if not entradas or not impactos:
        return set()

    de_entrada: set[str] = set()
    for e in entradas:
        de_entrada.add(e)
        de_entrada |= nx.descendants(G, e)

    ate_impacto: set[str] = set()
    for i in impactos:
        ate_impacto.add(i)
        ate_impacto |= nx.ancestors(G, i)

    return de_entrada & ate_impacto


# ══════════════════════════════════════════════════════════════════════════════
# PHANTOM SCORE
# ══════════════════════════════════════════════════════════════════════════════

def calcular_phantom_score(finding: dict, reachability: float) -> dict[str, Any]:
    """
    phantom = 10 × (cvss_norm×0.40 + epss_norm×0.20 + kev×0.15 + reach×0.25)

    EPSS ausente (finding sem CVE) → 0.5, não 0.0.
    KEV é binário ponderado (15%), não multiplicador 1.5×.
    """
    cvss_raw = finding.get("cvss_v3")
    score_raw = finding.get("score")
    cvss_fonte = "cvss_v3_nvd"
    cvss_val = None

    if cvss_raw is not None:
        try:
            cvss_val = float(cvss_raw) / 10.0
        except (TypeError, ValueError):
            cvss_val = None

    if cvss_val is None:
        cvss_fonte = "score_analyser"
        if score_raw is not None:
            try:
                cvss_val = float(score_raw) / SCORE_MAX_ANALYSER
            except (TypeError, ValueError):
                cvss_val = None

    if cvss_val is None:
        cvss_fonte = "severidade_fallback"
        sev = (finding.get("severidade") or finding.get("severidade_normalizada") or "").upper()
        cvss_val = {
            "ERROR": 0.7, "CRITICAL": 0.9, "HIGH": 0.7,
            "WARNING": 0.5, "MEDIUM": 0.5, "INFO": 0.2, "LOW": 0.2,
        }.get(sev, 0.3)

    cvss_val = min(max(cvss_val, 0.0), 1.0)

    epss_raw = finding.get("epss")
    if epss_raw is None:
        epss_val = 0.5
        epss_fonte = "epss_ausente_neutro"
    else:
        try:
            epss_val = float(epss_raw)
        except (TypeError, ValueError):
            epss_val = 0.5
            epss_fonte = "epss_ausente_neutro"
        else:
            epss_fonte = "epss_first"
    epss_val = min(max(epss_val, 0.0), 1.0)

    kev_raw = finding.get("kev")
    kev_val = 1.0 if kev_raw else 0.0
    kev_fonte = "cisa_kev" if kev_raw else "kev_ausente_zero"

    reach_val = min(max(float(reachability), 0.0), 1.0)
    reach_fonte = "grafo_networkx"

    score_bruto = (
        cvss_val * W_CVSS
        + epss_val * W_EPSS
        + kev_val * W_KEV
        + reach_val * W_REACH
    )
    phantom = round(min(max(score_bruto * 10.0, 0.0), 10.0), 2)

    return {
        "phantom_score": phantom,
        "reachability":  round(reach_val, 4),
        "phantom_componentes": {
            "cvss":         {"valor": round(cvss_val * 10, 2), "peso": W_CVSS,  "fonte": cvss_fonte},
            "epss":         {"valor": round(epss_val, 4),      "peso": W_EPSS,  "fonte": epss_fonte},
            "kev":          {"valor": kev_val,                 "peso": W_KEV,   "fonte": kev_fonte},
            "reachability": {"valor": round(reach_val, 4),     "peso": W_REACH, "fonte": reach_fonte},
        },
    }


def calcular_phantom_score_batch(
    vulnerabilidades: list[dict],
    reachability: dict[str, float],
) -> list[dict]:
    for v in vulnerabilidades:
        vid = v.get("id", "")
        origem = (v.get("origem") or "semgrep").lower()
        reach = reachability.get(vid, REACHABILITY_ORIGEM.get(origem, 0.6))
        v.update(calcular_phantom_score(v, reach))
    return vulnerabilidades


# ══════════════════════════════════════════════════════════════════════════════
# EXPORTAÇÃO / STATS
# ══════════════════════════════════════════════════════════════════════════════

def exportar_grafo_json(G: nx.DiGraph) -> dict:
    nos = [
        {
            "id":        n,
            "tipo":      d.get("tipo", ""),
            "origem":    d.get("origem", ""),
            "arquivo":   _arquivo_base(d.get("arquivo", "")),
            "linha":     d.get("linha", 0),
            "score":     d.get("score_base", 0.0),
            "kev":       d.get("kev", False),
            "epss":      d.get("epss", 0.0),
            "categoria": d.get("categoria", ""),
        }
        for n, d in G.nodes(data=True)
    ]
    arestas = [
        {
            "de":      u,
            "para":    v,
            "peso":    round(d.get("peso", 0.0), 3),
            "relacao": d.get("relacao", ""),
        }
        for u, v, d in G.edges(data=True)
    ]
    return {
        "nos":           nos,
        "arestas":       arestas,
        "total_nos":     len(nos),
        "total_arestas": len(arestas),
    }


def estatisticas_grafo(G: nx.DiGraph, reachability: dict[str, float]) -> dict:
    entradas = [n for n, d in G.nodes(data=True) if d.get("tipo") == "entrada"]
    impactos = [n for n, d in G.nodes(data=True) if d.get("tipo") == "impacto"]

    caminhos: list[dict] = []
    for e in entradas:
        descendentes = nx.descendants(G, e)
        for i in impactos:
            if i == e or i not in descendentes:
                continue
            try:
                caminho = nx.shortest_path(G, e, i)
            except (nx.NetworkXError, nx.NetworkXNoPath):
                continue
            caminhos.append({
                "entrada":     e,
                "impacto":     i,
                "comprimento": len(caminho) - 1,
                "caminho":     caminho,
            })

    reach_medio = (
        round(sum(reachability.values()) / len(reachability), 4)
        if reachability else 0.0
    )
    return {
        "total_nos":          G.number_of_nodes(),
        "total_arestas":      G.number_of_edges(),
        "nos_entrada":        len(entradas),
        "nos_impacto":        len(impactos),
        "caminhos_ataque":    len(caminhos),
        "reachability_medio": reach_medio,
        "top_caminhos":       sorted(caminhos, key=lambda c: c["comprimento"])[:5],
    }
