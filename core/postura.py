"""
PhantomFix — postura.py
Agregação histórica mecânica para a tela Postura do Dashboard.
Não chama LLM. Cache em memória com TTL de 60s.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable

# ── Cache simples por (user_id, projeto_id) ────────────────────────────────────
_CACHE: dict[tuple, tuple[float, dict]] = {}
_CACHE_TTL = 60  # segundos


def _cache_get(chave: tuple) -> dict | None:
    entry = _CACHE.get(chave)
    if not entry:
        return None
    ts, data = entry
    if time.time() - ts > _CACHE_TTL:
        _CACHE.pop(chave, None)
        return None
    return data


def _cache_set(chave: tuple, data: dict):
    _CACHE[chave] = (time.time(), data)


# ── Classificação de criptografia ─────────────────────────────────────────────
_LEGADO = {"sha-1", "sha1", "md5", "des", "rc4", "3des", "triple-des", "rc2"}
_PADRAO_OURO = {
    "ml-kem", "mlkem", "crystals", "crystals-kyber", "kyber",
    "dilithium", "falcon", "sphincs", "ntru",
}
_FUNCIONAL = {
    "aes", "aes-128", "aes-192", "aes-256", "aes-gcm", "aes-cbc",
    "rsa", "rsa-2048", "rsa-3072", "rsa-4096",
    "ecdsa", "ecdh", "ed25519", "ed448", "chacha20", "poly1305",
    "sha-256", "sha256", "sha-384", "sha384", "sha-512", "sha512",
    "hmac", "pbkdf2", "argon2", "scrypt", "bcrypt",
}


def _classificar_algo(nome: str) -> str:
    n = nome.lower().strip().replace("_", "-")
    if n in _LEGADO or any(n.startswith(x) for x in _LEGADO):
        return "legado"
    if n in _PADRAO_OURO or any(x in n for x in _PADRAO_OURO):
        return "padrao_ouro"
    if n in _FUNCIONAL or any(n.startswith(x) for x in _FUNCIONAL):
        return "funcional"
    return "funcional"  # desconhecido → funcional por padrão


def _agregar_criptografia(relatorio: dict) -> dict:
    """Lê algoritmos_criptografia do relatório ou infere dos findings."""
    algos_raw = relatorio.get("algoritmos_criptografia") or []
    if not algos_raw:
        # tenta extrair de findings com tipo relacionado a crypto
        for v in relatorio.get("vulnerabilidades", []):
            tipo = (v.get("tipo") or "").lower()
            desc = (v.get("descricao") or "").lower()
            for palavra in list(_LEGADO) + list(_FUNCIONAL) + list(_PADRAO_OURO):
                if palavra in tipo or palavra in desc:
                    algos_raw.append(palavra.upper() if len(palavra) <= 6 else palavra)
                    break

    buckets = {
        "legado": {"count": 0, "exemplos": []},
        "funcional": {"count": 0, "exemplos": []},
        "padrao_ouro": {"count": 0, "exemplos": []},
    }
    vistos: set[str] = set()
    for a in algos_raw:
        nome = str(a).strip()
        if not nome or nome.lower() in vistos:
            continue
        vistos.add(nome.lower())
        cat = _classificar_algo(nome)
        buckets[cat]["count"] += 1
        if len(buckets[cat]["exemplos"]) < 5:
            buckets[cat]["exemplos"].append(nome)
    return buckets


def _score_do_relatorio(rel: dict) -> float | None:
    """PhantomScore agregado do scan. Tenta vários campos conhecidos."""
    # score explícito no relatório
    for chave in ("phantom_score", "score_agregado", "score"):
        val = rel.get(chave)
        if val is not None:
            try:
                return round(float(val), 1)
            except (TypeError, ValueError):
                pass
    # média dos scores dos findings
    vulns = rel.get("vulnerabilidades") or []
    scores = []
    for v in vulns:
        try:
            s = float(v.get("score") or 0)
            if s > 0:
                scores.append(s)
        except (TypeError, ValueError):
            pass
    if scores:
        # PhantomScore de postura: quanto maior o risco médio, menor a postura
        # Aqui usamos a média invertida em escala 0-10 para "postura"
        # Se o dashboard espera "quanto maior melhor", invertemos:
        media_risco = sum(scores) / len(scores)
        postura = max(0.0, min(10.0, 10.0 - media_risco))
        return round(postura, 1)
    return None


def _contagem_severidade(rel: dict) -> dict:
    vulns = rel.get("vulnerabilidades") or []
    alta = media = baixa = 0
    for v in vulns:
        try:
            s = float(v.get("score") or 0)
        except (TypeError, ValueError):
            s = 0
        if s >= 7:
            alta += 1
        elif s >= 4:
            media += 1
        else:
            baixa += 1
    return {"total": len(vulns), "alta": alta, "media": media, "baixa": baixa}


def _chave_finding(v: dict) -> str:
    nome = (v.get("tipo") or v.get("nome") or v.get("id") or "").strip().lower()
    return nome


def _recorrentes(relatorios: list[dict], limite: int = 5) -> list[dict]:
    """Findings cujo nome+tipo aparecem em 2+ scans consecutivos (mais recentes primeiro)."""
    if len(relatorios) < 2:
        return []

    # relatorios já ordenados do mais recente ao mais antigo
    contagem: dict[str, dict] = {}
    for i, rel in enumerate(relatorios):
        chaves_scan = set()
        for v in rel.get("vulnerabilidades") or []:
            k = _chave_finding(v)
            if not k or k in chaves_scan:
                continue
            chaves_scan.add(k)
            if k not in contagem:
                contagem[k] = {
                    "nome": v.get("tipo") or v.get("nome") or k,
                    "tipo": v.get("categoria") or v.get("tipo") or "",
                    "scans_consecutivos": 1,
                    "severidade": _sev_label(v),
                    "_ultimo_idx": i,
                }
            else:
                # consecutivo se o scan anterior (idx-1) também tinha
                if contagem[k]["_ultimo_idx"] == i - 1:
                    contagem[k]["scans_consecutivos"] += 1
                    contagem[k]["_ultimo_idx"] = i
                # se quebrou a sequência, não incrementa

    resultado = [
        {k: v for k, v in item.items() if not k.startswith("_")}
        for item in contagem.values()
        if item["scans_consecutivos"] >= 2
    ]
    resultado.sort(key=lambda x: x["scans_consecutivos"], reverse=True)
    return resultado[:limite]


def _sev_label(v: dict) -> str:
    try:
        s = float(v.get("score") or 0)
    except (TypeError, ValueError):
        s = 0
    if s >= 9:
        return "critica"
    if s >= 7:
        return "alta"
    if s >= 4:
        return "media"
    return "baixa"


def _resumo_alteracoes(rel: dict, rel_ant: dict | None) -> str:
    if not rel_ant:
        return "primeiro scan"
    atual = {_chave_finding(v) for v in (rel.get("vulnerabilidades") or []) if _chave_finding(v)}
    ant = {_chave_finding(v) for v in (rel_ant.get("vulnerabilidades") or []) if _chave_finding(v)}
    novos = len(atual - ant)
    fechados = len(ant - atual)
    partes = []
    if fechados:
        partes.append(f"{fechados} corrigido{'s' if fechados != 1 else ''}")
    if novos:
        partes.append(f"{novos} novo{'s' if novos != 1 else ''}")
    if not partes:
        return "sem alterações relevantes"
    return " · ".join(partes)


def calcular_postura(
    user_id: int,
    projeto_id: str | None,
    carregar_todos: Callable[[int, str | None], list[dict]],
) -> dict:
    """
    carregar_todos(user_id, projeto_id) → lista de relatórios concluídos,
    ordenados do mais recente ao mais antigo.
    """
    chave = (user_id, projeto_id or "")
    cached = _cache_get(chave)
    if cached is not None:
        return cached

    relatorios = carregar_todos(user_id, projeto_id)
    # só concluídos
    relatorios = [r for r in relatorios if r.get("status") == "concluido"]

    if not relatorios:
        vazio = {
            "phantom_score_atual": None,
            "delta_ultimo_scan": None,
            "media_historica": {"valor": None, "base": "ultimos 10 scans"},
            "findings_abertos": {"total": 0, "alta": 0, "media": 0, "baixa": 0},
            "situacao_geral": {"score_inicial": None, "score_atual": None, "delta_total": None},
            "historico": [],
            "recorrentes": [],
            "criptografia": {
                "legado": {"count": 0, "exemplos": []},
                "funcional": {"count": 0, "exemplos": []},
                "padrao_ouro": {"count": 0, "exemplos": []},
            },
        }
        _cache_set(chave, vazio)
        return vazio

    scores = []
    for r in relatorios:
        s = _score_do_relatorio(r)
        scores.append(s)

    score_atual = scores[0]
    score_ant = scores[1] if len(scores) > 1 else None
    delta = None
    if score_atual is not None and score_ant is not None:
        delta = round(score_atual - score_ant, 1)

    ultimos_10 = scores[:10]
    validos = [s for s in ultimos_10 if s is not None]
    media = round(sum(validos) / len(validos), 1) if validos else None

    score_inicial = None
    for s in reversed(scores):
        if s is not None:
            score_inicial = s
            break
    delta_total = None
    if score_atual is not None and score_inicial is not None:
        delta_total = round(score_atual - score_inicial, 1)

    historico = []
    for i, rel in enumerate(relatorios[:10]):
        sc = scores[i]
        sc_ant = scores[i + 1] if i + 1 < len(scores) else None
        d = None
        if sc is not None and sc_ant is not None:
            d = round(sc - sc_ant, 1)
        historico.append({
            "protocolo": rel.get("protocolo"),
            "data": rel.get("corrigido_em") or rel.get("processado_em") or rel.get("analisado_em"),
            "phantom_score": sc,
            "delta": d,
            "total_findings": rel.get("total_encontrado") or len(rel.get("vulnerabilidades") or []),
            "alteracoes": _resumo_alteracoes(rel, relatorios[i + 1] if i + 1 < len(relatorios) else None),
            "status": rel.get("status", "concluido"),
            "repositorio": rel.get("repositorio"),
        })

    resultado = {
        "phantom_score_atual": score_atual,
        "delta_ultimo_scan": delta,
        "media_historica": {"valor": media, "base": "ultimos 10 scans"},
        "findings_abertos": _contagem_severidade(relatorios[0]),
        "situacao_geral": {
            "score_inicial": score_inicial,
            "score_atual": score_atual,
            "delta_total": delta_total,
        },
        "historico": historico,
        "recorrentes": _recorrentes(relatorios),
        "criptografia": _agregar_criptografia(relatorios[0]),
    }
    _cache_set(chave, resultado)
    return resultado
