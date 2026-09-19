"""
PhantomFix — Vault Obsidian
Versão: 1.0.0
Autor: Rafael Pedro

Descrição:
Gera o Vault Obsidian a partir do resultado de um scan concluído.
Produz notas interligadas via [[links]] para que o Graph View do Obsidian
monte as arestas corretamente. Cada scan acumula notas sem sobrescrever
o histórico anterior.

Estrutura gerada:
  vault/<user_id>/<protocolo>/
    findings/          — uma nota por vulnerabilidade
    componentes/       — dependências e pacotes vulneráveis
    endpoints/         — endpoints expostos (findings de ZAP/Nuclei)
    dados-sensiveis/   — segredos e dados regulados expostos
    criptografia/      — algoritmos detectados com semáforo
    scans/             — resumo do scan com delta em relação ao anterior
    _index.md          — índice geral do vault

Uso (pelo Core, dentro do pipeline_completo):
    from vault.vault_obsidian import gerar_vault
    caminho_zip = gerar_vault(user_id, protocolo, resultado, pasta_base)
    # caminho_zip é um Path para o .zip pronto para download
"""

import json
import os
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Constantes de semáforo de criptografia ────────────────────────────────────
CRIPTO_LEGADO = {
    "md5", "sha1", "des", "3des", "rc4", "rc2", "blowfish",
    "md4", "ripemd", "dsa-512", "rsa-512", "rsa-1024",
}
CRIPTO_FUNCIONAL = {
    "sha256", "sha384", "sha512", "aes", "aes-128", "aes-256",
    "rsa-2048", "rsa-4096", "ecdsa", "ecdh", "chacha20", "pbkdf2",
    "bcrypt", "scrypt", "argon2",
}
CRIPTO_OURO = {
    "kyber", "dilithium", "falcon", "sphincs", "crystals-kyber",
    "crystals-dilithium", "ntru", "mceliece",
}

SEVERIDADE_ORDEM = {"ERROR": 0, "WARNING": 1, "INFO": 2, "DESCONHECIDA": 3}

ORIGENS_ENDPOINT = {"zap", "nuclei", "spectral"}
ORIGENS_SEGREDO  = {"gitleaks", "trufflehog"}
ORIGENS_DEP      = {"trivy", "grype", "syft"}
ORIGENS_IAC      = {"checkov", "hadolint"}


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _slug(texto: str) -> str:
    """Converte texto para slug seguro como nome de arquivo."""
    s = texto.lower().strip()
    s = re.sub(r"[^\w\s\-]", "", s)
    s = re.sub(r"[\s_]+", "-", s)
    return s[:80] or "sem-nome"


def _sev_emoji(severidade: str) -> str:
    return {"ERROR": "🔴", "WARNING": "🟡", "INFO": "🔵"}.get(severidade, "⚪")


def _score_bar(score) -> str:
    """Barra visual de score 0–10."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜ N/A"
    filled = round(s)
    bar = "🟥" * min(filled, 10) + "⬜" * (10 - min(filled, 10))
    return f"{bar} {s:.1f}/10"


def _agora() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _data_curta(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        return iso[:10]
    except Exception:
        return iso


def _escrever(caminho: Path, conteudo: str):
    caminho.parent.mkdir(parents=True, exist_ok=True)
    caminho.write_text(conteudo, encoding="utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# DETECÇÃO DE ALGORITMOS DE CRIPTOGRAFIA
# ══════════════════════════════════════════════════════════════════════════════

def _detectar_algoritmos(vulnerabilidades: list[dict]) -> dict[str, dict]:
    """
    Percorre findings e extrai menções a algoritmos criptográficos.
    Retorna dict: { nome_normalizado: {semaforo, ocorrencias: [{id, arquivo}]} }
    """
    PADROES = re.compile(
        r"\b(md5|sha[\-_]?1|sha[\-_]?256|sha[\-_]?384|sha[\-_]?512|"
        r"des|3des|triple[\-_]?des|rc4|rc2|aes[\-_]?128|aes[\-_]?256|aes|"
        r"rsa[\-_]?512|rsa[\-_]?1024|rsa[\-_]?2048|rsa[\-_]?4096|rsa|"
        r"ecdsa|ecdh|chacha20|blowfish|bcrypt|scrypt|argon2|pbkdf2|"
        r"kyber|dilithium|falcon|sphincs|ntru|mceliece)\b",
        re.IGNORECASE,
    )

    encontrados: dict[str, dict] = {}

    for vuln in vulnerabilidades:
        texto = " ".join([
            vuln.get("descricao", ""),
            vuln.get("trecho_do_codigo", ""),
            vuln.get("tipo", ""),
            vuln.get("justificativa", ""),
        ]).lower()

        for m in PADROES.finditer(texto):
            nome_raw = m.group(0).lower().replace("-", "").replace("_", "")
            # Normaliza para chave consistente
            nome = re.sub(r"tripledes|3des", "3des", nome_raw)
            nome = re.sub(r"sha1$", "sha1", nome)

            if nome not in encontrados:
                if any(l in nome for l in ["md5", "sha1", "des", "3des", "rc4", "rc2", "blowfish", "md4", "rsa512", "rsa1024"]):
                    semaforo = "🔴 Legado"
                elif any(g in nome for g in ["kyber", "dilithium", "falcon", "sphincs", "ntru", "mceliece"]):
                    semaforo = "🟢 Padrão Ouro (pós-quântico)"
                else:
                    semaforo = "🟡 Funcional"

                encontrados[nome] = {"semaforo": semaforo, "ocorrencias": []}

            encontrados[nome]["ocorrencias"].append({
                "id":      vuln.get("id", ""),
                "arquivo": vuln.get("arquivo", ""),
            })

    return encontrados


# ══════════════════════════════════════════════════════════════════════════════
# NOTA: FINDING
# ══════════════════════════════════════════════════════════════════════════════

def _nota_finding(vuln: dict, protocolo: str) -> str:
    vid      = vuln.get("id", "sem-id")
    origem   = vuln.get("origem", "desconhecida")
    arquivo  = vuln.get("arquivo", "—")
    linha    = vuln.get("linha", 0)
    tipo     = vuln.get("tipo", "—")
    sev      = vuln.get("severidade", "DESCONHECIDA")
    score    = vuln.get("score", None)
    desc     = vuln.get("descricao", "—")
    just     = vuln.get("justificativa", "—")
    cat      = vuln.get("categoria", "—")
    rec      = vuln.get("recomendacao", "—")
    trecho   = vuln.get("trecho_do_codigo", "")
    cve      = vuln.get("cve_id", "")
    pkg      = vuln.get("pkg_name", "")
    tags     = vuln.get("tags_correlacao", [])
    correcao = vuln.get("correcao", "")
    explic   = vuln.get("explicacao", "")
    diff     = vuln.get("diff", "")
    conf     = vuln.get("confianca", None)
    verified = vuln.get("verified", None)
    status   = vuln.get("status_usuario", "aberto")   # campo futuro: corrigido/falso-positivo

    # Tags de rastreabilidade
    badges = ""
    if "confirmado_por_multiplas_ferramentas" in tags:
        badges += " `✅ multi-tool`"
    if "confirmado_em_uso" in tags:
        badges += " `📦 em uso`"
    if "confirmado_via_lockfile" in tags:
        badges += " `🔒 lockfile`"
    if cve:
        badges += f" `{cve}`"
    if verified is True:
        badges += " `⚡ secret verificado`"

    # Link para componente (se for dep)
    link_comp = ""
    if pkg:
        link_comp = f"\n- **Componente:** [[{_slug(pkg)}]]"

    # Status
    status_fmt = {
        "aberto":         "🟠 Aberto",
        "corrigido":      "✅ Corrigido",
        "falso_positivo": "🚫 Falso Positivo",
    }.get(status, "🟠 Aberto")

    # Patch do Ghost
    patch_bloco = ""
    if correcao and correcao != "Ghost não disponível":
        conf_txt = f" (confiança: {conf:.0%})" if conf is not None else ""
        patch_bloco = f"""
## 🛠 Patch — Ghost{conf_txt}

```
{correcao}
```

**Explicação:** {explic}
"""
        if diff:
            patch_bloco += f"\n**Diff:** {diff}\n"

    return f"""---
tags: [finding, {origem}, {sev.lower()}, {_slug(tipo)}]
scan: {protocolo}
status: {status}
---

# {_sev_emoji(sev)} [{vid}] {tipo}

**Scan:** [[{protocolo}]] · **Ferramenta:** `{origem}` · **Status:** {status_fmt}
{badges}

## Localização
- **Arquivo:** `{arquivo}`{f" · **Linha:** {linha}" if linha else ""}
{link_comp}

## Score PhantomFix
{_score_bar(score)}

## Descrição
{desc}

## Análise IA
**Categoria:** {cat}

**Justificativa:** {just}

## Recomendação
{rec}
{f"""
## Trecho de Código

```
{trecho}
```
""" if trecho and trecho != "[REDACTED — segredo nunca armazenado]" else ""}
{patch_bloco}
---
*Nota gerada automaticamente pelo PhantomFix em {_agora()}*
"""


# ══════════════════════════════════════════════════════════════════════════════
# NOTA: COMPONENTE / DEPENDÊNCIA
# ══════════════════════════════════════════════════════════════════════════════

def _nota_componente(pkg_name: str, findings_do_pkg: list[dict]) -> str:
    cves   = sorted({v.get("cve_id", "") for v in findings_do_pkg if v.get("cve_id")})
    sevs   = [v.get("severidade", "INFO") for v in findings_do_pkg]
    pior   = min(sevs, key=lambda s: SEVERIDADE_ORDEM.get(s, 99))
    versao = findings_do_pkg[0].get("trecho_do_codigo", "") if findings_do_pkg else ""
    # Tenta extrair versão da descrição
    desc0  = findings_do_pkg[0].get("descricao", "") if findings_do_pkg else ""
    m_ver  = re.search(r"(\d+[\.\d]+)", desc0)
    ver_str = m_ver.group(1) if m_ver else "—"

    links_findings = "\n".join(
        f"- [[{v.get('id', 'sem-id')}]] — {v.get('tipo', '')} ({v.get('severidade', '')})"
        for v in findings_do_pkg
    )
    links_cves = "\n".join(f"- `{c}`" for c in cves) if cves else "- Nenhum CVE registrado"

    return f"""---
tags: [componente, dependencia-vulneravel]
---

# 📦 {pkg_name}

**Severidade máxima:** {_sev_emoji(pior)} {pior}
**Versão instalada:** `{ver_str}`
**Total de findings:** {len(findings_do_pkg)}

## CVEs Associados
{links_cves}

## Findings que afetam este componente
{links_findings}

---
*Nota gerada automaticamente pelo PhantomFix em {_agora()}*
"""


# ══════════════════════════════════════════════════════════════════════════════
# NOTA: ENDPOINT
# ══════════════════════════════════════════════════════════════════════════════

def _nota_endpoint(url: str, findings_do_endpoint: list[dict]) -> str:
    sevs = [v.get("severidade", "INFO") for v in findings_do_endpoint]
    pior = min(sevs, key=lambda s: SEVERIDADE_ORDEM.get(s, 99))

    links_findings = "\n".join(
        f"- [[{v.get('id', 'sem-id')}]] — {v.get('tipo', '')} ({v.get('severidade', '')})"
        for v in findings_do_endpoint
    )

    # Detecta dados sensíveis mencionados nos findings
    sensivel_kw = re.compile(
        r"\b(cpf|senha|password|token|api.?key|secret|email|phone|credit.?card|pii|personal)\b",
        re.IGNORECASE,
    )
    dados_sens = set()
    for v in findings_do_endpoint:
        texto = v.get("descricao", "") + " " + v.get("tipo", "")
        for m in sensivel_kw.finditer(texto):
            dados_sens.add(m.group(0).lower())

    dados_bloco = (
        "\n".join(f"- `{d}`" for d in sorted(dados_sens))
        if dados_sens
        else "- Nenhum dado sensível identificado"
    )

    return f"""---
tags: [endpoint, dast]
---

# 🌐 {url}

**Severidade máxima:** {_sev_emoji(pior)} {pior}
**Findings relacionados:** {len(findings_do_endpoint)}

## Dados Sensíveis Potencialmente Expostos
{dados_bloco}

## Findings neste endpoint
{links_findings}

---
*Nota gerada automaticamente pelo PhantomFix em {_agora()}*
"""


# ══════════════════════════════════════════════════════════════════════════════
# NOTA: DADO SENSÍVEL / SEGREDO
# ══════════════════════════════════════════════════════════════════════════════

def _nota_dado_sensivel(tipo_segredo: str, findings: list[dict]) -> str:
    verificados = [v for v in findings if v.get("verified")]
    links_findings = "\n".join(
        f"- [[{v.get('id', 'sem-id')}]] — `{v.get('arquivo', '')}` "
        f"{'⚡ ATIVO' if v.get('verified') else '⚠ não verificado'}"
        for v in findings
    )

    # Regulações aplicáveis baseadas no tipo
    regs: list[str] = []
    t = tipo_segredo.lower()
    if any(k in t for k in ["cpf", "email", "phone", "personal", "pii", "nome"]):
        regs.append("LGPD (Lei 13.709/2018)")
    if any(k in t for k in ["card", "cvv", "pan", "credit"]):
        regs.append("PCI-DSS")
    if any(k in t for k in ["health", "saude", "medic"]):
        regs.append("LGPD — dados sensíveis (art. 11)")
    if not regs:
        regs.append("—")

    cat = "🔑 Credencial / Segredo de API" if any(
        k in t for k in ["key", "token", "secret", "password", "senha", "apikey"]
    ) else "📋 Dado Pessoal / Regulado"

    return f"""---
tags: [dado-sensivel, segredo]
---

# 🔐 {tipo_segredo}

**Categoria:** {cat}
**Ocorrências:** {len(findings)} ({len(verificados)} verificadas como ativas)

## Regulações Aplicáveis
{chr(10).join(f"- {r}" for r in regs)}

## Findings que expõem este dado
{links_findings}

---
*Nota gerada automaticamente pelo PhantomFix em {_agora()}*
"""


# ══════════════════════════════════════════════════════════════════════════════
# NOTA: ALGORITMO DE CRIPTOGRAFIA
# ══════════════════════════════════════════════════════════════════════════════

def _nota_criptografia(nome: str, info: dict) -> str:
    semaforo = info["semaforo"]
    ocorrs   = info["ocorrencias"]

    links = "\n".join(
        f"- [[{o['id']}]] — `{o['arquivo']}`"
        for o in ocorrs if o.get("id")
    ) or "- Nenhum finding direto"

    conselho = {
        "🔴 Legado": (
            "⚠️ **Ação imediata recomendada.** Este algoritmo é considerado inseguro "
            "e deve ser substituído por alternativas modernas (ex: SHA-256, AES-256, bcrypt/argon2)."
        ),
        "🟡 Funcional": (
            "✅ Seguro para uso atual, mas monitore a evolução do cenário pós-quântico. "
            "Planeje migração futura se o sistema tiver vida útil longa."
        ),
        "🟢 Padrão Ouro (pós-quântico)": (
            "🏆 Resistente a ataques quânticos. Excelente escolha para sistemas de longa duração."
        ),
    }.get(semaforo, "—")

    return f"""---
tags: [criptografia, semaforo]
---

# 🔒 {nome.upper()}

**Semáforo:** {semaforo}
**Detecções:** {len(ocorrs)}

## Avaliação
{conselho}

## Onde foi detectado
{links}

---
*Nota gerada automaticamente pelo PhantomFix em {_agora()}*
"""


# ══════════════════════════════════════════════════════════════════════════════
# NOTA: SCAN (resumo)
# ══════════════════════════════════════════════════════════════════════════════

def _nota_scan(resultado: dict, protocolo: str, scan_anterior: dict | None) -> str:
    vulns    = resultado.get("vulnerabilidades", [])
    repo     = resultado.get("repositorio", "—")
    data     = _data_curta(resultado.get("analisado_em") or resultado.get("processado_em"))
    total    = resultado.get("total_encontrado", len(vulns))
    status   = resultado.get("status", "—")

    # Contagem por severidade
    por_sev: dict[str, int] = {}
    for v in vulns:
        s = v.get("severidade", "DESCONHECIDA")
        por_sev[s] = por_sev.get(s, 0) + 1

    # Score médio
    scores_validos = [float(v["score"]) for v in vulns if v.get("score") not in (None, "", "N/A")]
    score_medio   = sum(scores_validos) / len(scores_validos) if scores_validos else None
    score_str     = f"{score_medio:.1f}/10" if score_medio is not None else "N/A"

    # Delta em relação ao scan anterior
    delta_bloco = ""
    if scan_anterior:
        ant_ids  = {v.get("id") for v in scan_anterior.get("vulnerabilidades", [])}
        cur_ids  = {v.get("id") for v in vulns}
        novos    = cur_ids - ant_ids
        fechados = ant_ids - cur_ids
        recorr   = cur_ids & ant_ids
        delta_bloco = f"""
## Delta em relação ao scan anterior
| | Quantidade |
|---|---|
| 🆕 Novos findings | {len(novos)} |
| ✅ Fechados | {len(fechados)} |
| 🔄 Recorrentes | {len(recorr)} |
"""

    # Origens ativas
    origens_ativas = sorted({v.get("origem", "?") for v in vulns})
    origens_str = ", ".join(f"`{o}`" for o in origens_ativas) if origens_ativas else "—"

    # Top 5 findings por score
    top5 = sorted(
        [v for v in vulns if v.get("score") not in (None, "", "N/A")],
        key=lambda v: float(v.get("score", 0)),
        reverse=True,
    )[:5]
    top5_bloco = "\n".join(
        f"- [[{v.get('id', '?')}]] {v.get('tipo', '?')} — score {v.get('score', '?')}"
        for v in top5
    ) if top5 else "- Nenhum finding com score disponível"

    # Todos os findings
    todos_links = "\n".join(
        f"- [[{v.get('id', '?')}]] {_sev_emoji(v.get('severidade',''))} {v.get('tipo','?')} `{v.get('arquivo','')}`"
        for v in sorted(vulns, key=lambda v: SEVERIDADE_ORDEM.get(v.get("severidade", ""), 99))
    ) or "- Nenhum finding"

    return f"""---
tags: [scan, resumo]
protocolo: {protocolo}
data: {data}
---

# 📊 Scan — {protocolo}

**Repositório:** `{repo}`
**Data:** {data}
**Status:** {status}
**Ferramentas ativas:** {origens_str}

## Resumo
| Métrica | Valor |
|---|---|
| Total de findings | {total} |
| 🔴 ERROR | {por_sev.get('ERROR', 0)} |
| 🟡 WARNING | {por_sev.get('WARNING', 0)} |
| 🔵 INFO | {por_sev.get('INFO', 0)} |
| Score médio | {score_str} |
{delta_bloco}
## Top 5 por Score
{top5_bloco}

## Todos os Findings
{todos_links}

---
*Nota gerada automaticamente pelo PhantomFix em {_agora()}*
"""


# ══════════════════════════════════════════════════════════════════════════════
# ÍNDICE GERAL
# ══════════════════════════════════════════════════════════════════════════════

def _nota_index(
    protocolo: str,
    vulns: list[dict],
    componentes: dict,
    endpoints: dict,
    dados_sens: dict,
    algos: dict,
    scans_anteriores: list[str],
) -> str:
    total_erros  = sum(1 for v in vulns if v.get("severidade") == "ERROR")
    total_warns  = sum(1 for v in vulns if v.get("severidade") == "WARNING")

    links_scans = "\n".join(
        f"- [[scans/{s}]]" for s in [protocolo] + scans_anteriores
    ) or "- Nenhum scan anterior"

    links_comp = "\n".join(
        f"- [[componentes/{_slug(c)}]] — {len(fs)} CVE(s)"
        for c, fs in componentes.items()
    ) or "- Nenhum"

    links_end = "\n".join(
        f"- [[endpoints/{_slug(u)}]]"
        for u in endpoints
    ) or "- Nenhum"

    links_ds = "\n".join(
        f"- [[dados-sensiveis/{_slug(t)}]]"
        for t in dados_sens
    ) or "- Nenhum"

    links_cripto = "\n".join(
        f"- [[criptografia/{_slug(a)}]] — {info['semaforo']}"
        for a, info in algos.items()
    ) or "- Nenhum algoritmo detectado"

    return f"""---
tags: [index, vault]
---

# 👻 PhantomFix Vault — {protocolo}

> Vault gerado automaticamente. Use o Graph View do Obsidian para visualizar as conexões.

## Último Scan
[[scans/{protocolo}]]

**🔴 Críticos:** {total_erros} · **🟡 Avisos:** {total_warns}

## Histórico de Scans
{links_scans}

## Componentes Vulneráveis
{links_comp}

## Endpoints
{links_end}

## Dados Sensíveis
{links_ds}

## Semáforo de Criptografia
{links_cripto}

---
*Vault atualizado em {_agora()}*
"""


# ══════════════════════════════════════════════════════════════════════════════
# PONTO DE ENTRADA PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def gerar_vault(
    user_id:          int,
    protocolo:        str,
    resultado:        dict,
    pasta_base:       Path,
    resultado_ant:    dict | None = None,
    scans_anteriores: list[str] | None = None,
) -> Path:
    """
    Gera todas as notas do vault e empacota em .zip.

    Args:
        user_id:          ID do usuário (para isolar o vault)
        protocolo:        ID único do scan (ex: "abc-123")
        resultado:        dict retornado pelo pipeline_completo (já com Ghost)
        pasta_base:       Path base onde o vault será escrito
                          (ex: RESULTADOS_DIR / str(user_id) / protocolo)
        resultado_ant:    resultado do scan imediatamente anterior (para delta)
        scans_anteriores: lista de protocolos anteriores (para links no índice)

    Returns:
        Path para o arquivo vault-<protocolo>.zip
    """
    scans_anteriores = scans_anteriores or []
    vulns            = resultado.get("vulnerabilidades", [])

    # Pasta raiz do vault deste scan
    vault_dir = pasta_base / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)

    # ── 1. Findings ───────────────────────────────────────────────────────────
    print(f"[vault] Gerando {len(vulns)} notas de finding...")
    for vuln in vulns:
        vid      = vuln.get("id", "sem-id")
        nome_arq = f"{vid}.md"
        conteudo = _nota_finding(vuln, protocolo)
        _escrever(vault_dir / "findings" / nome_arq, conteudo)

    # ── 2. Componentes (dependências vulneráveis) ─────────────────────────────
    print("[vault] Gerando notas de componentes...")
    por_pacote: dict[str, list[dict]] = {}
    for v in vulns:
        pkg = v.get("pkg_name", "")
        if pkg and v.get("origem") in ORIGENS_DEP:
            por_pacote.setdefault(pkg, []).append(v)

    for pkg, findings_pkg in por_pacote.items():
        nome_arq = f"{_slug(pkg)}.md"
        conteudo = _nota_componente(pkg, findings_pkg)
        _escrever(vault_dir / "componentes" / nome_arq, conteudo)

    # ── 3. Endpoints ──────────────────────────────────────────────────────────
    print("[vault] Gerando notas de endpoints...")
    por_endpoint: dict[str, list[dict]] = {}
    for v in vulns:
        if v.get("origem") in ORIGENS_ENDPOINT:
            url = v.get("arquivo", v.get("url", "endpoint-desconhecido"))
            por_endpoint.setdefault(url, []).append(v)

    for url, findings_end in por_endpoint.items():
        nome_arq = f"{_slug(url)}.md"
        conteudo = _nota_endpoint(url, findings_end)
        _escrever(vault_dir / "endpoints" / nome_arq, conteudo)

    # ── 4. Dados sensíveis / segredos ─────────────────────────────────────────
    print("[vault] Gerando notas de dados sensíveis...")
    por_segredo: dict[str, list[dict]] = {}
    for v in vulns:
        if v.get("origem") in ORIGENS_SEGREDO:
            tipo = v.get("tipo", "segredo-desconhecido")
            por_segredo.setdefault(tipo, []).append(v)

    for tipo_seg, findings_seg in por_segredo.items():
        nome_arq = f"{_slug(tipo_seg)}.md"
        conteudo = _nota_dado_sensivel(tipo_seg, findings_seg)
        _escrever(vault_dir / "dados-sensiveis" / nome_arq, conteudo)

    # ── 5. Criptografia ───────────────────────────────────────────────────────
    print("[vault] Detectando algoritmos de criptografia...")
    algos = _detectar_algoritmos(vulns)
    for nome_algo, info_algo in algos.items():
        nome_arq = f"{_slug(nome_algo)}.md"
        conteudo = _nota_criptografia(nome_algo, info_algo)
        _escrever(vault_dir / "criptografia" / nome_arq, conteudo)

    # ── 6. Nota do scan ───────────────────────────────────────────────────────
    print("[vault] Gerando nota do scan...")
    conteudo_scan = _nota_scan(resultado, protocolo, resultado_ant)
    _escrever(vault_dir / "scans" / f"{protocolo}.md", conteudo_scan)

    # ── 7. Índice ─────────────────────────────────────────────────────────────
    print("[vault] Gerando índice...")
    conteudo_index = _nota_index(
        protocolo, vulns,
        por_pacote, por_endpoint, por_segredo, algos,
        scans_anteriores,
    )
    _escrever(vault_dir / "_index.md", conteudo_index)

    # ── 8. Empacota em .zip ───────────────────────────────────────────────────
    print("[vault] Empacotando vault...")
    zip_path = pasta_base / f"vault-{protocolo}.zip"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for arquivo in sorted(vault_dir.rglob("*.md")):
            arcname = arquivo.relative_to(vault_dir)
            zf.write(arquivo, arcname)

    n_notas = sum(1 for _ in vault_dir.rglob("*.md"))
    print(f"[vault] ✓ {n_notas} notas geradas → {zip_path}")

    return zip_path
