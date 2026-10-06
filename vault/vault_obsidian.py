# PhantomFix — Copyright (C) 2025–2026 Rafael Pedro, Bernardo Coroa,
   # Giovanna Esmelardi, Gustavo Enrique
   # SPDX-License-Identifier: GPL-3.0-or-later
   # Licenciado sob a GNU GPL v3. Veja LICENSE.md na raiz do repositório.

"""
PhantomFix — Vault Obsidian (Unificado)
Versão: 2.1.1

Vault por repositório — acumula scans ao longo do tempo.
Cada scan novo adiciona/atualiza notas sem apagar o histórico.

Mudanças v2.1.1:
- Notas de finding exibem PhantomScore com tabela de componentes auditável
  (tabela Markdown real — sem fence de código, pra renderizar no Obsidian)
- Reachability exibida por finding
- Badges de correlação cross-origem
- Bloco de correlação com findings absorvidos e pares de ataque
- Índice lista componentes/endpoints/dados acumulados do vault, não só do scan atual

Estrutura:
  vaults/<slug_repo>/
    _index.md
    findings/
    componentes/
    endpoints/
    dados-sensiveis/
    criptografia/
    scans/
"""

import hashlib
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

CRIPTO_LEGADO = {"md5", "sha1", "des", "3des", "rc4", "rc2", "blowfish", "md4", "ripemd", "rsa512", "rsa1024"}
CRIPTO_OURO   = {"kyber", "dilithium", "falcon", "sphincs", "ntru", "mceliece"}

SEVERIDADE_ORDEM = {"ERROR": 0, "WARNING": 1, "INFO": 2, "DESCONHECIDA": 3}

ORIGENS_ENDPOINT = {"zap", "nuclei", "spectral"}
ORIGENS_SEGREDO  = {"gitleaks", "trufflehog"}
ORIGENS_DEP      = {"trivy", "grype", "syft"}

LABEL_CORRELACAO = {
    "merge_secrets_cross_origem":        "Merge — mesmo segredo confirmado por scanners diferentes",
    "merge_sast_mesma_linha":            "Merge — múltiplas regras SAST na mesma linha de código",
    "credencial_em_endpoint_vulneravel": "Par de ataque — credencial exposta em endpoint vulnerável",
}


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _slug(texto: str) -> str:
    s = texto.lower().strip()
    s = re.sub(r"[^\w\s\-]", "", s)
    s = re.sub(r"[\s_]+", "-", s)
    return s[:80] or "sem-nome"


def _finding_hash(vuln: dict) -> str:
    chave = f"{vuln.get('origem','')}|{vuln.get('tipo','')}|{vuln.get('arquivo','')}|{vuln.get('linha',0)}"
    return hashlib.sha1(chave.encode()).hexdigest()[:12]


def _sev_emoji(sev: str) -> str:
    return {"ERROR": "🔴", "WARNING": "🟡", "INFO": "🔵"}.get(sev, "⚪")


def _score_bar(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜ N/A"
    filled = round(s)
    return "🟥" * min(filled, 10) + "⬜" * (10 - min(filled, 10)) + f" {s:.1f}/10"


def _agora() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _escrever(caminho: Path, conteudo: str):
    caminho.parent.mkdir(parents=True, exist_ok=True)
    caminho.write_text(conteudo, encoding="utf-8")


def _ler_indice_existente(vault_dir: Path) -> dict[str, str]:
    indice_path = vault_dir / ".finding_index.json"
    if indice_path.exists():
        try:
            return json.loads(indice_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _salvar_indice(vault_dir: Path, indice: dict[str, str]):
    (vault_dir / ".finding_index.json").write_text(
        json.dumps(indice, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _slug_repo(repositorio: str) -> str:
    nome = repositorio.split("/")[-1] if "/" in repositorio else repositorio
    return _slug(nome) or "repo"


def _fmt_val(val) -> str:
    if val is None or val == "":
        return "—"
    try:
        f = float(val)
        return f"{f:.2f}" if f != int(f) else str(int(f))
    except (TypeError, ValueError):
        return str(val)


def _stems(pasta: Path) -> list[str]:
    if not pasta.exists():
        return []
    return sorted(p.stem for p in pasta.glob("*.md"))


# ══════════════════════════════════════════════════════════════════════════════
# DETECÇÃO DE CRIPTOGRAFIA
# ══════════════════════════════════════════════════════════════════════════════

def _detectar_algoritmos(vulnerabilidades: list[dict]) -> dict[str, dict]:
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
            vuln.get("descricao", ""), vuln.get("trecho_do_codigo", ""),
            vuln.get("tipo", ""), vuln.get("justificativa", ""),
        ]).lower()
        for m in PADROES.finditer(texto):
            nome = re.sub(r"[-_]", "", m.group(0).lower())
            nome = re.sub(r"tripledes", "3des", nome)
            if nome not in encontrados:
                if any(l in nome for l in CRIPTO_LEGADO):
                    semaforo = "🔴 Legado"
                elif any(g in nome for g in CRIPTO_OURO):
                    semaforo = "🟢 Padrão Ouro (pós-quântico)"
                else:
                    semaforo = "🟡 Funcional"
                encontrados[nome] = {"semaforo": semaforo, "ocorrencias": []}
            encontrados[nome]["ocorrencias"].append({
                "id": vuln.get("id", ""), "arquivo": vuln.get("arquivo", ""),
            })
    return encontrados


# ══════════════════════════════════════════════════════════════════════════════
# NOTAS
# ══════════════════════════════════════════════════════════════════════════════

def _nota_finding(vuln: dict, protocolo: str, fhash: str, primeiro_scan: str) -> str:
    vid     = vuln.get("id", "sem-id")
    origem  = vuln.get("origem", "desconhecida")
    arquivo = vuln.get("arquivo", "—")
    linha   = vuln.get("linha", 0)
    tipo    = vuln.get("tipo", "—")
    sev     = vuln.get("severidade", "DESCONHECIDA")
    score   = vuln.get("score", None)
    desc    = vuln.get("descricao", "—")
    just    = vuln.get("justificativa", "—")
    cat     = vuln.get("categoria", "—")
    rec     = vuln.get("recomendacao", "—")
    trecho  = vuln.get("trecho_do_codigo", "")
    cve     = vuln.get("cve_id", "")
    pkg     = vuln.get("pkg_name", "")
    tags    = vuln.get("tags_correlacao", [])
    correcao = vuln.get("correcao", "")
    explic  = vuln.get("explicacao", "")
    status  = vuln.get("status_usuario", "aberto")

    phantom_score = vuln.get("phantom_score", None)
    reachability  = vuln.get("reachability", None)
    componentes   = vuln.get("phantom_componentes") or {}

    correlacao_rel   = vuln.get("correlacao_relacao", "")
    correlacao_ids   = vuln.get("correlacao_ids") or []
    correlacao_par   = vuln.get("correlacao_par_ids") or []
    tipos_detectados = vuln.get("tipos_detectados") or []

    badges = ""
    if "confirmado_por_multiplas_ferramentas" in tags:
        badges += " `✅ multi-tool`"
    if "confirmado_em_uso" in tags:
        badges += " `📦 em uso`"
    if cve:
        badges += f" `{cve}`"
    if vuln.get("verified"):
        badges += " `⚡ secret verificado`"
    if correlacao_rel == "merge_secrets_cross_origem":
        badges += " `🔗 confirmado cross-scanner`"
    if correlacao_rel == "merge_sast_mesma_linha":
        badges += " `🔗 multi-regra mesma linha`"
    if correlacao_rel == "credencial_em_endpoint_vulneravel":
        badges += " `⚠️ credencial+injection`"

    ferramentas_conf = vuln.get("ferramentas_confirmaram", 1)
    origens_conf = vuln.get("origens_confirmadas") or [origem]
    if ferramentas_conf and int(ferramentas_conf) > 1:
        badges += f" `🛡️ {ferramentas_conf} ferramentas`"

    score_display = phantom_score if phantom_score is not None else score

    if phantom_score is not None and componentes:
        cvss_c  = componentes.get("cvss", {})
        epss_c  = componentes.get("epss", {})
        kev_c   = componentes.get("kev", {})
        reach_c = componentes.get("reachability", {})
        tabela_componentes = f"""
| Componente   | Valor                            | Peso | Fonte                        |
| ------------ | -------------------------------- | ---- | ---------------------------- |
| CVSS         | {_fmt_val(cvss_c.get('valor'))}  | 40%  | `{cvss_c.get('fonte', '—')}` |
| EPSS         | {_fmt_val(epss_c.get('valor'))}  | 20%  | `{epss_c.get('fonte', '—')}` |
| KEV          | {_fmt_val(kev_c.get('valor'))}   | 15%  | `{kev_c.get('fonte', '—')}`  |
| Reachability | {_fmt_val(reach_c.get('valor'))} | 25%  | `grafo_networkx`             |

**Score original do scanner/Analyser:** {_fmt_val(score)}
**Reachability:** {f"{float(reachability):.2f}" if reachability is not None else "—"}
"""
    else:
        tabela_componentes = f"\n**Score original do scanner/Analyser:** {_fmt_val(score)}\n"

    bloco_correlacao = ""
    if correlacao_rel:
        label = LABEL_CORRELACAO.get(correlacao_rel, correlacao_rel)
        abs_links = ", ".join(f"[[{i}]]" for i in correlacao_ids) if correlacao_ids else "—"
        par_links = ", ".join(f"[[{i}]]" for i in correlacao_par) if correlacao_par else "—"
        tipos_str = ", ".join(f"`{t}`" for t in tipos_detectados) if tipos_detectados else "—"

        bloco_correlacao = f"""
## 🔗 Correlação Cross-Scanner

**Tipo:** {label}
"""
        if correlacao_ids:
            bloco_correlacao += f"""
**Findings absorvidos:** {abs_links}
**Ferramentas que confirmaram:** {", ".join(f"`{o}`" for o in origens_conf)}
"""
        if tipos_detectados:
            bloco_correlacao += f"""
**Tipos fundidos:** {tipos_str}
"""
        if correlacao_par:
            bloco_correlacao += f"""
**Par de ataque:** {par_links}

> ⚠️ Este finding e seu par ocorrem no mesmo arquivo. Um atacante que explora um tem acesso imediato ao outro.
"""

    patch_bloco = ""
    if correcao and correcao not in ("Ghost não disponível", "Correção indisponível", ""):
        conf = vuln.get("confianca")
        conf_txt = f" (confiança: {conf:.0%})" if conf is not None else ""
        patch_bloco = (
            f"\n## 🛠 Patch — Ghost{conf_txt}\n\n```\n{correcao}\n```\n\n"
            f"**Explicação:** {explic}\n"
        )
        if vuln.get("diff"):
            patch_bloco += f"\n**Diff:** {vuln['diff']}\n"

    link_comp = f"\n- **Componente:** [[{_slug(pkg)}]]" if pkg else ""
    status_fmt = {
        "aberto": "🟠 Aberto",
        "corrigido": "✅ Corrigido",
        "falso_positivo": "🚫 Falso Positivo",
    }.get(status, "🟠 Aberto")

    trecho_bloco = ""
    if trecho and trecho != "[REDACTED — segredo nunca armazenado]":
        trecho_bloco = f"\n## Trecho de Código\n\n```\n{trecho}\n```\n"

    return f"""---
tags: [finding, {origem}, {sev.lower()}, {_slug(tipo)}]
hash: {fhash}
primeiro_scan: {primeiro_scan}
ultimo_scan: {protocolo}
status: {status}
phantom_score: {_fmt_val(phantom_score)}
reachability: {_fmt_val(reachability)}
---

# {_sev_emoji(sev)} [{vid}] {tipo}

**Ferramenta:** `{origem}` · **Status:** {status_fmt}
{badges}

## Localização
- **Arquivo:** `{arquivo}`{f" · **Linha:** {linha}" if linha else ""}
{link_comp}

## PhantomScore
{_score_bar(score_display)}
{tabela_componentes}
## Descrição
{desc}

## Análise IA
**Categoria:** {cat}

**Justificativa:** {just}

## Recomendação
{rec}
{trecho_bloco}{patch_bloco}{bloco_correlacao}
## Histórico de Scans
- Primeiro detectado: [[{primeiro_scan}]]
- Último scan: [[{protocolo}]]

---
*Atualizado automaticamente pelo PhantomFix em {_agora()}*
"""


def _nota_componente(pkg_name: str, findings_do_pkg: list[dict]) -> str:
    cves  = sorted({v.get("cve_id", "") for v in findings_do_pkg if v.get("cve_id")})
    sevs  = [v.get("severidade", "INFO") for v in findings_do_pkg]
    pior  = min(sevs, key=lambda s: SEVERIDADE_ORDEM.get(s, 99))
    desc0 = findings_do_pkg[0].get("descricao", "") if findings_do_pkg else ""
    m_ver = re.search(r"(\d+[\.\d]+)", desc0)
    ver   = m_ver.group(1) if m_ver else "—"

    links = "\n".join(
        f"- [[{v.get('id','?')}]] — {v.get('tipo','')} ({v.get('severidade','')})"
        for v in findings_do_pkg
    )
    cves_str = "\n".join(f"- `{c}`" for c in cves) if cves else "- Nenhum CVE registrado"

    return f"""---
tags: [componente, dependencia-vulneravel]
---

# 📦 {pkg_name}

**Severidade máxima:** {_sev_emoji(pior)} {pior}
**Versão instalada:** `{ver}`
**Total de findings:** {len(findings_do_pkg)}

## CVEs Associados
{cves_str}

## Findings que afetam este componente
{links}

---
*Atualizado pelo PhantomFix em {_agora()}*
"""


def _nota_endpoint(url: str, findings: list[dict]) -> str:
    sevs = [v.get("severidade", "INFO") for v in findings]
    pior = min(sevs, key=lambda s: SEVERIDADE_ORDEM.get(s, 99))
    sensivel_kw = re.compile(
        r"\b(cpf|senha|password|token|api.?key|secret|email|phone|credit.?card|pii|personal)\b",
        re.IGNORECASE,
    )
    dados = set()
    for v in findings:
        for m in sensivel_kw.finditer(v.get("descricao", "") + " " + v.get("tipo", "")):
            dados.add(m.group(0).lower())

    links = "\n".join(
        f"- [[{v.get('id','?')}]] — {v.get('tipo','')} ({v.get('severidade','')})"
        for v in findings
    )
    dados_str = "\n".join(f"- `{d}`" for d in sorted(dados)) if dados else "- Nenhum identificado"

    return f"""---
tags: [endpoint, dast]
---

# 🌐 {url}

**Severidade máxima:** {_sev_emoji(pior)} {pior}
**Findings:** {len(findings)}

## Dados Sensíveis Potencialmente Expostos
{dados_str}

## Findings neste endpoint
{links}

---
*Atualizado pelo PhantomFix em {_agora()}*
"""


def _nota_dado_sensivel(tipo_seg: str, findings: list[dict]) -> str:
    verificados = [v for v in findings if v.get("verified")]
    regs = []
    t = tipo_seg.lower()
    if any(k in t for k in ["cpf", "email", "phone", "personal", "pii"]):
        regs.append("LGPD (Lei 13.709/2018)")
    if any(k in t for k in ["card", "cvv", "pan", "credit"]):
        regs.append("PCI-DSS")
    if not regs:
        regs.append("—")

    cat = (
        "🔑 Credencial"
        if any(k in t for k in ["key", "token", "secret", "password", "senha", "apikey"])
        else "📋 Dado Pessoal"
    )
    links = "\n".join(
        f"- [[{v.get('id','?')}]] — `{v.get('arquivo','')}` "
        f"{'⚡ ATIVO' if v.get('verified') else '⚠ não verificado'}"
        for v in findings
    )

    return f"""---
tags: [dado-sensivel, segredo]
---

# 🔐 {tipo_seg}

**Categoria:** {cat}
**Ocorrências:** {len(findings)} ({len(verificados)} ativas)

## Regulações Aplicáveis
{chr(10).join(f"- {r}" for r in regs)}

## Findings
{links}

---
*Atualizado pelo PhantomFix em {_agora()}*
"""


def _nota_criptografia(nome: str, info: dict) -> str:
    semaforo = info["semaforo"]
    ocorrs   = info["ocorrencias"]
    links = "\n".join(
        f"- [[{o['id']}]] — `{o['arquivo']}`"
        for o in ocorrs if o.get("id")
    ) or "- Nenhum finding direto"

    conselho = {
        "🔴 Legado":                     "⚠️ **Ação imediata.** Substitua por SHA-256, AES-256, bcrypt ou argon2.",
        "🟡 Funcional":                  "✅ Seguro atualmente. Monitore o cenário pós-quântico.",
        "🟢 Padrão Ouro (pós-quântico)": "🏆 Resistente a ataques quânticos. Excelente escolha.",
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
*Atualizado pelo PhantomFix em {_agora()}*
"""


def _nota_scan(resultado: dict, protocolo: str, total_vault: int) -> str:
    vulns  = resultado.get("vulnerabilidades", [])
    repo   = resultado.get("repositorio", "—")
    data   = (resultado.get("analisado_em") or resultado.get("processado_em") or "")[:10]
    total  = resultado.get("total_encontrado", len(vulns))
    status = resultado.get("status", "—")
    grafo  = resultado.get("grafo") or {}

    por_sev: dict[str, int] = {}
    for v in vulns:
        s = v.get("severidade", "DESCONHECIDA")
        por_sev[s] = por_sev.get(s, 0) + 1

    scores: list[float] = []
    usa_phantom = False
    for v in vulns:
        ps = v.get("phantom_score")
        s  = v.get("score")
        val = ps if ps is not None else s
        if ps is not None:
            usa_phantom = True
        if val not in (None, "", "N/A"):
            try:
                scores.append(float(val))
            except (TypeError, ValueError):
                pass

    score_str   = f"{sum(scores)/len(scores):.1f}/10" if scores else "N/A"
    score_label = "PhantomScore médio" if usa_phantom else "Score médio"

    origens = sorted({v.get("origem", "?") for v in vulns})
    origens_str = ", ".join(f"`{o}`" for o in origens) or "—"

    n_merge = sum(1 for v in vulns if str(v.get("correlacao_relacao", "")).startswith("merge_"))
    n_pares = sum(
        1 for v in vulns
        if v.get("correlacao_relacao") == "credencial_em_endpoint_vulneravel"
    ) // 2

    top5 = sorted(
        [v for v in vulns if v.get("phantom_score") is not None or v.get("score") not in (None, "", "N/A")],
        key=lambda v: float(v.get("phantom_score") if v.get("phantom_score") is not None else v.get("score") or 0),
        reverse=True,
    )[:5]
    top5_str = "\n".join(
        f"- [[{v.get('id','?')}]] {v.get('tipo','?')} — "
        f"PhantomScore {v.get('phantom_score', v.get('score','?'))}"
        for v in top5
    ) or "- Nenhum com score"

    todos = "\n".join(
        f"- [[{v.get('id','?')}]] {_sev_emoji(v.get('severidade',''))} "
        f"{v.get('tipo','?')} `{v.get('arquivo','')}`"
        for v in sorted(vulns, key=lambda v: SEVERIDADE_ORDEM.get(v.get("severidade", ""), 99))
    ) or "- Nenhum finding"

    caminhos = grafo.get("caminhos_ataque", "—")

    return f"""---
tags: [scan, resumo]
protocolo: {protocolo}
data: {data}
repositorio: {repo}
---

# 📊 Scan — {protocolo}

**Repositório:** `{repo}`
**Data:** {data}
**Status:** {status}
**Ferramentas:** {origens_str}

## Resumo deste scan

| Métrica                  | Valor                       |
| ------------------------ | --------------------------- |
| Findings neste scan      | {total}                     |
| 🔴 ERROR                 | {por_sev.get('ERROR', 0)}   |
| 🟡 WARNING               | {por_sev.get('WARNING', 0)} |
| 🔵 INFO                  | {por_sev.get('INFO', 0)}    |
| {score_label}            | {score_str}                 |
| Correlações (merge)      | {n_merge}                   |
| Pares de ataque          | {n_pares}                   |
| Caminhos no grafo        | {caminhos}                  |
| Total acumulado no vault | {total_vault}               |

## Top 5 por PhantomScore
{top5_str}

## Todos os Findings deste scan
{todos}

---
*Gerado automaticamente pelo PhantomFix em {_agora()}*
"""


def _nota_index(
    slug: str,
    scans: list[str],
    total_findings: int,
    por_sev: dict,
    componentes: list,
    endpoints: list,
    dados_sens: list,
    algos: dict,
) -> str:
    links_scans  = "\n".join(f"- [[scans/{s}]]" for s in reversed(scans)) or "- Nenhum scan"
    links_comp   = "\n".join(f"- [[componentes/{_slug(c)}]]" for c in componentes) or "- Nenhum"
    links_end    = "\n".join(f"- [[endpoints/{_slug(u)}]]" for u in endpoints) or "- Nenhum"
    links_ds     = "\n".join(f"- [[dados-sensiveis/{_slug(t)}]]" for t in dados_sens) or "- Nenhum"
    links_cripto = "\n".join(
        f"- [[criptografia/{_slug(a)}]] — {info['semaforo']}"
        for a, info in algos.items()
    ) or "- Nenhum"

    return f"""---
tags: [index, vault]
repositorio: {slug}
ultimo_scan: {scans[-1] if scans else "—"}
---

# 👻 PhantomFix Vault — {slug}

> Vault unificado. Use o **Graph View** do Obsidian para visualizar conexões entre findings, scans e componentes.

## Postura Acumulada

|                          |                  |
| ------------------------ | ---------------- |
| Total de findings únicos | {total_findings} |
| 🔴 Críticos              | {por_sev.get('ERROR', 0)} |
| 🟡 Avisos                | {por_sev.get('WARNING', 0)} |
| 🔵 Informativos          | {por_sev.get('INFO', 0)} |
| Scans realizados         | {len(scans)}     |

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
# PONTO DE ENTRADA
# ══════════════════════════════════════════════════════════════════════════════

def gerar_vault(
    user_id: int,
    protocolo: str,
    resultado: dict,
    pasta_base: Path,
    resultado_ant: dict | None = None,
    scans_anteriores: list[str] | None = None,
) -> Path:
    """
    Atualiza o vault unificado do repositório com os findings do scan atual.

    O vault fica em pasta_base/../../vaults/<slug_repo>/ e é compartilhado entre scans.
    Returns: Path para o vault-<slug_repo>.zip atualizado.
    """
    vulns       = resultado.get("vulnerabilidades", [])
    repositorio = resultado.get("repositorio", "repositorio")
    slug        = _slug_repo(repositorio)

    vault_dir = pasta_base.parent.parent / "vaults" / slug
    vault_dir.mkdir(parents=True, exist_ok=True)

    indice = _ler_indice_existente(vault_dir)

    scans_dir = vault_dir / "scans"
    scans_dir.mkdir(exist_ok=True)
    scans_existentes = sorted(f.stem for f in scans_dir.glob("*.md"))

    print(f"[vault] Vault unificado: {vault_dir}")
    print(f"[vault] Scans anteriores no vault: {len(scans_existentes)}")
    print(f"[vault] Findings já indexados: {len(indice)}")
    print(f"[vault] Processando {len(vulns)} findings do scan atual...")

    novos = 0
    atualizados = 0

    # ── 1. Findings ───────────────────────────────────────────────────────────
    for vuln in vulns:
        fhash = _finding_hash(vuln)

        if fhash in indice:
            nome_arq  = indice[fhash]
            nota_path = vault_dir / "findings" / f"{nome_arq}.md"
            primeiro_scan = protocolo
            if nota_path.exists():
                conteudo_ant = nota_path.read_text(encoding="utf-8")
                m = re.search(r"^primeiro_scan:\s*(\S+)", conteudo_ant, re.MULTILINE)
                if m:
                    primeiro_scan = m.group(1)
            _escrever(nota_path, _nota_finding(vuln, protocolo, fhash, primeiro_scan))
            atualizados += 1
        else:
            vid      = vuln.get("id", f"finding-{fhash}")
            nome_arq = f"{vid}-{fhash}"
            indice[fhash] = nome_arq
            _escrever(
                vault_dir / "findings" / f"{nome_arq}.md",
                _nota_finding(vuln, protocolo, fhash, protocolo),
            )
            novos += 1

    print(f"[vault] Findings: {novos} novos, {atualizados} atualizados")

    # ── 2. Componentes ────────────────────────────────────────────────────────
    por_pacote: dict[str, list[dict]] = {}
    for v in vulns:
        pkg = v.get("pkg_name", "")
        if pkg and v.get("origem") in ORIGENS_DEP:
            por_pacote.setdefault(pkg, []).append(v)
    for pkg, fs in por_pacote.items():
        _escrever(vault_dir / "componentes" / f"{_slug(pkg)}.md", _nota_componente(pkg, fs))

    # ── 3. Endpoints ──────────────────────────────────────────────────────────
    por_endpoint: dict[str, list[dict]] = {}
    for v in vulns:
        if v.get("origem") in ORIGENS_ENDPOINT:
            url = v.get("arquivo", v.get("url", "endpoint-desconhecido"))
            por_endpoint.setdefault(url, []).append(v)
    for url, fs in por_endpoint.items():
        _escrever(vault_dir / "endpoints" / f"{_slug(url)}.md", _nota_endpoint(url, fs))

    # ── 4. Dados sensíveis ────────────────────────────────────────────────────
    por_segredo: dict[str, list[dict]] = {}
    for v in vulns:
        if v.get("origem") in ORIGENS_SEGREDO:
            por_segredo.setdefault(v.get("tipo", "segredo"), []).append(v)
    for tipo_seg, fs in por_segredo.items():
        _escrever(
            vault_dir / "dados-sensiveis" / f"{_slug(tipo_seg)}.md",
            _nota_dado_sensivel(tipo_seg, fs),
        )

    # ── 5. Criptografia ───────────────────────────────────────────────────────
    cripto_dir = vault_dir / "criptografia"
    cripto_dir.mkdir(exist_ok=True)

    algos_novos = _detectar_algoritmos(vulns)
    for nome, info in algos_novos.items():
        nota_path = cripto_dir / f"{_slug(nome)}.md"
        if nota_path.exists():
            conteudo_ant = nota_path.read_text(encoding="utf-8")
            m = re.search(r"\*\*Detecções:\*\* (\d+)", conteudo_ant)
            total_det = int(m.group(1)) + len(info["ocorrencias"]) if m else len(info["ocorrencias"])
            nota = _nota_criptografia(nome, {"semaforo": info["semaforo"], "ocorrencias": info["ocorrencias"]})
            nota = nota.replace(
                f"**Detecções:** {len(info['ocorrencias'])}",
                f"**Detecções:** {total_det}",
            )
            _escrever(nota_path, nota)
        else:
            _escrever(nota_path, _nota_criptografia(nome, info))

    # Semáforo acumulado para o índice (notas já em disco + deste scan)
    algos_index: dict[str, dict] = {}
    for nota in cripto_dir.glob("*.md"):
        texto = nota.read_text(encoding="utf-8")
        m = re.search(r"\*\*Semáforo:\*\* (.+)", texto)
        algos_index[nota.stem] = {"semaforo": m.group(1).strip() if m else "—", "ocorrencias": []}

    # ── 6. Nota do scan atual ─────────────────────────────────────────────────
    por_sev_vault: dict[str, int] = {}
    for f_path in (vault_dir / "findings").glob("*.md"):
        conteudo = f_path.read_text(encoding="utf-8")
        m = re.search(r"^tags:.*\[(.*)\]", conteudo, re.MULTILINE)
        if m:
            tags_str = m.group(1)
            for sev in ["error", "warning", "info"]:
                if sev in tags_str:
                    por_sev_vault[sev.upper()] = por_sev_vault.get(sev.upper(), 0) + 1
                    break

    _escrever(
        vault_dir / "scans" / f"{protocolo}.md",
        _nota_scan(resultado, protocolo, len(indice)),
    )

    # ── 7. Índice ─────────────────────────────────────────────────────────────
    _salvar_indice(vault_dir, indice)

    scans_atualizados = scans_existentes.copy()
    if protocolo not in scans_atualizados:
        scans_atualizados.append(protocolo)

    _escrever(
        vault_dir / "_index.md",
        _nota_index(
            slug,
            scans_atualizados,
            len(indice),
            por_sev_vault,
            _stems(vault_dir / "componentes") or list(por_pacote.keys()),
            _stems(vault_dir / "endpoints") or list(por_endpoint.keys()),
            _stems(vault_dir / "dados-sensiveis") or list(por_segredo.keys()),
            algos_index or algos_novos,
        ),
    )

    # ── 8. Empacota ───────────────────────────────────────────────────────────
    zip_path = vault_dir.parent / f"vault-{slug}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for arquivo in sorted(vault_dir.rglob("*")):
            if arquivo.is_file() and arquivo.name != ".finding_index.json":
                zf.write(arquivo, arquivo.relative_to(vault_dir))

    n_notas = sum(1 for _ in vault_dir.rglob("*.md"))
    print(f"[vault] ✓ {n_notas} notas no vault ({novos} novos findings, {atualizados} atualizados)")
    print(f"[vault] ✓ {len(scans_atualizados)} scan(s) acumulados → {zip_path}")

    return zip_path
