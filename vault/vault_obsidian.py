"""
PhantomFix — Vault Obsidian (Unificado)
Versão: 2.0.0

Vault por repositório — acumula scans ao longo do tempo.
Cada scan novo adiciona/atualiza notas sem apagar o histórico.

Estrutura:
  vault/<user_id>/<slug_repo>/
    _index.md
    findings/        — uma nota por finding único (deduplicado por hash)
    componentes/     — dependências vulneráveis
    endpoints/       — endpoints expostos
    dados-sensiveis/ — segredos detectados
    criptografia/    — semáforo de algoritmos
    scans/           — uma nota por execução de scan

Deduplicação:
  Chave de identidade: hash(origem + tipo + arquivo + linha)
  Se o finding já existe, atualiza a nota; se não, cria nova.
  O ID original do finding (vuln-001) é preservado como âncora.
"""

import hashlib
import json
import os
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# ── Semáforo de criptografia ──────────────────────────────────────────────────
CRIPTO_LEGADO = {"md5","sha1","des","3des","rc4","rc2","blowfish","md4","ripemd","rsa512","rsa1024"}
CRIPTO_OURO   = {"kyber","dilithium","falcon","sphincs","ntru","mceliece"}

SEVERIDADE_ORDEM = {"ERROR": 0, "WARNING": 1, "INFO": 2, "DESCONHECIDA": 3}

ORIGENS_ENDPOINT = {"zap", "nuclei", "spectral"}
ORIGENS_SEGREDO  = {"gitleaks", "trufflehog"}
ORIGENS_DEP      = {"trivy", "grype", "syft"}


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _slug(texto: str) -> str:
    s = texto.lower().strip()
    s = re.sub(r"[^\w\s\-]", "", s)
    s = re.sub(r"[\s_]+", "-", s)
    return s[:80] or "sem-nome"


def _finding_hash(vuln: dict) -> str:
    """Chave de identidade de um finding para deduplicação."""
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
    """
    Lê o arquivo de índice interno de findings já escritos.
    Retorna: { finding_hash: nome_arquivo_sem_extensao }
    """
    indice_path = vault_dir / ".finding_index.json"
    if indice_path.exists():
        try:
            return json.loads(indice_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _salvar_indice(vault_dir: Path, indice: dict[str, str]):
    indice_path = vault_dir / ".finding_index.json"
    indice_path.write_text(json.dumps(indice, ensure_ascii=False, indent=2), encoding="utf-8")


def _slug_repo(repositorio: str) -> str:
    """Gera slug estável para o nome do repositório."""
    nome = repositorio.split("/")[-1] if "/" in repositorio else repositorio
    return _slug(nome) or "repo"


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
    status   = vuln.get("status_usuario", "aberto")

    badges = ""
    if "confirmado_por_multiplas_ferramentas" in tags: badges += " `✅ multi-tool`"
    if "confirmado_em_uso" in tags:                    badges += " `📦 em uso`"
    if cve:                                            badges += f" `{cve}`"
    if vuln.get("verified"):                           badges += " `⚡ secret verificado`"

    status_fmt = {"aberto": "🟠 Aberto", "corrigido": "✅ Corrigido",
                  "falso_positivo": "🚫 Falso Positivo"}.get(status, "🟠 Aberto")

    patch_bloco = ""
    if correcao and correcao != "Ghost não disponível":
        conf = vuln.get("confianca")
        conf_txt = f" (confiança: {conf:.0%})" if conf is not None else ""
        patch_bloco = f"\n## 🛠 Patch — Ghost{conf_txt}\n\n```\n{correcao}\n```\n\n**Explicação:** {explic}\n"
        if vuln.get("diff"):
            patch_bloco += f"\n**Diff:** {vuln['diff']}\n"

    link_comp = f"\n- **Componente:** [[{_slug(pkg)}]]" if pkg else ""

    return f"""---
tags: [finding, {origem}, {sev.lower()}, {_slug(tipo)}]
hash: {fhash}
primeiro_scan: {primeiro_scan}
ultimo_scan: {protocolo}
status: {status}
---

# {_sev_emoji(sev)} [{vid}] {tipo}

**Ferramenta:** `{origem}` · **Status:** {status_fmt}
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
{f'''
## Trecho de Código

```
{trecho}
```
''' if trecho and trecho != "[REDACTED — segredo nunca armazenado]" else ""}
{patch_bloco}
## Histórico de Scans
- Primeiro detectado: [[{primeiro_scan}]]
- Último scan: [[{protocolo}]]

---
*Atualizado automaticamente pelo PhantomFix em {_agora()}*
"""


def _nota_componente(pkg_name: str, findings_do_pkg: list[dict]) -> str:
    cves  = sorted({v.get("cve_id","") for v in findings_do_pkg if v.get("cve_id")})
    sevs  = [v.get("severidade","INFO") for v in findings_do_pkg]
    pior  = min(sevs, key=lambda s: SEVERIDADE_ORDEM.get(s, 99))
    desc0 = findings_do_pkg[0].get("descricao","") if findings_do_pkg else ""
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
    sevs = [v.get("severidade","INFO") for v in findings]
    pior = min(sevs, key=lambda s: SEVERIDADE_ORDEM.get(s, 99))
    sensivel_kw = re.compile(
        r"\b(cpf|senha|password|token|api.?key|secret|email|phone|credit.?card|pii|personal)\b",
        re.IGNORECASE,
    )
    dados = set()
    for v in findings:
        for m in sensivel_kw.finditer(v.get("descricao","") + " " + v.get("tipo","")):
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
    if any(k in t for k in ["cpf","email","phone","personal","pii"]): regs.append("LGPD (Lei 13.709/2018)")
    if any(k in t for k in ["card","cvv","pan","credit"]):            regs.append("PCI-DSS")
    if not regs: regs.append("—")

    cat = "🔑 Credencial" if any(k in t for k in ["key","token","secret","password","senha","apikey"]) else "📋 Dado Pessoal"
    links = "\n".join(
        f"- [[{v.get('id','?')}]] — `{v.get('arquivo','')}` {'⚡ ATIVO' if v.get('verified') else '⚠ não verificado'}"
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
        "🔴 Legado":                    "⚠️ **Ação imediata.** Substitua por SHA-256, AES-256, bcrypt ou argon2.",
        "🟡 Funcional":                 "✅ Seguro atualmente. Monitore o cenário pós-quântico.",
        "🟢 Padrão Ouro (pós-quântico)":"🏆 Resistente a ataques quânticos. Excelente escolha.",
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

    por_sev: dict[str, int] = {}
    for v in vulns:
        s = v.get("severidade", "DESCONHECIDA")
        por_sev[s] = por_sev.get(s, 0) + 1

    scores = [float(v["score"]) for v in vulns if v.get("score") not in (None, "", "N/A")]
    score_str = f"{sum(scores)/len(scores):.1f}/10" if scores else "N/A"

    origens = sorted({v.get("origem","?") for v in vulns})
    origens_str = ", ".join(f"`{o}`" for o in origens) or "—"

    top5 = sorted(
        [v for v in vulns if v.get("score") not in (None,"","N/A")],
        key=lambda v: float(v.get("score",0)), reverse=True
    )[:5]
    top5_str = "\n".join(
        f"- [[{v.get('id','?')}]] {v.get('tipo','?')} — score {v.get('score','?')}"
        for v in top5
    ) or "- Nenhum com score"

    todos = "\n".join(
        f"- [[{v.get('id','?')}]] {_sev_emoji(v.get('severidade',''))} {v.get('tipo','?')} `{v.get('arquivo','')}`"
        for v in sorted(vulns, key=lambda v: SEVERIDADE_ORDEM.get(v.get("severidade",""), 99))
    ) or "- Nenhum finding"

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
| Métrica | Valor |
|---|---|
| Findings neste scan | {total} |
| 🔴 ERROR | {por_sev.get('ERROR', 0)} |
| 🟡 WARNING | {por_sev.get('WARNING', 0)} |
| 🔵 INFO | {por_sev.get('INFO', 0)} |
| Score médio | {score_str} |
| Total acumulado no vault | {total_vault} |

## Top 5 por Score
{top5_str}

## Todos os Findings deste scan
{todos}

---
*Gerado automaticamente pelo PhantomFix em {_agora()}*
"""


def _nota_index(slug: str, scans: list[str], total_findings: int,
                por_sev: dict, componentes: list, endpoints: list,
                dados_sens: list, algos: dict) -> str:

    links_scans = "\n".join(f"- [[scans/{s}]]" for s in reversed(scans)) or "- Nenhum scan"
    links_comp  = "\n".join(f"- [[componentes/{_slug(c)}]]" for c in componentes) or "- Nenhum"
    links_end   = "\n".join(f"- [[endpoints/{_slug(u)}]]" for u in endpoints) or "- Nenhum"
    links_ds    = "\n".join(f"- [[dados-sensiveis/{_slug(t)}]]" for t in dados_sens) or "- Nenhum"
    links_cripto= "\n".join(f"- [[criptografia/{_slug(a)}]] — {info['semaforo']}" for a,info in algos.items()) or "- Nenhum"

    return f"""---
tags: [index, vault]
repositorio: {slug}
ultimo_scan: {scans[-1] if scans else "—"}
---

# 👻 PhantomFix Vault — {slug}

> Vault unificado. Use o **Graph View** do Obsidian para visualizar conexões entre findings, scans e componentes.

## Postura Acumulada
| | |
|---|---|
| Total de findings únicos | {total_findings} |
| 🔴 Críticos | {por_sev.get('ERROR', 0)} |
| 🟡 Avisos | {por_sev.get('WARNING', 0)} |
| 🔵 Informativos | {por_sev.get('INFO', 0)} |
| Scans realizados | {len(scans)} |

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
    user_id:          int,
    protocolo:        str,
    resultado:        dict,
    pasta_base:       Path,
    resultado_ant:    dict | None = None,
    scans_anteriores: list[str] | None = None,
) -> Path:
    """
    Atualiza o vault unificado do repositório com os findings do scan atual.

    O vault fica em pasta_base/vault/<slug_repo>/ e é compartilhado entre scans.
    Cada chamada adiciona novas notas e atualiza as existentes.

    Returns: Path para o vault-<slug_repo>.zip atualizado.
    """
    vulns      = resultado.get("vulnerabilidades", [])
    repositorio = resultado.get("repositorio", "repositorio")
    slug        = _slug_repo(repositorio)

    # Pasta do vault unificado (compartilhada entre scans do mesmo repo)
    vault_dir = pasta_base.parent.parent / "vaults" / slug
    vault_dir.mkdir(parents=True, exist_ok=True)

    # Carrega índice de findings já existentes
    indice = _ler_indice_existente(vault_dir)

    # Carrega lista de scans anteriores do próprio vault
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
            # Finding já existe — atualiza preservando o primeiro_scan
            nome_arq  = indice[fhash]
            nota_path = vault_dir / "findings" / f"{nome_arq}.md"
            # Lê o primeiro_scan da nota existente
            primeiro_scan = protocolo
            if nota_path.exists():
                conteudo_ant = nota_path.read_text(encoding="utf-8")
                m = re.search(r"^primeiro_scan:\s*(\S+)", conteudo_ant, re.MULTILINE)
                if m:
                    primeiro_scan = m.group(1)
            conteudo = _nota_finding(vuln, protocolo, fhash, primeiro_scan)
            _escrever(nota_path, conteudo)
            atualizados += 1
        else:
            # Finding novo
            vid      = vuln.get("id", f"finding-{fhash}")
            nome_arq = f"{vid}-{fhash}"
            indice[fhash] = nome_arq
            conteudo = _nota_finding(vuln, protocolo, fhash, protocolo)
            _escrever(vault_dir / "findings" / f"{nome_arq}.md", conteudo)
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
            por_segredo.setdefault(v.get("tipo","segredo"), []).append(v)
    for tipo_seg, fs in por_segredo.items():
        _escrever(vault_dir / "dados-sensiveis" / f"{_slug(tipo_seg)}.md", _nota_dado_sensivel(tipo_seg, fs))

    # ── 5. Criptografia ───────────────────────────────────────────────────────
    # Carrega algoritmos já detectados em scans anteriores
    algos_existentes: dict[str, dict] = {}
    cripto_dir = vault_dir / "criptografia"
    cripto_dir.mkdir(exist_ok=True)

    algos_novos = _detectar_algoritmos(vulns)
    for nome, info in algos_novos.items():
        nota_path = cripto_dir / f"{_slug(nome)}.md"
        if nota_path.exists():
            # Acumula ocorrências
            conteudo_ant = nota_path.read_text(encoding="utf-8")
            m = re.search(r"\*\*Detecções:\*\* (\d+)", conteudo_ant)
            total_det = int(m.group(1)) + len(info["ocorrencias"]) if m else len(info["ocorrencias"])
            info_merged = {"semaforo": info["semaforo"], "ocorrencias": info["ocorrencias"]}
            # Reescreve com total acumulado
            nota = _nota_criptografia(nome, info_merged)
            nota = nota.replace(f"**Detecções:** {len(info['ocorrencias'])}", f"**Detecções:** {total_det}")
            _escrever(nota_path, nota)
        else:
            _escrever(nota_path, _nota_criptografia(nome, info))

    # ── 6. Nota do scan atual ─────────────────────────────────────────────────
    todos_findings = list(indice.keys())
    por_sev_vault: dict[str, int] = {}
    for f_path in (vault_dir / "findings").glob("*.md"):
        conteudo = f_path.read_text(encoding="utf-8")
        m = re.search(r"^tags:.*\[(.*)\]", conteudo, re.MULTILINE)
        if m:
            tags_str = m.group(1)
            for sev in ["error", "warning", "info"]:
                if sev in tags_str:
                    sev_upper = sev.upper()
                    por_sev_vault[sev_upper] = por_sev_vault.get(sev_upper, 0) + 1
                    break

    _escrever(
        vault_dir / "scans" / f"{protocolo}.md",
        _nota_scan(resultado, protocolo, len(indice))
    )

    # ── 7. Salva índice atualizado ────────────────────────────────────────────
    _salvar_indice(vault_dir, indice)

    # ── 8. Atualiza lista de scans e índice geral ─────────────────────────────
    scans_atualizados = scans_existentes.copy()
    if protocolo not in scans_atualizados:
        scans_atualizados.append(protocolo)

    _escrever(
        vault_dir / "_index.md",
        _nota_index(
            slug, scans_atualizados, len(indice), por_sev_vault,
            list(por_pacote.keys()), list(por_endpoint.keys()),
            list(por_segredo.keys()), algos_novos,
        )
    )

    # ── 9. Empacota ───────────────────────────────────────────────────────────
    zip_path = vault_dir.parent / f"vault-{slug}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for arquivo in sorted(vault_dir.rglob("*")):
            if arquivo.is_file() and arquivo.name != ".finding_index.json":
                zf.write(arquivo, arquivo.relative_to(vault_dir))

    n_notas = sum(1 for _ in vault_dir.rglob("*.md"))
    print(f"[vault] ✓ {n_notas} notas no vault ({novos} novos findings, {atualizados} atualizados)")
    print(f"[vault] ✓ {len(scans_atualizados)} scan(s) acumulados → {zip_path}")

    return zip_path
