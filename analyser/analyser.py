"""
PhantomFix — Analyser
Versão: 3.1

Recebe o findings.json do scanner, executa correlação mecânica entre
ferramentas e enriquece cada vulnerabilidade com score, justificativa,
categoria e recomendação via LLM.

Fluxo:
  1. Correlação 1 — Trivy × imports no código
       - Import direto encontrado  → score_base 8.5 | tag "confirmado_em_uso"
       - Só no lockfile (dep transitiva) → score_base 6.0 | tag "confirmado_via_lockfile"
  2. Correlação 2 — Semgrep × ZAP mesmo tipo + localização (score_base 8.0)
  3. LLM analisa cada vulnerabilidade com o contexto de correlação já embutido
  4. Ordena por score decrescente e salva

Uso:
    python analyser.py <findings.json> <saida.json>
"""

import json
import os
import re
import sys
import time
from pathlib import Path
from datetime import datetime

import requests


# ══════════════════════════════════════════════════════════════════════════════
# CORRELAÇÃO 1 — Trivy × import/uso da biblioteca no código
#
# Dois níveis de evidência:
#   A) Import direto no código-fonte  → risco confirmado, score_base 8.5
#   B) Presente apenas no lockfile    → dep transitiva do bundler/runtime,
#      risco real mas exploração indireta, score_base 6.0
# ══════════════════════════════════════════════════════════════════════════════

EXTENSOES_CODIGO = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
    ".rb", ".php", ".cs", ".cpp", ".c", ".rs", ".kt", ".swift"
}


def _cache_arquivos_codigo(pasta: Path) -> dict:
    """Lê todos os arquivos de código da pasta e retorna {path: conteudo_lower}."""
    cache = {}
    for f in pasta.rglob("*"):
        if f.is_file() and f.suffix.lower() in EXTENSOES_CODIGO:
            try:
                cache[f] = f.read_text(encoding="utf-8", errors="ignore").lower()
            except Exception:
                pass
    return cache


def correlacionar_trivy_imports(vulns: list, pasta_repo: Path) -> int:
    """
    Para cada finding do Trivy, verifica se o pacote vulnerável é importado
    em algum arquivo de código do projeto.

    - Import direto encontrado  → tag "confirmado_em_uso",      score_base 8.5
    - Só presente no lockfile   → tag "confirmado_via_lockfile", score_base 6.0

    Retorna o número de findings afetados (ambos os casos).
    """
    trivy_vulns = [v for v in vulns if v.get("origem") == "trivy" and v.get("pkg_name")]
    if not trivy_vulns:
        return 0

    # Agrupa findings Trivy por pacote para evitar varrer o código N vezes
    por_pacote: dict[str, list] = {}
    for v in trivy_vulns:
        pkg = v["pkg_name"].lower()
        por_pacote.setdefault(pkg, []).append(v)

    # Só varre o código se o repositório existir
    cache = _cache_arquivos_codigo(pasta_repo) if pasta_repo.exists() else {}
    total_afetados = 0

    for pkg_key, findings in por_pacote.items():
        # Gera variações do nome para cobrir casos como "python-jose" → "jose"
        nome_simples = pkg_key.split("/")[-1].replace("-", "_").replace(".", "_")
        padroes = list({pkg_key, nome_simples})

        arquivos_com_uso = []
        for arq_path, conteudo in cache.items():
            for padrao in padroes:
                if re.search(r'\b' + re.escape(padrao) + r'\b', conteudo):
                    arquivos_com_uso.append(str(arq_path))
                    break

        if arquivos_com_uso:
            # ── Nível A: import direto confirmado no código-fonte ─────────────
            exemplos = [Path(a).name for a in arquivos_com_uso[:3]]
            for v in findings:
                v["score_base"]          = 8.5
                v["tags_correlacao"]     = v.get("tags_correlacao", []) + ["confirmado_em_uso"]
                v["contexto_correlacao"] = (
                    f"Biblioteca vulnerável '{pkg_key}' ({v.get('cve_id', '')}) "
                    f"confirmada em uso direto no código: {', '.join(exemplos)}. "
                    f"O risco não é teórico."
                )
            total_afetados += len(findings)

        else:
            # ── Nível B: presente no lockfile, sem import direto ──────────────
            # Provavelmente dep transitiva de bundler/runtime (ex: Vite, Webpack).
            # Risco real, mas exploração é indireta — o score deve refletir isso.
            for v in findings:
                v["score_base"]          = 6.0
                v["tags_correlacao"]     = v.get("tags_correlacao", []) + ["confirmado_via_lockfile"]
                v["contexto_correlacao"] = (
                    f"Biblioteca vulnerável '{pkg_key}' ({v.get('cve_id', '')}) "
                    f"presente no lockfile do projeto, mas sem import direto "
                    f"identificado no código-fonte. Provavelmente dependência "
                    f"transitiva de bundler ou runtime (ex: Vite, Webpack). "
                    f"O risco é real, mas a exploração é indireta e depende "
                    f"do contexto de execução — score deve ser moderado."
                )
            total_afetados += len(findings)

    return total_afetados


# ══════════════════════════════════════════════════════════════════════════════
# CORRELAÇÃO 2 — Semgrep × ZAP: mesmo tipo + mesmo arquivo ou linhas próximas
#
# Quando SAST e DAST convergem para o mesmo ponto, a confiança aumenta muito.
# score_base → 8.0 | tag → "confirmado_por_multiplas_ferramentas"
# ══════════════════════════════════════════════════════════════════════════════

LINHAS_PROXIMAS = int(os.getenv("CORRELACAO_LINHAS_PROXIMAS", "10"))

GRUPOS_TIPO = [
    {"xss", "crosssite", "scripting", "injection"},
    {"sqli", "sqlinjection", "sql"},
    {"ssrf", "requestforgery", "forgery"},
    {"auth", "authentication", "autenticacao", "login"},
    {"csrf", "crosssiterequest"},
    {"rce", "remoteexecution", "commandinjection", "cmdinject"},
    {"disclosure", "information", "informacao", "exposicao"},
    {"cors", "crossorigin"},
    {"redirect", "redirecionamento", "open"},
]


def _normalizar_tipo(tipo: str) -> str:
    t = tipo.lower()
    t = re.sub(r'^(cwe-\d+[\s\-_]*)', '', t)
    t = re.sub(r'[\-_\s]', '', t)
    return t


def _mesmo_grupo(tipo_a: str, tipo_b: str) -> bool:
    na, nb = _normalizar_tipo(tipo_a), _normalizar_tipo(tipo_b)
    if na == nb:
        return True
    for grupo in GRUPOS_TIPO:
        if any(kw in na for kw in grupo) and any(kw in nb for kw in grupo):
            return True
    return False


def correlacionar_semgrep_zap(vulns: list) -> int:
    """
    Cruza findings do Semgrep com findings do ZAP pelo tipo e localização.
    Retorna o número de pares correlacionados.
    """
    semgrep_vulns = [v for v in vulns if v.get("origem") == "semgrep"]
    zap_vulns     = [v for v in vulns if v.get("origem") == "zap"]
    pares = 0

    for sv in semgrep_vulns:
        for zv in zap_vulns:
            if not _mesmo_grupo(sv.get("tipo", ""), zv.get("tipo", "")):
                continue

            arquivo_sg = Path(sv.get("arquivo", "")).name.lower()
            arquivo_zp = Path(zv.get("arquivo", "")).name.lower()

            mesmo_arquivo = bool(arquivo_sg and arquivo_zp and arquivo_sg == arquivo_zp)
            proximas      = (
                sv.get("linha", 0) > 0 and zv.get("linha", 0) > 0
                and abs(sv["linha"] - zv["linha"]) <= LINHAS_PROXIMAS
            )

            if mesmo_arquivo or proximas:
                tag   = "confirmado_por_multiplas_ferramentas"
                razao = (
                    f"Semgrep (SAST) e ZAP (DAST) detectaram '{sv['tipo']}' "
                    f"no mesmo ponto: arquivo '{sv['arquivo']}'"
                    + (f", linhas {sv['linha']} e {zv['linha']}" if proximas else "")
                    + ". Vulnerabilidade confirmada por análise estática e dinâmica independentes."
                )

                for v in (sv, zv):
                    if tag not in v.get("tags_correlacao", []):
                        v.setdefault("tags_correlacao", []).append(tag)
                        v["score_base"]          = max(v.get("score_base", 0), 8.0)
                        v["contexto_correlacao"] = razao

                pares += 1

    return pares


# ══════════════════════════════════════════════════════════════════════════════
# ANALYSER AGENT
# ══════════════════════════════════════════════════════════════════════════════

class AnalyserAgent:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("OLLAMA_ANALYSER_KEY")
        if not self.api_key:
            raise ValueError("Defina a variável de ambiente OLLAMA_ANALYSER_KEY.")
        self.url   = "https://ollama.com/v1/chat/completions"
        self.model = os.getenv("OLLAMA_MODEL", "gpt-oss:20b")

    def _call_llm(self, prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type":  "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role":    "system",
                    "content": "Você é um analista de segurança. Responda apenas com JSON válido, sem comentários adicionais.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature":       0.2,
            "max_tokens":        800,
            "reasoning_effort":  "low",
            "include_reasoning": False,
        }

        for tentativa in range(5):
            try:
                resp = requests.post(self.url, headers=headers, json=payload, timeout=60)

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("retry-after", 60))
                    print(f"\n  ⏳ Rate limit — aguardando {retry_after}s...")
                    time.sleep(retry_after + 1)
                    continue

                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"]

            except requests.exceptions.RequestException as e:
                print(f"  Tentativa {tentativa+1} falhou: {e}")
                time.sleep(2)

        raise Exception("Falha ao comunicar com a API após 5 tentativas.")

    def _montar_prompt(self, vuln: dict) -> str:
        """
        Monta o prompt para o LLM. Se a vulnerabilidade foi correlacionada,
        inclui esse contexto para que o score reflita a confirmação.
        """
        contexto_correlacao = ""
        tags       = vuln.get("tags_correlacao", [])
        score_base = vuln.get("score_base", 0)

        if tags:
            contexto_correlacao = f"""
ATENÇÃO — Correlação detectada pelo sistema:
- Tags: {", ".join(tags)}
- Score base sugerido pela correlação: {score_base}
- Contexto: {vuln.get("contexto_correlacao", "")}

Considere este contexto ao definir o score final:
- "confirmado_em_uso": import direto no código → score alto (≥ 8.0)
- "confirmado_via_lockfile": dep transitiva do bundler, sem import direto → score moderado (4.0–6.9)
- "confirmado_por_multiplas_ferramentas": SAST + DAST convergem → score alto (≥ 8.0)
"""

        return f"""Analise a vulnerabilidade abaixo e retorne **apenas** um objeto JSON com as chaves "score", "justificativa", "categoria" e "recomendacao". O JSON deve estar em uma linha, sem quebras de linha extras.

Escala de score (0-10):
- 9.0-10.0: Crítico — exploração trivial, impacto imediato (ex: RCE, SQLi com dados expostos)
- 7.0-8.9:  Alto — exploração possível, impacto significativo (ex: XSS armazenado, IDOR)
- 4.0-6.9:  Médio — exploração condicionada, impacto moderado (ex: headers ausentes, CORS, dep transitiva)
- 1.0-3.9:  Baixo — difícil exploração, impacto limitado (ex: informações de versão, timing)
- 0.0-0.9:  Informativo — sem impacto direto
{contexto_correlacao}
Vulnerabilidade:
{json.dumps(vuln, indent=2, ensure_ascii=False)}

Responda exatamente assim (exemplo):
{{"score": 8.5, "justificativa": "...", "categoria": "...", "recomendacao": "..."}}"""

    def barra_progresso(self, atual: int, total: int, largura: int = 35) -> str:
        preenchido = int(largura * atual / total) if total > 0 else 0
        barra      = "█" * preenchido + "░" * (largura - preenchido)
        pct        = int(100 * atual / total) if total > 0 else 0
        return f"  [{barra}] {pct:3d}% ({atual}/{total})"

    def analyze_findings(self, findings_path: Path, output_path: Path) -> Path | None:
        if not findings_path.exists():
            print(f"Arquivo não encontrado: {findings_path}")
            return None

        data  = json.loads(findings_path.read_text(encoding="utf-8"))
        vulns = data.get("vulnerabilidades", [])

        # ── Correlação mecânica (antes do LLM) ───────────────────────────────

        pasta_repo = Path(os.getenv("PASTA_REPO", ""))
        if not pasta_repo.exists():
            # Fallback: tenta inferir pelo caminho do findings
            candidata  = findings_path.parent.parent.parent / "jobs"
            pastas_job = list(candidata.rglob("repo")) if candidata.exists() else []
            pasta_repo = pastas_job[0] if pastas_job else Path("")

        print(f"\n[Correlação 1] Trivy × imports no código (repo: {pasta_repo})...")
        c1 = correlacionar_trivy_imports(vulns, pasta_repo)
        print(f"  {c1} finding(s) Trivy correlacionados")
        # Detalha os dois níveis para facilitar debugging
        em_uso     = sum(1 for v in vulns if "confirmado_em_uso"      in v.get("tags_correlacao", []))
        via_lock   = sum(1 for v in vulns if "confirmado_via_lockfile" in v.get("tags_correlacao", []))
        if c1:
            print(f"    → {em_uso} com import direto (score_base 8.5)")
            print(f"    → {via_lock} só no lockfile / dep transitiva (score_base 6.0)")

        print("\n[Correlação 2] Semgrep × ZAP (mesmo tipo + localização)...")
        c2 = correlacionar_semgrep_zap(vulns)
        print(f"  {c2} par(es) Semgrep×ZAP correlacionado(s)")

        total_correlacionados = sum(1 for v in vulns if v.get("tags_correlacao"))
        print(f"\n  Total com correlação: {total_correlacionados} vulnerabilidades")

        # ── Análise LLM ───────────────────────────────────────────────────────
        limite = int(os.getenv("ANALYSER_LIMITE", "0"))
        vulns_para_analisar = vulns[:limite] if limite > 0 else vulns

        total = len(vulns_para_analisar)
        print(f"\nAnalisando {total} vulnerabilidades com LLM ({self.model})...")
        print(f"  (intervalo de 2s entre chamadas para respeitar o rate limit)\n")

        enriched = []
        for idx, vuln in enumerate(vulns_para_analisar, 1):
            print(self.barra_progresso(idx - 1, total), end="\r", flush=True)

            prompt = self._montar_prompt(vuln)

            try:
                raw   = self._call_llm(prompt)
                clean = raw.strip()

                if "```json" in clean:
                    clean = clean.split("```json")[1].split("```")[0].strip()
                elif "```" in clean:
                    clean = clean.split("```")[1].split("```")[0].strip()

                start = clean.find("{")
                end   = clean.rfind("}") + 1
                if start != -1 and end > start:
                    clean = clean[start:end]

                result = json.loads(clean)
                vuln["score"]         = result.get("score", "N/A")
                vuln["justificativa"] = result.get("justificativa", "N/A")
                vuln["categoria"]     = result.get("categoria", "N/A")
                vuln["recomendacao"]  = result.get("recomendacao", "N/A")

            except Exception as e:
                print(f"\n  ⚠ Erro em {vuln.get('id', '?')}: {e}")
                vuln["score"]         = vuln.get("score_base") or None
                vuln["justificativa"] = f"Falha na análise: {str(e)[:100]}"
                vuln["categoria"]     = "Desconhecida"
                vuln["recomendacao"]  = "Revisar manualmente"

            enriched.append(vuln)
            time.sleep(2)

        print(self.barra_progresso(total, total), flush=True)
        print(f"\n  Análise concluída.")

        # Ordena por score decrescente
        enriched_ordenado = sorted(
            enriched,
            key=lambda v: float(v.get("score") or 0),
            reverse=True,
        )

        output = {
            **data,
            "analisado_por_agente":  True,
            "modelo_ia":             f"ollama-cloud/{self.model}",
            "processado_em":         datetime.now().isoformat(),
            "total_correlacionados": total_correlacionados,
            "vulnerabilidades":      enriched_ordenado,
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(output, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"Resultado enriquecido salvo em: {output_path}")
        return output_path


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python analyser.py <findings.json> <saida.json>")
        sys.exit(1)

    agent = AnalyserAgent()
    agent.analyze_findings(Path(sys.argv[1]), Path(sys.argv[2]))
