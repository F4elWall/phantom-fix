"""
PhantomFix — Data Control (scanner.py)
Script chamado pelo Core como subprocesso. Recebe o caminho de uma pasta
já extraída e o caminho de um arquivo de saída, roda Semgrep + ZAP,
prioriza com OpenRouter (gratuito) e escreve o resultado em JSON.

Uso:
    python scanner.py <pasta_extraida> <arquivo_saida.json>
"""

import subprocess
import json
import sys
import os
import time
import requests
from datetime import datetime
from pathlib import Path

# ── Configuração via variáveis de ambiente ────────────────────────────────────
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL   = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free")
ZAP_TIMEOUT        = int(os.getenv("ZAP_TIMEOUT", "3600"))
ZAP_API_URL        = os.getenv("ZAP_API_URL", "http://localhost:8080")

# ── Argumentos ────────────────────────────────────────────────────────────────
if len(sys.argv) < 3:
    print("Uso: python scanner.py <pasta_extraida> <arquivo_saida.json>")
    sys.exit(1)

PASTA         = Path(sys.argv[1]).resolve()
ARQUIVO_SAIDA = Path(sys.argv[2]).resolve()

if not PASTA.exists():
    print(f"Pasta não encontrada: {PASTA}")
    sys.exit(1)

# ── Lê scan.config.json (opcional) ───────────────────────────────────────────
config_path = PASTA / "scan.config.json"
url_alvo    = None

if config_path.exists():
    try:
        config   = json.loads(config_path.read_text(encoding="utf-8"))
        url_alvo = config.get("url")
        print(f"Config encontrado. URL alvo: {url_alvo or 'não informada'}")
    except json.JSONDecodeError:
        print("scan.config.json inválido — ignorando")

vulnerabilidades = []

# ══════════════════════════════════════════════════════════════════════════════
# PARTE 1 — SEMGREP (SAST)
# ══════════════════════════════════════════════════════════════════════════════
print("\n[1/3] Rodando Semgrep (SAST)...")

resultado_semgrep = subprocess.run(
    ["semgrep", "--config=auto", "--json", "--quiet", str(PASTA)],
    capture_output=True, text=True
)

try:
    saida_semgrep = json.loads(resultado_semgrep.stdout)
except json.JSONDecodeError:
    print(f"  ⚠ Semgrep não retornou JSON válido: {resultado_semgrep.stderr[:300]}")
    saida_semgrep = {"results": []}

for item in saida_semgrep.get("results", []):
    trecho = item.get("extra", {}).get("lines", "").strip()
    # Se o Semgrep não entregou o trecho, lê direto do arquivo
    if not trecho or trecho == "requires login":
        try:
            arquivo_path = Path(item.get("path", ""))
            linha        = item.get("start", {}).get("line", 0)
            if arquivo_path.exists() and linha > 0:
                linhas  = arquivo_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                inicio  = max(0, linha - 4)
                fim     = min(len(linhas), linha + 3)
                trecho  = "\n".join(linhas[inicio:fim])
        except Exception:
            trecho = "trecho não disponível"

    vulnerabilidades.append({
        "id":               "",
        "origem":           "semgrep",
        "arquivo":          item.get("path", ""),
        "linha":            item.get("start", {}).get("line", 0),
        "tipo":             item.get("check_id", "").split(".")[-1],
        "severidade":       item.get("extra", {}).get("severity", "DESCONHECIDA"),
        "descricao":        item.get("extra", {}).get("message", ""),
        "trecho_do_codigo": trecho,
        "score":            0,
        "justificativa":    "",
    })

print(f"  → {len(vulnerabilidades)} achados")

# ══════════════════════════════════════════════════════════════════════════════
# PARTE 2 — ZAP (DAST)
# ══════════════════════════════════════════════════════════════════════════════
def risco_zap_para_severidade(riskdesc: str) -> str:
    r = riskdesc.lower()
    if "high"   in r: return "ERROR"
    if "medium" in r: return "WARNING"
    return "INFO"

print("\n[2/3] ZAP (DAST)...")
contador_zap = 0

def zap_get(endpoint: str, params: dict = {}) -> dict:
    resp = requests.get(f"{ZAP_API_URL}{endpoint}", params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()

if url_alvo:
    print(f"  URL alvo: {url_alvo}")
    try:
        print("  Rodando spider...")
        spider_resp = zap_get("/JSON/spider/action/scan/", {"url": url_alvo})
        scan_id     = spider_resp.get("scan")

        inicio = time.time()
        while True:
            status = zap_get("/JSON/spider/view/status/", {"scanId": scan_id})
            if int(status.get("status", 0)) >= 100:
                break
            if time.time() - inicio > ZAP_TIMEOUT:
                print(f"  ⚠ Spider excedeu {ZAP_TIMEOUT}s — seguindo.")
                break
            time.sleep(2)

        print("  Rodando active scan...")
        ascan_resp = zap_get("/JSON/ascan/action/scan/", {"url": url_alvo})
        ascan_id   = ascan_resp.get("scan")

        inicio = time.time()
        while True:
            status = zap_get("/JSON/ascan/view/status/", {"scanId": ascan_id})
            if int(status.get("status", 0)) >= 100:
                break
            if time.time() - inicio > ZAP_TIMEOUT:
                print(f"  ⚠ Active scan excedeu {ZAP_TIMEOUT}s — coletando alertas disponíveis.")
                break
            time.sleep(3)

        alertas_resp = zap_get("/JSON/core/view/alerts/", {"baseurl": url_alvo})
        alertas      = alertas_resp.get("alerts", [])

        for alerta in alertas:
            vulnerabilidades.append({
                "id":               "",
                "origem":           "zap",
                "arquivo":          alerta.get("url", ""),
                "linha":            0,
                "tipo":             alerta.get("alert", "desconhecido").lower().replace(" ", "-"),
                "severidade":       risco_zap_para_severidade(alerta.get("risk", "")),
                "descricao":        alerta.get("description", ""),
                "trecho_do_codigo": alerta.get("solution", ""),
                "score":            0,
                "justificativa":    "",
            })
            contador_zap += 1

    except requests.exceptions.ConnectionError:
        print(f"  ⚠ Não foi possível conectar ao ZAP em {ZAP_API_URL}")
    except Exception as e:
        print(f"  ⚠ Erro ao consultar a API do ZAP: {e}")

    print(f"  → {contador_zap} achados")
else:
    print("  Sem URL no config — pulando DAST.")

# Numera IDs em sequência
for i, v in enumerate(vulnerabilidades):
    v["id"] = f"vuln-{i+1:03d}"

print(f"\n  Total combinado: {len(vulnerabilidades)} vulnerabilidades")

# ══════════════════════════════════════════════════════════════════════════════
# PARTE 3 — PRIORIZAÇÃO COM OPENROUTER (gratuito, sem custo de API)
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n[3/3] Priorizando com OpenRouter ({OPENROUTER_MODEL})...")

if not OPENROUTER_API_KEY:
    print("  ⚠ OPENROUTER_API_KEY não configurada — scores zerados.")
    for vuln in vulnerabilidades:
        vuln["score"]        = 0
        vuln["justificativa"] = "API key não configurada"
else:
    def pontuar_com_ia(vuln: dict) -> tuple[int, str]:
        origem_desc = (
            "análise estática de código"
            if vuln["origem"] == "semgrep"
            else "teste dinâmico da aplicação rodando"
        )
        prompt = f"""Você é especialista em segurança de aplicações.
Analise a vulnerabilidade abaixo e atribua um score de 0 a 10 (10 = crítico).

Origem: {vuln['origem']} ({origem_desc})
Tipo: {vuln['tipo']}
Severidade: {vuln['severidade']}
Descrição: {vuln['descricao']}
Trecho: {vuln['trecho_do_codigo'][:300]}

Responda APENAS com este JSON, sem mais nada:
{{"score": 8, "justificativa": "motivo em uma frase"}}"""

        try:
            resp = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type":  "application/json",
                },
                json={
                    "model":    OPENROUTER_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=30   # muito mais rápido que Ollama local
            )
            conteudo = resp.json()["choices"][0]["message"]["content"].strip()
            if conteudo.startswith("```"):
                conteudo = conteudo.split("```")[1]
                if conteudo.startswith("json"):
                    conteudo = conteudo[4:]
            resultado = json.loads(conteudo)
            return resultado.get("score", 5), resultado.get("justificativa", "")
        except Exception as e:
            return 5, f"Análise indisponível ({e})"

    for idx, vuln in enumerate(vulnerabilidades, 1):
        print(f"  {idx}/{len(vulnerabilidades)} — {vuln['id']}", end="\r")
        vuln["score"], vuln["justificativa"] = pontuar_com_ia(vuln)

vulnerabilidades.sort(key=lambda x: x["score"], reverse=True)
print(f"\n  Priorização concluída.")

# ══════════════════════════════════════════════════════════════════════════════
# ESCREVE O JSON DE SAÍDA
# ══════════════════════════════════════════════════════════════════════════════
resultado_final = {
    "analisado_em":     datetime.now().isoformat(),
    "total_encontrado": len(vulnerabilidades),
    "origem_semgrep":   sum(1 for v in vulnerabilidades if v["origem"] == "semgrep"),
    "origem_zap":       sum(1 for v in vulnerabilidades if v["origem"] == "zap"),
    "vulnerabilidades": vulnerabilidades,
}

ARQUIVO_SAIDA.parent.mkdir(parents=True, exist_ok=True)
ARQUIVO_SAIDA.write_text(
    json.dumps(resultado_final, indent=2, ensure_ascii=False),
    encoding="utf-8"
)
print(f"\nResultado escrito em: {ARQUIVO_SAIDA}")
