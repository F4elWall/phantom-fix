"""
Autor e revisão: Bernardo Coroa
Versão: 3.1

PhantomFix — Data Control (scanner.py)
Script chamado pelo Core como subprocesso. Recebe o caminho de uma pasta
já extraída e o caminho de um arquivo de saída, roda Semgrep + ZAP +
Gitleaks + Trivy e escreve o resultado bruto em JSON.

Responsabilidade: APENAS coleta de dados.
Correlação e scoring ficam no analyser.py.

Uso:
    python scanner.py <pasta_extraida> <arquivo_saida.json>
"""

import subprocess
import json
import sys
import os
import time
import tempfile
import requests
from datetime import datetime
from pathlib import Path

# ── Configuração via variáveis de ambiente ────────────────────────────────────
ZAP_TIMEOUT = int(os.getenv("ZAP_TIMEOUT", "3600"))
ZAP_API_URL = os.getenv("ZAP_API_URL", "http://localhost:8080")

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
print("\n[1/4] Rodando Semgrep (SAST)...")

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
    if not trecho or trecho == "requires login":
        try:
            arquivo_path = Path(item.get("path", ""))
            linha        = item.get("start", {}).get("line", 0)
            if arquivo_path.exists() and linha > 0:
                linhas = arquivo_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                inicio = max(0, linha - 4)
                fim    = min(len(linhas), linha + 3)
                trecho = "\n".join(linhas[inicio:fim])
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

print("\n[2/4] ZAP (DAST)...")
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

        alertas_por_tipo: dict[str, dict] = {}
        for alerta in alertas:
            tipo        = alerta.get("alert", "desconhecido")
            risco_atual = alerta.get("riskcode", 0)
            if tipo not in alertas_por_tipo:
                alertas_por_tipo[tipo] = alerta
            else:
                if risco_atual > alertas_por_tipo[tipo].get("riskcode", 0):
                    alertas_por_tipo[tipo] = alerta

        for alerta in alertas_por_tipo.values():
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

        print(f"  ({len(alertas)} alertas brutos → {contador_zap} tipos únicos após deduplicação)")

    except requests.exceptions.ConnectionError:
        print(f"  ⚠ Não foi possível conectar ao ZAP em {ZAP_API_URL}")
    except Exception as e:
        print(f"  ⚠ Erro ao consultar a API do ZAP: {e}")

    print(f"  → {contador_zap} achados")
else:
    print("  Sem URL no config — pulando DAST.")

# ══════════════════════════════════════════════════════════════════════════════
# PARTE 3 — GITLEAKS (Secrets)
# ══════════════════════════════════════════════════════════════════════════════
print("\n[3/4] Rodando Gitleaks (Secrets)...")
contador_gitleaks = 0

try:
    resultado_gitleaks = subprocess.run(
        [
            "gitleaks", "detect",
            "--source", str(PASTA),
            "--report-format", "json",
            "--report-path", "/dev/stdout",
            "--no-git",
            "--exit-code", "0",
        ],
        capture_output=True, text=True
    )

    saida_gl   = resultado_gitleaks.stdout.strip()
    achados_gl = json.loads(saida_gl) if saida_gl else []

    for item in achados_gl:
        # Ofusca o valor real do secret — nunca salvar a credencial exposta
        match_raw = item.get("Match", "")
        secret    = item.get("Secret", "")
        if secret and secret in match_raw:
            trecho = match_raw.replace(secret, "[REDACTED]")
        else:
            trecho = match_raw

        vulnerabilidades.append({
            "id":               "",
            "origem":           "gitleaks",
            "arquivo":          item.get("File", ""),
            "linha":            item.get("StartLine", 0),
            "tipo":             item.get("RuleID", "secret-exposed"),
            "severidade":       "ERROR",
            "descricao":        item.get("Description", "Credencial ou segredo exposto no código"),
            "trecho_do_codigo": trecho,
            "score":            0,
            "justificativa":    "",
        })
        contador_gitleaks += 1

    print(f"  → {contador_gitleaks} achados")

except FileNotFoundError:
    print("  ⚠ Gitleaks não encontrado — verifique se está instalado e no PATH")
except json.JSONDecodeError:
    print("  ⚠ Gitleaks não retornou JSON válido")
except Exception as e:
    print(f"  ⚠ Erro ao rodar Gitleaks: {e}")

# ══════════════════════════════════════════════════════════════════════════════
# PARTE 4 — TRIVY (SCA — Dependências)
# ══════════════════════════════════════════════════════════════════════════════
print("\n[4/4] Rodando Trivy (SCA — Dependências)...")
contador_trivy = 0

# FIX v3.1: Trivy mistura logs INFO/WARN no stdout junto com o JSON, corrompendo
# o json.loads(). Solução: redirecionar o JSON para um arquivo temporário via
# --output, isolando completamente o JSON dos logs do stderr/stdout.
# Também adicionado --include-dev-deps para capturar vulns em deps de dev
# (ex: brace-expansion, nanoid) que o Trivy suprime por padrão.

with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
    trivy_output = Path(tmp.name)

try:
    resultado_trivy = subprocess.run(
        [
            "trivy", "fs",
            "--format", "json",
            "--output", str(trivy_output),  # ← JSON isolado do stdout
            "--quiet",
            "--scanners", "vuln",
            "--include-dev-deps",           # ← captura deps de dev também
            str(PASTA),
        ],
        capture_output=True, text=True
    )

    if resultado_trivy.returncode != 0:
        print(f"  ⚠ Trivy retornou código {resultado_trivy.returncode}")
        if resultado_trivy.stderr:
            print(f"  stderr: {resultado_trivy.stderr[:300]}")

    if trivy_output.exists() and trivy_output.stat().st_size > 0:
        saida_trivy = json.loads(trivy_output.read_text(encoding="utf-8"))
    else:
        print("  ⚠ Trivy não gerou arquivo de saída")
        saida_trivy = {}

    for resultado in saida_trivy.get("Results", []):
        arquivo_dep = resultado.get("Target", "")
        for vuln in resultado.get("Vulnerabilities", []) or []:
            pkg_name         = vuln.get("PkgName", "")
            cve_id           = vuln.get("VulnerabilityID", "")
            severidade_trivy = vuln.get("Severity", "UNKNOWN").upper()

            mapa_sev = {
                "CRITICAL": "ERROR",
                "HIGH":     "ERROR",
                "MEDIUM":   "WARNING",
                "LOW":      "INFO",
                "UNKNOWN":  "INFO",
            }

            descricao = (
                f"{cve_id}: {vuln.get('Title', '')} — "
                f"{pkg_name} {vuln.get('InstalledVersion', '')} "
                f"(fix: {vuln.get('FixedVersion', 'sem fix disponível')})"
            ).strip(" —")

            vulnerabilidades.append({
                "id":               "",
                "origem":           "trivy",
                "arquivo":          arquivo_dep,
                "linha":            0,
                "tipo":             "vulnerable-dependency",
                "severidade":       mapa_sev.get(severidade_trivy, "INFO"),
                "descricao":        descricao,
                "trecho_do_codigo": vuln.get("Description", ""),
                "score":            0,
                "justificativa":    "",
                # Campos extras preservados para a correlação no analyser.py
                "pkg_name":         pkg_name,
                "cve_id":           cve_id,
                "sev_original":     severidade_trivy,
            })
            contador_trivy += 1

    print(f"  → {contador_trivy} achados")

except FileNotFoundError:
    print("  ⚠ Trivy não encontrado — verifique se está instalado e no PATH")
except json.JSONDecodeError as e:
    print(f"  ⚠ Trivy não retornou JSON válido: {e}")
except Exception as e:
    print(f"  ⚠ Erro ao rodar Trivy: {e}")
finally:
    trivy_output.unlink(missing_ok=True)  # limpa o arquivo temporário

# ══════════════════════════════════════════════════════════════════════════════
# FINALIZAÇÃO — numera IDs e escreve o JSON
# ══════════════════════════════════════════════════════════════════════════════
for i, v in enumerate(vulnerabilidades):
    v["id"] = f"vuln-{i+1:03d}"

total = len(vulnerabilidades)
print(f"\n  Total combinado: {total} vulnerabilidades")
print(f"    Semgrep:  {sum(1 for v in vulnerabilidades if v['origem'] == 'semgrep')}")
print(f"    ZAP:      {sum(1 for v in vulnerabilidades if v['origem'] == 'zap')}")
print(f"    Gitleaks: {sum(1 for v in vulnerabilidades if v['origem'] == 'gitleaks')}")
print(f"    Trivy:    {sum(1 for v in vulnerabilidades if v['origem'] == 'trivy')}")

resultado_final = {
    "analisado_em":    datetime.now().isoformat(),
    "total_encontrado": total,
    "origem_semgrep":  sum(1 for v in vulnerabilidades if v["origem"] == "semgrep"),
    "origem_zap":      sum(1 for v in vulnerabilidades if v["origem"] == "zap"),
    "origem_gitleaks": sum(1 for v in vulnerabilidades if v["origem"] == "gitleaks"),
    "origem_trivy":    sum(1 for v in vulnerabilidades if v["origem"] == "trivy"),
    "vulnerabilidades": vulnerabilidades,
}

ARQUIVO_SAIDA.parent.mkdir(parents=True, exist_ok=True)
ARQUIVO_SAIDA.write_text(
    json.dumps(resultado_final, indent=2, ensure_ascii=False),
    encoding="utf-8"
)
print(f"\nResultado escrito em: {ARQUIVO_SAIDA}")
