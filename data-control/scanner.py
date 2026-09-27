"""
Autor e revisão: Bernardo Coroa
Versão: 4.0

PhantomFix — Data Control (scanner.py)
Script chamado pelo Core como subprocesso. Recebe o caminho de uma pasta
já extraída e o caminho de um arquivo de saída, roda todos os scanners
disponíveis e escreve o resultado bruto em JSON.

Scanners:
  SAST:    Semgrep
  DAST:    OWASP ZAP
  Secrets: Gitleaks, TruffleHog
  SCA:     Trivy, Syft + Grype
  IaC:     Checkov, Hadolint
  API:     Spectral
  CVEs:    Nuclei (requer URL ativa)

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
ZAP_TIMEOUT      = int(os.getenv("ZAP_TIMEOUT", "3600"))
ZAP_API_URL      = os.getenv("ZAP_API_URL", "http://localhost:8080")
NUCLEI_TEMPLATES = os.getenv("NUCLEI_TEMPLATES", "")   # pasta de templates; vazio = padrão do nuclei
SPECTRAL_RULESET = os.getenv("SPECTRAL_RULESET", "@stoplight/spectral-owasp-ruleset")

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
print("\n[1/11] Rodando Semgrep (SAST)...")

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

print("\n[2/11] ZAP (DAST)...")
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
print("\n[3/11] Rodando Gitleaks (Secrets)...")
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
print("\n[4/11] Rodando Trivy (SCA — Dependências)...")
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
# PARTE 5 — TRUFFLEHOG (Secrets com validação ativa)
# ══════════════════════════════════════════════════════════════════════════════
print("\n[5/11] Rodando TruffleHog (Secrets + validação ativa)...")
contador_trufflehog = 0

try:
    resultado_trufflehog = subprocess.run(
        [
            "trufflehog", "filesystem", str(PASTA),
            "--json",
            "--no-update",          # não atualiza detectores online durante o scan
        ],
        capture_output=True, text=True
    )

    # TruffleHog emite um JSON por linha (NDJSON), não um array
    for linha in resultado_trufflehog.stdout.splitlines():
        linha = linha.strip()
        if not linha:
            continue
        try:
            item = json.loads(linha)
        except json.JSONDecodeError:
            continue

        # Estrutura do TruffleHog v3
        source_meta  = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        arquivo      = source_meta.get("file", "")
        detector     = item.get("DetectorName", "secret-exposed")
        verified     = item.get("Verified", False)

        # Secrets verificados como ativos sobem para ERROR; não verificados ficam em WARNING
        severidade = "ERROR" if verified else "WARNING"
        status_txt = "ATIVO (verificado)" if verified else "não verificado"

        vulnerabilidades.append({
            "id":               "",
            "origem":           "trufflehog",
            "arquivo":          arquivo,
            "linha":            0,
            "tipo":             detector.lower().replace(" ", "-"),
            "severidade":       severidade,
            "descricao":        f"Segredo exposto: {detector} ({status_txt})",
            "trecho_do_codigo": "[REDACTED — segredo nunca armazenado]",
            "score":            0,
            "justificativa":    "",
            "verified":         verified,
        })
        contador_trufflehog += 1

    print(f"  → {contador_trufflehog} achados")

except FileNotFoundError:
    print("  ⚠ TruffleHog não encontrado — verifique se está instalado e no PATH")
except Exception as e:
    print(f"  ⚠ Erro ao rodar TruffleHog: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# PARTE 6 — SYFT + GRYPE (SBOM + CVEs em dependências)
# ══════════════════════════════════════════════════════════════════════════════
print("\n[6/11] Rodando Syft (SBOM) + Grype (CVEs)...")
contador_grype = 0

with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_sbom:
    sbom_path = Path(tmp_sbom.name)

with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_grype:
    grype_path = Path(tmp_grype.name)

try:
    # Syft gera o SBOM
    proc_syft = subprocess.run(
        [
            "syft", str(PASTA),
            "-o", f"syft-json={sbom_path}",
            "-q",
        ],
        capture_output=True, text=True
    )

    if proc_syft.returncode != 0 or not sbom_path.exists() or sbom_path.stat().st_size == 0:
        print(f"  ⚠ Syft falhou: {proc_syft.stderr[:200]}")
    else:
        print(f"  SBOM gerado — rodando Grype...")

        # Grype consome o SBOM e busca CVEs
        proc_grype = subprocess.run(
            [
                "grype", f"sbom:{sbom_path}",
                "-o", "json",
                "--file", str(grype_path),
                "-q",
                "--only-fixed",     # só CVEs com fix disponível — reduz ruído
            ],
            capture_output=True, text=True
        )

        if grype_path.exists() and grype_path.stat().st_size > 0:
            saida_grype = json.loads(grype_path.read_text(encoding="utf-8"))

            mapa_sev = {
                "Critical": "ERROR",
                "High":     "ERROR",
                "Medium":   "WARNING",
                "Low":      "INFO",
                "Negligible": "INFO",
                "Unknown":  "INFO",
            }

            for match in saida_grype.get("matches", []):
                vuln      = match.get("vulnerability", {})
                artifact  = match.get("artifact", {})
                cve_id    = vuln.get("id", "")
                pkg_name  = artifact.get("name", "")
                pkg_ver   = artifact.get("version", "")
                sev_orig  = vuln.get("severity", "Unknown")
                fix_vers  = ", ".join(vuln.get("fix", {}).get("versions", [])) or "sem fix"

                # Localiza o arquivo de manifesto onde o pacote foi declarado
                locations = artifact.get("locations", [])
                arquivo_dep = locations[0].get("path", "") if locations else ""

                descricao = (
                    f"{cve_id}: {vuln.get('description', '')[:200]} — "
                    f"{pkg_name} {pkg_ver} (fix: {fix_vers})"
                ).strip(" —")

                vulnerabilidades.append({
                    "id":               "",
                    "origem":           "grype",
                    "arquivo":          arquivo_dep,
                    "linha":            0,
                    "tipo":             "vulnerable-dependency",
                    "severidade":       mapa_sev.get(sev_orig, "INFO"),
                    "descricao":        descricao,
                    "trecho_do_codigo": vuln.get("description", ""),
                    "score":            0,
                    "justificativa":    "",
                    "pkg_name":         pkg_name,
                    "cve_id":           cve_id,
                    "sev_original":     sev_orig,
                })
                contador_grype += 1

    print(f"  → {contador_grype} achados")

except FileNotFoundError as e:
    print(f"  ⚠ Syft ou Grype não encontrado: {e}")
except Exception as e:
    print(f"  ⚠ Erro ao rodar Syft/Grype: {e}")
finally:
    sbom_path.unlink(missing_ok=True)
    grype_path.unlink(missing_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# PARTE 7 — CHECKOV (IaC — Terraform, K8s, CloudFormation)
# ══════════════════════════════════════════════════════════════════════════════
print("\n[7/11] Rodando Checkov (IaC)...")
contador_checkov = 0

with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_checkov:
    checkov_path = Path(tmp_checkov.name)

try:
    proc_checkov = subprocess.run(
        [
            "checkov",
            "--directory", str(PASTA),
            "--output", "json",
            "--output-file", str(checkov_path),
            "--quiet",
            "--compact",
            "--skip-download",      # não baixa políticas externas durante o scan
        ],
        capture_output=True, text=True
    )

    if checkov_path.exists() and checkov_path.stat().st_size > 0:
        raw = checkov_path.read_text(encoding="utf-8").strip()

        # Checkov pode retornar um objeto ou uma lista de objetos (um por framework)
        saida_checkov = json.loads(raw)
        if isinstance(saida_checkov, dict):
            saida_checkov = [saida_checkov]

        mapa_sev_checkov = {
            "HIGH":   "ERROR",
            "MEDIUM": "WARNING",
            "LOW":    "INFO",
        }

        for bloco in saida_checkov:
            failed = bloco.get("results", {}).get("failed_checks", [])
            for check in failed:
                sev_orig = check.get("severity") or "MEDIUM"
                vulnerabilidades.append({
                    "id":               "",
                    "origem":           "checkov",
                    "arquivo":          check.get("repo_file_path", check.get("file_path", "")),
                    "linha":            check.get("file_line_range", [0])[0],
                    "tipo":             check.get("check_id", "iac-misconfiguration").lower(),
                    "severidade":       mapa_sev_checkov.get(sev_orig.upper(), "WARNING"),
                    "descricao":        check.get("check_type", "") + ": " + check.get("check_id", ""),
                    "trecho_do_codigo": json.dumps(check.get("resource", ""), ensure_ascii=False),
                    "score":            0,
                    "justificativa":    "",
                    "guideline":        check.get("guideline", ""),
                })
                contador_checkov += 1

    print(f"  → {contador_checkov} achados")

except FileNotFoundError:
    print("  ⚠ Checkov não encontrado — verifique se está instalado e no PATH")
except json.JSONDecodeError as e:
    print(f"  ⚠ Checkov não retornou JSON válido: {e}")
except Exception as e:
    print(f"  ⚠ Erro ao rodar Checkov: {e}")
finally:
    checkov_path.unlink(missing_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# PARTE 8 — HADOLINT (Dockerfile)
# ══════════════════════════════════════════════════════════════════════════════
print("\n[8/11] Rodando Hadolint (Dockerfile)...")
contador_hadolint = 0

# Localiza todos os Dockerfiles na pasta
dockerfiles = list(PASTA.rglob("Dockerfile")) + list(PASTA.rglob("Dockerfile.*"))

if not dockerfiles:
    print("  Nenhum Dockerfile encontrado — pulando.")
else:
    for dockerfile in dockerfiles:
        try:
            proc_hadolint = subprocess.run(
                ["hadolint", "--format", "json", str(dockerfile)],
                capture_output=True, text=True
            )

            saida_raw = proc_hadolint.stdout.strip()
            if not saida_raw:
                continue

            achados_hadolint = json.loads(saida_raw)

            mapa_sev_hadolint = {
                "error":   "ERROR",
                "warning": "WARNING",
                "info":    "INFO",
                "style":   "INFO",
            }

            for item in achados_hadolint:
                vulnerabilidades.append({
                    "id":               "",
                    "origem":           "hadolint",
                    "arquivo":          str(dockerfile.relative_to(PASTA)),
                    "linha":            item.get("line", 0),
                    "tipo":             item.get("code", "dockerfile-issue").lower(),
                    "severidade":       mapa_sev_hadolint.get(item.get("level", "warning"), "WARNING"),
                    "descricao":        item.get("message", ""),
                    "trecho_do_codigo": "",
                    "score":            0,
                    "justificativa":    "",
                })
                contador_hadolint += 1

        except json.JSONDecodeError:
            print(f"  ⚠ Hadolint não retornou JSON para {dockerfile.name}")
        except FileNotFoundError:
            print("  ⚠ Hadolint não encontrado — verifique se está instalado e no PATH")
            break
        except Exception as e:
            print(f"  ⚠ Erro ao rodar Hadolint em {dockerfile.name}: {e}")

    print(f"  → {contador_hadolint} achados em {len(dockerfiles)} Dockerfile(s)")


# ══════════════════════════════════════════════════════════════════════════════
# PARTE 9 — NUCLEI (CVEs e misconfigs via URL ativa)
# ══════════════════════════════════════════════════════════════════════════════
print("\n[9/11] Nuclei (CVEs + misconfigs)...")
contador_nuclei = 0

if url_alvo:
    print(f"  URL alvo: {url_alvo}")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_nuclei:
        nuclei_path = Path(tmp_nuclei.name)

    try:
        cmd_nuclei = [
            "nuclei",
            "-u", url_alvo,
            "-je", str(nuclei_path),    # JSON exportado por linha
            "-silent",
            "-severity", "medium,high,critical",
            "-tags", "cve,misconfig,exposure",
            "-rate-limit", "50",        # requisições por segundo — evita sobrecarga
            "-timeout", "10",
        ]
        if NUCLEI_TEMPLATES:
            cmd_nuclei += ["-t", NUCLEI_TEMPLATES]

        proc_nuclei = subprocess.run(
            cmd_nuclei,
            capture_output=True, text=True, timeout=600
        )

        if nuclei_path.exists() and nuclei_path.stat().st_size > 0:
            for linha in nuclei_path.read_text(encoding="utf-8").splitlines():
                linha = linha.strip()
                if not linha:
                    continue
                try:
                    item = json.loads(linha)
                except json.JSONDecodeError:
                    continue

                # info pode vir como dict ou lista em alguns templates — normaliza
                info_raw  = item.get("info", {})
                info_tmpl = info_raw if isinstance(info_raw, dict) else {}
                sev_orig  = info_tmpl.get("severity", "medium")
                if not isinstance(sev_orig, str):
                    sev_orig = "medium"
                sev_orig = sev_orig.lower()
                mapa_sev_nuclei = {
                    "critical": "ERROR",
                    "high":     "ERROR",
                    "medium":   "WARNING",
                    "low":      "INFO",
                    "info":     "INFO",
                }

                vulnerabilidades.append({
                    "id":               "",
                    "origem":           "nuclei",
                    "arquivo":          item.get("matched-at", url_alvo),
                    "linha":            0,
                    "tipo":             item.get("template-id", "nuclei-finding").lower(),
                    "severidade":       mapa_sev_nuclei.get(sev_orig, "WARNING"),
                    "descricao":        info_tmpl.get("name", "") + ": " + info_tmpl.get("description", ""),
                    "trecho_do_codigo": item.get("extracted-results", [""])[0] if isinstance(item.get("extracted-results"), list) and item.get("extracted-results") else "",
                    "score":            0,
                    "justificativa":    "",
                    "cve_id":           (info_tmpl.get("classification") or {}).get("cve-id", [""])[0] if isinstance((info_tmpl.get("classification") or {}), dict) and (info_tmpl.get("classification") or {}).get("cve-id") else "",
                })
                contador_nuclei += 1

        print(f"  → {contador_nuclei} achados")

    except subprocess.TimeoutExpired:
        print("  ⚠ Nuclei excedeu 10 min — coletando achados disponíveis")
    except FileNotFoundError:
        print("  ⚠ Nuclei não encontrado — verifique se está instalado e no PATH")
    except Exception as e:
        print(f"  ⚠ Erro ao rodar Nuclei: {e}")
    finally:
        nuclei_path.unlink(missing_ok=True)
else:
    print("  Sem URL no config — pulando Nuclei.")


# ══════════════════════════════════════════════════════════════════════════════
# PARTE 10 — SPECTRAL (OpenAPI, AsyncAPI, GraphQL)
# ══════════════════════════════════════════════════════════════════════════════
print("\n[10/11] Rodando Spectral (schemas de API)...")
contador_spectral = 0

# Localiza schemas de API na pasta
EXTENSOES_API = {".yaml", ".yml", ".json"}
NOMES_API     = {"openapi", "swagger", "asyncapi", "graphql", "schema", "api"}

schemas_api = [
    f for f in PASTA.rglob("*")
    if f.suffix.lower() in EXTENSOES_API
    and any(nome in f.name.lower() for nome in NOMES_API)
    and f.stat().st_size > 0
]

if not schemas_api:
    print("  Nenhum schema de API encontrado — pulando.")
else:
    for schema in schemas_api:
        try:
            proc_spectral = subprocess.run(
                [
                    "spectral", "lint", str(schema),
                    "--format", "json",
                    "--ruleset", SPECTRAL_RULESET,
                    "--quiet",
                ],
                capture_output=True, text=True, timeout=60
            )

            saida_raw = proc_spectral.stdout.strip()
            if not saida_raw:
                continue

            achados_spectral = json.loads(saida_raw)

            mapa_sev_spectral = {
                0: "ERROR",    # error
                1: "WARNING",  # warn
                2: "INFO",     # info
                3: "INFO",     # hint
            }

            for item in achados_spectral:
                sev_code = item.get("severity", 1)
                vulnerabilidades.append({
                    "id":               "",
                    "origem":           "spectral",
                    "arquivo":          str(schema.relative_to(PASTA)),
                    "linha":            item.get("range", {}).get("start", {}).get("line", 0),
                    "tipo":             item.get("code", "api-schema-issue"),
                    "severidade":       mapa_sev_spectral.get(sev_code, "WARNING"),
                    "descricao":        item.get("message", ""),
                    "trecho_do_codigo": " > ".join(str(p) for p in item.get("path", [])),
                    "score":            0,
                    "justificativa":    "",
                })
                contador_spectral += 1

        except subprocess.TimeoutExpired:
            print(f"  ⚠ Spectral timeout em {schema.name}")
        except json.JSONDecodeError:
            print(f"  ⚠ Spectral não retornou JSON para {schema.name}")
        except FileNotFoundError:
            print("  ⚠ Spectral não encontrado — verifique se está instalado e no PATH")
            break
        except Exception as e:
            print(f"  ⚠ Erro ao rodar Spectral em {schema.name}: {e}")

    print(f"  → {contador_spectral} achados em {len(schemas_api)} schema(s)")


# ══════════════════════════════════════════════════════════════════════════════
# FINALIZAÇÃO — numera IDs e escreve o JSON
# ══════════════════════════════════════════════════════════════════════════════
for i, v in enumerate(vulnerabilidades):
    v["id"] = f"vuln-{i+1:03d}"

total = len(vulnerabilidades)

# ── Contadores por origem ─────────────────────────────────────────────────────
def conta(origem): return sum(1 for v in vulnerabilidades if v["origem"] == origem)

print(f"\n[11/11] Finalizando...")
print(f"\n  Total combinado: {total} vulnerabilidades")
print(f"    Semgrep:     {conta('semgrep')}")
print(f"    ZAP:         {conta('zap')}")
print(f"    Gitleaks:    {conta('gitleaks')}")
print(f"    TruffleHog:  {conta('trufflehog')}")
print(f"    Trivy:       {conta('trivy')}")
print(f"    Grype:       {conta('grype')}")
print(f"    Checkov:     {conta('checkov')}")
print(f"    Hadolint:    {conta('hadolint')}")
print(f"    Nuclei:      {conta('nuclei')}")
print(f"    Spectral:    {conta('spectral')}")

resultado_final = {
    "analisado_em":         datetime.now().isoformat(),
    "total_encontrado":     total,
    "origem_semgrep":       conta("semgrep"),
    "origem_zap":           conta("zap"),
    "origem_gitleaks":      conta("gitleaks"),
    "origem_trufflehog":    conta("trufflehog"),
    "origem_trivy":         conta("trivy"),
    "origem_grype":         conta("grype"),
    "origem_checkov":       conta("checkov"),
    "origem_hadolint":      conta("hadolint"),
    "origem_nuclei":        conta("nuclei"),
    "origem_spectral":      conta("spectral"),
    "vulnerabilidades":     vulnerabilidades,
}

ARQUIVO_SAIDA.parent.mkdir(parents=True, exist_ok=True)
ARQUIVO_SAIDA.write_text(
    json.dumps(resultado_final, indent=2, ensure_ascii=False),
    encoding="utf-8"
)
print(f"\nResultado escrito em: {ARQUIVO_SAIDA}")
