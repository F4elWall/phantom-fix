import subprocess
import json
from datetime import datetime
import requests

# ================================================
# CONFIGURAÇÃO — ⚠️ TROQUE SEU-NOME AQUI TAMBÉM ⚠️
# ================================================
CAMINHO_JUICE_SHOP = r"C:\Users\berac\juice-shop"
# ================================================

vulnerabilidades = []

# ============================================================
# PARTE 1 — SEMGREP (análise estática: lê o código)
# ============================================================
print("Rodando Semgrep...")
resultado_bruto = subprocess.run(
    ["semgrep","--config=p/javascript","--json","--quiet",
     CAMINHO_JUICE_SHOP],
    capture_output=True, text=True
)

try:
    saida_semgrep = json.loads(resultado_bruto.stdout)
except json.JSONDecodeError:
    print("Erro ao ler resultado do Semgrep. Verifique o caminho.")
    print(resultado_bruto.stderr)
    exit(1)

for item in saida_semgrep.get("results", []):
    vuln = {
        "id": "",
        "origem": "semgrep",
        "arquivo": item.get("path",""),
        "linha": item.get("start",{}).get("line",0),
        "tipo": item.get("check_id","").split(".")[-1],
        "severidade": item.get("extra",{}).get("severity","DESCONHECIDA"),
        "descricao": item.get("extra",{}).get("message",""),
        "trecho_do_codigo": item.get("extra",{}).get("lines","").strip(),
        "score": 0,
        "justificativa": ""
    }
    vulnerabilidades.append(vuln)

print(f"Semgrep: {len(vulnerabilidades)} vulnerabilidades encontradas.")

# ============================================================
# PARTE 2 — ZAP (análise dinâmica: ataca a aplicação rodando)
# ============================================================
def converter_risco_zap(riskdesc):
    """Converte o nível de risco do ZAP para o mesmo padrão do Semgrep"""
    r = riskdesc.lower()
    if "high" in r:   return "ERROR"
    if "medium" in r: return "WARNING"
    return "INFO"

print("Lendo relatório do ZAP...")
try:
    with open("zap_report.json","r",encoding="utf-8") as f:
        zap_data = json.load(f)

    sites = zap_data.get("site",[])
    alertas = sites[0].get("alerts",[]) if sites else []
    contador_zap = 0

    for alerta in alertas:
        instancias = alerta.get("instances",[{}])
        uri = instancias[0].get("uri","") if instancias else ""
        vuln = {
            "id": "",
            "origem": "zap",
            "arquivo": uri,
            "linha": 0,
            "tipo": alerta.get("name","desconhecido").lower().replace(" ","-"),
            "severidade": converter_risco_zap(alerta.get("riskdesc","")),
            "descricao": alerta.get("desc",""),
            "trecho_do_codigo": alerta.get("solution",""),
            "score": 0,
            "justificativa": ""
        }
        vulnerabilidades.append(vuln)
        contador_zap += 1

    print(f"ZAP: {contador_zap} vulnerabilidades encontradas.")

except FileNotFoundError:
    print("zap_report.json não encontrado — pulando análise dinâmica.")
    print("Execute o ZAP primeiro (passo 6) e rode este script novamente.")

# Numera todos os IDs em sequência
for i, v in enumerate(vulnerabilidades):
    v["id"] = f"vuln-{i+1:03d}"

print(f"Total combinado: {len(vulnerabilidades)} vulnerabilidades.")

# ============================================================
# PARTE 3 — ANALYSER (phi3:mini pontua cada vulnerabilidade)
# ============================================================
print("Iniciando análise de prioridade com IA...")
try:
    import ollama
    for vuln in vulnerabilidades:
        origem_desc = "análise estática de código" if vuln["origem"] == "semgrep" \
                      else "teste dinâmico da aplicação rodando"
        prompt = f"""Você é especialista em segurança. Analise e atribua score 0-10.
Origem: {vuln['origem']} ({origem_desc})
Tipo: {vuln['tipo']}
Severidade: {vuln['severidade']}
Descrição: {vuln['descricao']}
Contexto: {vuln['trecho_do_codigo']}

Responda APENAS neste JSON (sem mais nada):
{{"score": 8, "justificativa": "motivo curto aqui"}}"""

        resp = ollama.chat(model="phi3:mini",
                           messages=[{"role":"user","content":prompt}])
        try:
            r = json.loads(resp["message"]["content"])
            vuln["score"] = r.get("score", 0)
            vuln["justificativa"] = r.get("justificativa","")
        except:
            vuln["score"] = 5
            vuln["justificativa"] = "Análise automática indisponível"

    print("Priorização concluída.")
except ImportError:
    print("Ollama não instalado — score zerado. Instala: pip install ollama")

# Ordena do mais crítico ao menos crítico
vulnerabilidades.sort(key=lambda x: x["score"], reverse=True)

# ============================================================
# SALVAR E ENVIAR AO CORE
# ============================================================
qtd_semgrep = sum(1 for v in vulnerabilidades if v["origem"] == "semgrep")
qtd_zap     = sum(1 for v in vulnerabilidades if v["origem"] == "zap")

resultado_final = {
    "repositorio": "juice-shop",
    "analisado_em": datetime.now().isoformat(),
    "total_encontrado": len(vulnerabilidades),
    "origem_semgrep": qtd_semgrep,
    "origem_zap": qtd_zap,
    "vulnerabilidades": vulnerabilidades
}

# Salva localmente para backup
with open("findings.json", "w", encoding="utf-8") as f:
    json.dump(resultado_final, f, indent=2, ensure_ascii=False)

# Envia para o seu Core via Ngrok
url_core = "https://doodle-hardening-contest.ngrok-free.dev/ingest"
try:
    print(f"\nEnviando para o Core ({url_core})...")
    resp = requests.post(url_core, json=resultado_final, timeout=120)
    resp.raise_for_status()
    print("✅ Sucesso! Dados entregues ao Core.")
except Exception as e:
    print(f"❌ Erro ao enviar para o Core: {e}")

print(f"\nPronto! Relatório processado e enviado.")