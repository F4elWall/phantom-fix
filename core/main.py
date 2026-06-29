from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import json
import os
import requests

app = FastAPI()

# Permite acesso do Dashboard e Spirit
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

ARQUIVO_RESULTADO = "resultado.json"

# URL do Ghost
URL_GHOST = os.getenv("URL_GHOST", "http://localhost:8001/corrigir")


# ------------------------------------------------
# ROTA 1 - Recebe dados do Data Control
# ------------------------------------------------
@app.post("/ingest")
def receber_vulnerabilidades(dados: dict):

    print(f"Recebido: {dados.get('total_encontrado')} vulnerabilidades")
    print(f"  -> Semgrep: {dados.get('origem_semgrep', 0)}")
    print(f"  -> ZAP     : {dados.get('origem_zap', 0)}")

    # Pega somente as 10 primeiras vulnerabilidades
    top_10 = dados.get("vulnerabilidades", [])[:10]

    print("Enviando para o Ghost...")

    for vuln in top_10:
        try:
            resp = requests.post(URL_GHOST, json=vuln, timeout=120)

            # Gera exceção caso o Ghost retorne erro HTTP
            resp.raise_for_status()

            correcao = resp.json()

            vuln["correcao"] = correcao.get(
                "correcao",
                "Correção indisponível"
            )

            vuln["explicacao"] = correcao.get(
                "explicacao",
                ""
            )

        except Exception as e:
            vuln["correcao"] = "Ghost não disponível ainda"
            vuln["explicacao"] = ""
            print(f"Ghost offline: {e}")

    resultado = {
        "repositorio": dados.get("repositorio"),
        "analisado_em": dados.get("analisado_em"),
        "total_encontrado": dados.get("total_encontrado"),
        "origem_semgrep": dados.get("origem_semgrep", 0),
        "origem_zap": dados.get("origem_zap", 0),
        "vulnerabilidades": top_10,
        "processado_em": datetime.now().isoformat()
    }

    with open(ARQUIVO_RESULTADO, "w", encoding="utf-8") as f:
        json.dump(resultado, f, indent=2, ensure_ascii=False)

    print("Resultado salvo.")

    return {
        "status": "ok",
        "processadas": len(top_10)
    }


# ------------------------------------------------
# ROTA 2 - Dashboard consulta vulnerabilidades
# ------------------------------------------------
@app.get("/vulnerabilidades")
def listar():

    if not os.path.exists(ARQUIVO_RESULTADO):
        return {"erro": "Nenhuma análise disponível ainda"}

    with open(ARQUIVO_RESULTADO, "r", encoding="utf-8") as f:
        return json.load(f)


# ------------------------------------------------
# ROTA 3 - Spirit consulta relatório completo
# ------------------------------------------------
@app.get("/relatorio")
def relatorio():

    if not os.path.exists(ARQUIVO_RESULTADO):
        return {"erro": "Nenhuma análise disponível ainda"}

    with open(ARQUIVO_RESULTADO, "r", encoding="utf-8") as f:
        return json.load(f)


# ------------------------------------------------
# ROTA 4 - Teste
# ------------------------------------------------
@app.get("/")
def raiz():
    return {
        "status": "PhantomFix Core funcionando"
    }