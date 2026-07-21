"""
PhantomFix — Core (versão 0.4.0)
Recebe ZIP, extrai, chama Scanner → Analyser → (Ghost futuro) → relatório final.
"""

import json
import os
import shutil
import subprocess
import uuid
import zipfile
import asyncio
import httpx
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="PhantomFix Core", version="0.4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Configuração ──────────────────────────────────────────────────────────────
SCANNER_PATH     = os.getenv("SCANNER_PATH", "../data-control/scanner.py")
ANALYSER_PATH    = os.getenv("ANALYSER_PATH", "../analyser/analyser.py")
SCANNER_PYTHON   = os.getenv("SCANNER_PYTHON", "python3")
SCANNER_TIMEOUT  = int(os.getenv("SCANNER_TIMEOUT", "1800"))

GHOST_URL        = os.getenv("GHOST_URL", "http://localhost:8001/corrigir")
RESULTADO_PATH   = Path(os.getenv("RESULTADO_PATH", "resultado.json"))

JOBS_DIR = Path(os.getenv("JOBS_DIR", "./jobs"))
JOBS_DIR.mkdir(exist_ok=True)

# Estado em memória
_status_jobs: dict[str, dict] = {}
_ultimo_resultado: dict | None = None


def salvar_resultado(dados: dict):
    global _ultimo_resultado
    _ultimo_resultado = dados
    RESULTADO_PATH.write_text(
        json.dumps(dados, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


# ══════════════════════════════════════════════════════════════════════════════
# ROTA PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/scan")
async def receber_zip(
    background: BackgroundTasks,
    arquivo: UploadFile = File(...),
    repositorio: str = Form(...),
):
    protocolo = str(uuid.uuid4())[:8]
    _status_jobs[protocolo] = {"status": "recebido", "repositorio": repositorio}

    pasta_job = JOBS_DIR / protocolo
    pasta_job.mkdir(parents=True, exist_ok=True)

    zip_path = pasta_job / "repositorio.zip"
    conteudo = await arquivo.read()
    zip_path.write_bytes(conteudo)

    print(f"[{protocolo}] Recebido: {repositorio}")

    background.add_task(pipeline_completo, protocolo, pasta_job, zip_path, repositorio)

    return {"status": "recebido", "protocolo": protocolo}


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE
# ══════════════════════════════════════════════════════════════════════════════
def pipeline_completo(protocolo: str, pasta_job: Path, zip_path: Path, repositorio: str):
    try:
        _status_jobs[protocolo]["status"] = "extraindo"
        pasta_extraida = pasta_job / "repo"
        pasta_extraida.mkdir(exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(pasta_extraida)

        # ── Scanner (bruto) ─────────────────────────────────────────────────
        _status_jobs[protocolo]["status"] = "escaneando"
        arquivo_findings = pasta_job / "findings.json"

        subprocess.run(
            [SCANNER_PYTHON, SCANNER_PATH, str(pasta_extraida), str(arquivo_findings)],
            capture_output=True, text=True, timeout=SCANNER_TIMEOUT, check=True
        )

        # ── Analyser Agent ──────────────────────────────────────────────────
        _status_jobs[protocolo]["status"] = "analisando"
        arquivo_enriquecido = pasta_job / "resultado_enriquecido.json"

        analyser_result = subprocess.run(
            [SCANNER_PYTHON, ANALYSER_PATH, str(arquivo_findings)],
            capture_output=True, text=True, timeout=SCANNER_TIMEOUT
        )

        if analyser_result.returncode == 0 and arquivo_enriquecido.exists():
            resultado_final = json.loads(arquivo_enriquecido.read_text(encoding="utf-8"))
        else:
            resultado_final = json.loads(arquivo_findings.read_text(encoding="utf-8"))

        # Salva relatório final FORA da pasta temporária
        salvar_resultado(resultado_final)

        _status_jobs[protocolo]["status"] = "concluido"
        print(f"[{protocolo}] Pipeline concluído com sucesso.")

    except Exception as e:
        _status_jobs[protocolo]["status"] = "erro"
        _status_jobs[protocolo]["detalhe"] = str(e)
        print(f"[{protocolo}] Erro: {e}")

    finally:
        # Limpeza (mantém só o relatório final)
        shutil.rmtree(pasta_job, ignore_errors=True)


# Rotas do Dashboard (mantidas)
@app.get("/")
def raiz():
    return {"status": "PhantomFix Core funcionando", "versao": "0.4.0"}


@app.get("/relatorio")
def relatorio_completo():
    if not RESULTADO_PATH.exists():
        raise HTTPException(status_code=404, detail="Nenhuma análise disponível")
    return json.loads(RESULTADO_PATH.read_text(encoding="utf-8"))


# ... (outras rotas status etc. podem ser mantidas)
