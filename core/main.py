"""
PhantomFix — Core
Recebe o .zip do cliente, extrai numa pasta temporária, aciona o scanner.py
(Data Control) como subprocesso, aguarda o .json de achados, aciona o Ghost
para gerar as correções, e gera o relatorio.json final para o Dashboard.
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

app = FastAPI(title="PhantomFix Core", version="0.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Configuração ──────────────────────────────────────────────────────────────
SCANNER_PATH     = os.getenv("SCANNER_PATH", "../data_control/scanner.py")
SCANNER_PYTHON   = os.getenv("SCANNER_PYTHON", "python3")
SCANNER_TIMEOUT  = int(os.getenv("SCANNER_TIMEOUT", "1800"))  # 30 min — scans + IA podem demorar

GHOST_URL         = os.getenv("GHOST_URL", "http://localhost:8001/corrigir")
RESULTADO_PATH    = Path(os.getenv("RESULTADO_PATH", "resultado.json"))
TOP_N             = int(os.getenv("TOP_N_VULNS", "10"))

JOBS_DIR = Path(os.getenv("JOBS_DIR", "./jobs"))
JOBS_DIR.mkdir(exist_ok=True)

# ── Estado dos jobs em memória — trocar por Redis/DB em produção ─────────────
_status_jobs: dict[str, dict] = {}
_ultimo_resultado: dict | None = None


def carregar_resultado() -> dict | None:
    global _ultimo_resultado
    if _ultimo_resultado:
        return _ultimo_resultado
    if RESULTADO_PATH.exists():
        _ultimo_resultado = json.loads(RESULTADO_PATH.read_text(encoding="utf-8"))
    return _ultimo_resultado


def salvar_resultado(dados: dict):
    global _ultimo_resultado
    _ultimo_resultado = dados
    RESULTADO_PATH.write_text(
        json.dumps(dados, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


# ══════════════════════════════════════════════════════════════════════════════
# ROTA PRINCIPAL — recebe o .zip do cliente
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/scan")
async def receber_zip(
    background: BackgroundTasks,
    arquivo: UploadFile = File(...),
    repositorio: str = Form(...),
):
    protocolo = str(uuid.uuid4())[:8]
    _status_jobs[protocolo] = {"status": "recebido", "repositorio": repositorio}

    # 1. Cria a pasta temporária do job e salva o .zip nela
    pasta_job = JOBS_DIR / protocolo
    pasta_job.mkdir(parents=True, exist_ok=True)

    zip_path = pasta_job / "repositorio.zip"
    conteudo = await arquivo.read()
    zip_path.write_bytes(conteudo)

    print(f"[{protocolo}] Recebido: {repositorio} ({len(conteudo) / 1024:.1f} KB)")

    # Roda o pipeline pesado em background — responde ao cliente imediatamente
    background.add_task(pipeline_completo, protocolo, pasta_job, zip_path, repositorio)

    return {"status": "recebido", "protocolo": protocolo, "repositorio": repositorio}


@app.get("/scan/{protocolo}/status")
def status_scan(protocolo: str):
    job = _status_jobs.get(protocolo)
    if not job:
        raise HTTPException(status_code=404, detail="Protocolo não encontrado")
    return job


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE — extrai, aciona o scanner.py, aciona o Ghost, gera relatorio.json
# ══════════════════════════════════════════════════════════════════════════════
def pipeline_completo(protocolo: str, pasta_job: Path, zip_path: Path, repositorio: str):
    try:
        # ── 1. Extrai o .zip dentro da própria pasta do job ─────────────────
        _status_jobs[protocolo]["status"] = "extraindo"
        pasta_extraida = pasta_job / "repo"
        pasta_extraida.mkdir(exist_ok=True)

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(pasta_extraida)
            print(f"[{protocolo}] Extraído em {pasta_extraida}")
        except zipfile.BadZipFile:
            _status_jobs[protocolo]["status"] = "erro"
            _status_jobs[protocolo]["detalhe"] = "Arquivo .zip inválido ou corrompido"
            return

        # ── 2. Aciona o scanner.py (Data Control) como subprocesso ─────────
        _status_jobs[protocolo]["status"] = "escaneando"
        arquivo_saida = pasta_job / "findings.json"

        print(f"[{protocolo}] Acionando scanner.py...")
        resultado_processo = subprocess.run(
            [SCANNER_PYTHON, SCANNER_PATH, str(pasta_extraida), str(arquivo_saida)],
            capture_output=True, text=True, timeout=SCANNER_TIMEOUT
        )

        if resultado_processo.returncode != 0:
            _status_jobs[protocolo]["status"] = "erro"
            _status_jobs[protocolo]["detalhe"] = f"scanner.py falhou: {resultado_processo.stderr[-500:]}"
            print(f"[{protocolo}] scanner.py falhou:\n{resultado_processo.stderr}")
            return

        if not arquivo_saida.exists():
            _status_jobs[protocolo]["status"] = "erro"
            _status_jobs[protocolo]["detalhe"] = "scanner.py não gerou o arquivo de saída"
            return

        # ── 3. Lê o .json de achados gerado pelo scanner.py ─────────────────
        achados = json.loads(arquivo_saida.read_text(encoding="utf-8"))
        vulnerabilidades = achados.get("vulnerabilidades", [])
        print(f"[{protocolo}] scanner.py retornou {len(vulnerabilidades)} vulnerabilidades")

        top_vulns = vulnerabilidades[:TOP_N]

        # ── 4. Salva versão inicial do relatório (sem correções ainda) ──────
        resultado = {
            "repositorio":      repositorio,
            "analisado_em":     achados.get("analisado_em"),
            "processado_em":    datetime.now().isoformat(),
            "total_encontrado": achados.get("total_encontrado", len(vulnerabilidades)),
            "origem_semgrep":   achados.get("origem_semgrep", 0),
            "origem_zap":       achados.get("origem_zap", 0),
            "status":           "gerando_correcoes",
            "vulnerabilidades": top_vulns,
        }
        salvar_resultado(resultado)
        _status_jobs[protocolo]["status"] = "priorizado"

        # ── 5. Aciona o Ghost para cada vulnerabilidade selecionada ─────────
        _status_jobs[protocolo]["status"] = "corrigindo"
        print(f"[{protocolo}] Acionando o Ghost para {len(top_vulns)} vulnerabilidades...")
        asyncio.run(processar_com_ghost(top_vulns))

        # ── 6. Gera o relatorio.json final ──────────────────────────────────
        resultado["status"]           = "concluido"
        resultado["corrigido_em"]     = datetime.now().isoformat()
        resultado["vulnerabilidades"] = top_vulns
        salvar_resultado(resultado)

        _status_jobs[protocolo]["status"] = "concluido"
        print(f"[{protocolo}] Pipeline concluído. relatorio.json pronto para o Dashboard.")

    except subprocess.TimeoutExpired:
        _status_jobs[protocolo]["status"] = "erro"
        _status_jobs[protocolo]["detalhe"] = f"scanner.py excedeu {SCANNER_TIMEOUT}s"
        print(f"[{protocolo}] scanner.py excedeu o tempo limite")

    except Exception as e:
        _status_jobs[protocolo]["status"] = "erro"
        _status_jobs[protocolo]["detalhe"] = str(e)
        print(f"[{protocolo}] Erro no pipeline: {e}")

    finally:
        # ── 7. Limpeza — remove a pasta do job (zip + repo extraído) ────────
        shutil.rmtree(pasta_job, ignore_errors=True)
        print(f"[{protocolo}] Limpeza concluída")


# ── Ghost: solicita correção para cada vulnerabilidade ───────────────────────
async def solicitar_correcao(vuln: dict, cliente: httpx.AsyncClient) -> dict:
    payload = {
        "id":               vuln.get("id"),
        "arquivo":          vuln.get("arquivo"),
        "linha":            vuln.get("linha"),
        "tipo":             vuln.get("tipo"),
        "severidade":       vuln.get("severidade"),
        "descricao":        vuln.get("descricao"),
        "trecho_do_codigo": vuln.get("trecho_do_codigo", ""),
        "score":            vuln.get("score", 0),
    }
    try:
        resp = await cliente.post(GHOST_URL, json=payload, timeout=120)
        resp.raise_for_status()
        correcao = resp.json()
        return {
            "correcao":   correcao.get("correcao", "Correção indisponível"),
            "explicacao": correcao.get("explicacao", ""),
        }
    except Exception as e:
        print(f"  Ghost indisponível para {vuln.get('id')}: {e}")
        return {"correcao": "Ghost não disponível", "explicacao": ""}


async def processar_com_ghost(vulnerabilidades: list[dict]):
    """Envia vulnerabilidades ao Ghost em paralelo (respeitando limite de concorrência)."""
    semaforo = asyncio.Semaphore(3)

    async def com_semaforo(vuln, cliente):
        async with semaforo:
            return await solicitar_correcao(vuln, cliente)

    async with httpx.AsyncClient() as cliente:
        tarefas   = [com_semaforo(v, cliente) for v in vulnerabilidades]
        correcoes = await asyncio.gather(*tarefas)

    for vuln, correcao in zip(vulnerabilidades, correcoes):
        vuln.update(correcao)


# ══════════════════════════════════════════════════════════════════════════════
# ROTAS DO DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/")
def raiz():
    return {"status": "PhantomFix Core funcionando", "versao": "0.3.0"}


@app.get("/vulnerabilidades")
def listar_vulnerabilidades(
    severidade: Optional[str] = None,
    origem:     Optional[str] = None,
    score_min:  Optional[int] = None,
):
    resultado = carregar_resultado()
    if not resultado:
        raise HTTPException(status_code=404, detail="Nenhuma análise disponível ainda")

    vulns = resultado.get("vulnerabilidades", [])

    if severidade:
        vulns = [v for v in vulns if v.get("severidade", "").upper() == severidade.upper()]
    if origem:
        vulns = [v for v in vulns if v.get("origem", "").lower() == origem.lower()]
    if score_min is not None:
        vulns = [v for v in vulns if v.get("score", 0) >= score_min]

    return {
        **{k: v for k, v in resultado.items() if k != "vulnerabilidades"},
        "exibindo":         len(vulns),
        "vulnerabilidades": vulns,
    }


@app.get("/relatorio")
def relatorio_completo():
    resultado = carregar_resultado()
    if not resultado:
        raise HTTPException(status_code=404, detail="Nenhuma análise disponível ainda")
    return resultado


@app.get("/status")
def status_analise():
    resultado = carregar_resultado()
    if not resultado:
        return {"status": "ocioso", "detalhe": "Nenhuma análise executada ainda"}
    return {
        "status":       resultado.get("status", "desconhecido"),
        "repositorio":  resultado.get("repositorio"),
        "analisado_em": resultado.get("analisado_em"),
        "corrigido_em": resultado.get("corrigido_em"),
    }