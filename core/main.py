"""
PhantomFix — Core
Recebe o .zip do cliente, extrai numa pasta temporária, aciona o scanner.py,
aciona o analyser.py (Groq), aciona o Ghost, e salva tudo em resultados/{protocolo}/.
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
SCANNER_PATH    = os.getenv("SCANNER_PATH",    "../data-control/scanner.py")
ANALYSER_PATH   = os.getenv("ANALYSER_PATH",   "../analyser/analyser.py")
SCANNER_PYTHON  = os.getenv("SCANNER_PYTHON",  "python3")
SCANNER_TIMEOUT = int(os.getenv("SCANNER_TIMEOUT", "7200"))

GHOST_URL       = os.getenv("GHOST_URL", "http://localhost:8002/corrigir")

# Pasta onde ficam salvos os resultados permanentes por protocolo
RESULTADOS_DIR  = Path(os.getenv("RESULTADOS_DIR", "../resultados"))
RESULTADOS_DIR.mkdir(parents=True, exist_ok=True)

# Pasta temporária dos jobs (extraída e limpa ao final)
JOBS_DIR = Path(os.getenv("JOBS_DIR", "./jobs"))
JOBS_DIR.mkdir(exist_ok=True)

# ── Estado dos jobs em memória ────────────────────────────────────────────────
_status_jobs: dict[str, dict] = {}
_ultimo_resultado: dict | None = None
_ultimo_protocolo: str | None = None

def carregar_ultimo_resultado_do_disco():
    global _ultimo_resultado, _ultimo_protocolo
    if not RESULTADOS_DIR.exists():
        return
    pastas = sorted(
        (p for p in RESULTADOS_DIR.iterdir() if p.is_dir()),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    for pasta in pastas:
        relatorio = pasta / "relatorio.json"
        if relatorio.exists():
            _ultimo_resultado = json.loads(relatorio.read_text(encoding="utf-8"))
            _ultimo_protocolo = pasta.name
            print(f"[Core] Resultado restaurado: {pasta.name}")
            return


carregar_ultimo_resultado_do_disco()

def carregar_resultado(protocolo: str | None = None) -> dict | None:
    global _ultimo_resultado, _ultimo_protocolo

    # Se pedir um protocolo específico, lê do disco
    if protocolo:
        path = RESULTADOS_DIR / protocolo / "relatorio.json"
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return None

    # Sem protocolo, retorna o último em memória
    if _ultimo_resultado:
        return _ultimo_resultado
    return None


def salvar_resultado(protocolo: str, dados: dict):
    global _ultimo_resultado, _ultimo_protocolo
    _ultimo_resultado  = dados
    _ultimo_protocolo  = protocolo

    pasta = RESULTADOS_DIR / protocolo
    pasta.mkdir(parents=True, exist_ok=True)

    (pasta / "relatorio.json").write_text(
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

    pasta_job = JOBS_DIR / protocolo
    pasta_job.mkdir(parents=True, exist_ok=True)

    zip_path = pasta_job / "repositorio.zip"
    conteudo = await arquivo.read()
    zip_path.write_bytes(conteudo)

    print(f"[{protocolo}] Recebido: {repositorio} ({len(conteudo) / 1024:.1f} KB)")

    background.add_task(pipeline_completo, protocolo, pasta_job, zip_path, repositorio)

    return {"status": "recebido", "protocolo": protocolo, "repositorio": repositorio}


@app.get("/scan/{protocolo}/status")
def status_scan(protocolo: str):
    job = _status_jobs.get(protocolo)
    if not job:
        raise HTTPException(status_code=404, detail="Protocolo não encontrado")
    return job


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE
# ══════════════════════════════════════════════════════════════════════════════
def pipeline_completo(protocolo: str, pasta_job: Path, zip_path: Path, repositorio: str):
    # Pasta permanente deste protocolo em resultados/
    pasta_resultado = RESULTADOS_DIR / protocolo
    pasta_resultado.mkdir(parents=True, exist_ok=True)

    try:
        # ── 1. Extrai o .zip ─────────────────────────────────────────────────
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

        # ── 2. Scanner (SAST + DAST) ─────────────────────────────────────────
        _status_jobs[protocolo]["status"] = "escaneando"
        arquivo_findings = pasta_resultado / "findings.json"  # salvo em resultados/

        print(f"[{protocolo}] Acionando scanner.py...")
        proc_scanner = subprocess.run(
            [SCANNER_PYTHON, SCANNER_PATH, str(pasta_extraida), str(arquivo_findings)],
            capture_output=True, text=True, timeout=SCANNER_TIMEOUT
        )

        print(f"[{protocolo}] --- scanner.py ---")
        print(proc_scanner.stdout)
        if proc_scanner.stderr:
            print(proc_scanner.stderr)

        if proc_scanner.returncode != 0:
            _status_jobs[protocolo]["status"] = "erro"
            _status_jobs[protocolo]["detalhe"] = f"scanner.py falhou: {proc_scanner.stderr[-500:]}"
            return

        if not arquivo_findings.exists():
            _status_jobs[protocolo]["status"] = "erro"
            _status_jobs[protocolo]["detalhe"] = "scanner.py não gerou findings.json"
            return

        achados = json.loads(arquivo_findings.read_text(encoding="utf-8"))
        vulnerabilidades = achados.get("vulnerabilidades", [])
        print(f"[{protocolo}] {len(vulnerabilidades)} vulnerabilidades encontradas")

        # ── 3. Analyser (Groq) ───────────────────────────────────────────────
        _status_jobs[protocolo]["status"] = "analisando"
        arquivo_enriquecido = pasta_resultado / "resultado_enriquecido.json"

        print(f"[{protocolo}] Acionando analyser.py...")
        proc_analyser = subprocess.run(
            [SCANNER_PYTHON, ANALYSER_PATH, str(arquivo_findings), str(arquivo_enriquecido)],
            capture_output=True, text=True, timeout=SCANNER_TIMEOUT
        )

        print(f"[{protocolo}] --- analyser.py ---")
        print(proc_analyser.stdout)
        if proc_analyser.stderr:
            print(proc_analyser.stderr)

        if proc_analyser.returncode == 0 and arquivo_enriquecido.exists():
            achados_finais   = json.loads(arquivo_enriquecido.read_text(encoding="utf-8"))
            vulnerabilidades = achados_finais.get("vulnerabilidades", [])
            print(f"[{protocolo}] Analyser enriqueceu {len(vulnerabilidades)} vulnerabilidades")
        else:
            print(f"[{protocolo}] ⚠ Analyser falhou — usando findings brutos")
            achados_finais = achados

        # ── 4. Salva versão inicial do relatório ─────────────────────────────
        resultado = {
            "protocolo":        protocolo,
            "repositorio":      repositorio,
            "analisado_em":     achados.get("analisado_em"),
            "processado_em":    datetime.now().isoformat(),
            "total_encontrado": achados.get("total_encontrado", len(vulnerabilidades)),
            "origem_semgrep":   achados.get("origem_semgrep", 0),
            "origem_zap":       achados.get("origem_zap", 0),
            "analisado_por_ia": achados_finais.get("analisado_por_agente", False),
            "modelo_ia":        achados_finais.get("modelo_ia", ""),
            "status":           "gerando_correcoes",
            "vulnerabilidades": vulnerabilidades,
        }
        salvar_resultado(protocolo, resultado)
        _status_jobs[protocolo]["status"] = "priorizado"

        # ── 5. Ghost (correções) ─────────────────────────────────────────────
        _status_jobs[protocolo]["status"] = "corrigindo"
        print(f"[{protocolo}] Acionando Ghost para {len(vulnerabilidades)} vulnerabilidades...")
        asyncio.run(processar_com_ghost(vulnerabilidades))

        # ── 6. Relatório final ───────────────────────────────────────────────
        resultado["status"]           = "concluido"
        resultado["corrigido_em"]     = datetime.now().isoformat()
        resultado["vulnerabilidades"] = vulnerabilidades
        salvar_resultado(protocolo, resultado)

        _status_jobs[protocolo]["status"] = "concluido"
        print(f"[{protocolo}] Pipeline concluído → resultados/{protocolo}/")

    except subprocess.TimeoutExpired:
        _status_jobs[protocolo]["status"] = "erro"
        _status_jobs[protocolo]["detalhe"] = f"Timeout após {SCANNER_TIMEOUT}s"

    except Exception as e:
        _status_jobs[protocolo]["status"] = "erro"
        _status_jobs[protocolo]["detalhe"] = str(e)
        print(f"[{protocolo}] Erro: {e}")

    finally:
        # Limpa só a pasta temporária do job — resultados/ fica intacta
        shutil.rmtree(pasta_job, ignore_errors=True)
        print(f"[{protocolo}] Pasta temporária limpa")


# ── Ghost ─────────────────────────────────────────────────────────────────────
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
        "justificativa":    vuln.get("justificativa", ""),
        "categoria":        vuln.get("categoria", ""),
        "recomendacao":     vuln.get("recomendacao", ""),
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
    return {"status": "PhantomFix Core funcionando", "versao": "0.4.0"}


@app.get("/vulnerabilidades")
def listar_vulnerabilidades(
    protocolo:  Optional[str] = None,
    severidade: Optional[str] = None,
    origem:     Optional[str] = None,
    score_min:  Optional[int] = None,
):
    resultado = carregar_resultado(protocolo)
    if not resultado:
        raise HTTPException(status_code=404, detail="Nenhuma análise disponível ainda")

    vulns = resultado.get("vulnerabilidades", [])

    if severidade:
        vulns = [v for v in vulns if v.get("severidade", "").upper() == severidade.upper()]
    if origem:
        vulns = [v for v in vulns if v.get("origem", "").lower() == origem.lower()]
    if score_min is not None:
        vulns = [v for v in vulns if v.get("score") and float(v["score"]) >= score_min]

    return {
        **{k: v for k, v in resultado.items() if k != "vulnerabilidades"},
        "exibindo":         len(vulns),
        "vulnerabilidades": vulns,
    }


@app.get("/relatorio")
def relatorio_completo(protocolo: Optional[str] = None):
    resultado = carregar_resultado(protocolo)
    if not resultado:
        raise HTTPException(status_code=404, detail="Nenhuma análise disponível ainda")
    return resultado


@app.get("/resultados")
def listar_resultados():
    """Lista todos os protocolos disponíveis em resultados/."""
    if not RESULTADOS_DIR.exists():
        return {"resultados": []}
    protocolos = [
        {
            "protocolo": p.name,
            "relatorio":  (p / "relatorio.json").exists(),
            "findings":   (p / "findings.json").exists(),
            "enriquecido": (p / "resultado_enriquecido.json").exists(),
        }
        for p in sorted(RESULTADOS_DIR.iterdir()) if p.is_dir()
    ]
    return {"resultados": protocolos}


@app.get("/status")
def status_analise():
    resultado = carregar_resultado()
    if not resultado:
        return {"status": "ocioso", "detalhe": "Nenhuma análise executada ainda"}
    return {
        "status":       resultado.get("status", "desconhecido"),
        "protocolo":    resultado.get("protocolo"),
        "repositorio":  resultado.get("repositorio"),
        "analisado_em": resultado.get("analisado_em"),
        "corrigido_em": resultado.get("corrigido_em"),
        "modelo_ia":    resultado.get("modelo_ia", ""),
    }
