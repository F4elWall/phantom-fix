"""
PhantomFix — Core
Recebe o .zip do cliente, extrai numa pasta temporária, aciona o scanner.py,
aciona o analyser.py (Groq), aciona o Ghost, e salva tudo em resultados/{user_id}/{protocolo}/.
"""

import json
import os
import shutil
import subprocess
import sys
import uuid
import zipfile
import asyncio
import httpx
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Adiciona a raiz do projeto ao path para importar database/
sys.path.append(str(Path(__file__).parent.parent))
from database import db

app = FastAPI(title="PhantomFix Core", version="0.6.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inicializa o banco na subida
db.inicializar_banco()

# ── Configuração ──────────────────────────────────────────────────────────────
SCANNER_PATH    = os.getenv("SCANNER_PATH",    "../data-control/scanner.py")
ANALYSER_PATH   = os.getenv("ANALYSER_PATH",   "../analyser/analyser.py")
SCANNER_PYTHON  = os.getenv("SCANNER_PYTHON",  "python3")
SCANNER_TIMEOUT = int(os.getenv("SCANNER_TIMEOUT", "7200"))
GHOST_URL       = os.getenv("GHOST_URL", "http://localhost:8002/corrigir")

RESULTADOS_DIR  = Path(os.getenv("RESULTADOS_DIR", "../resultados"))
RESULTADOS_DIR.mkdir(parents=True, exist_ok=True)

JOBS_DIR = Path(os.getenv("JOBS_DIR", "./jobs"))
JOBS_DIR.mkdir(exist_ok=True)

# ── Estado dos jobs em memória ────────────────────────────────────────────────
_status_jobs: dict[str, dict] = {}


# ── Auth helpers ──────────────────────────────────────────────────────────────

def usuario_autenticado(authorization: str = Header(None)) -> dict:
    """Extrai e valida o session_token do header Authorization: Bearer <token>"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Não autenticado")
    session_token = authorization.split(" ", 1)[1]
    usuario = db.buscar_sessao(session_token)
    if not usuario:
        raise HTTPException(status_code=401, detail="Sessão inválida ou expirada")
    return usuario


# ── Caminhos por usuário ──────────────────────────────────────────────────────

def pasta_resultados_usuario(user_id: int) -> Path:
    p = RESULTADOS_DIR / str(user_id)
    p.mkdir(parents=True, exist_ok=True)
    return p


def carregar_resultado(user_id: int, protocolo: str | None = None) -> dict | None:
    base = pasta_resultados_usuario(user_id)
    if protocolo:
        path = base / protocolo / "relatorio.json"
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return None
    # Sem protocolo: retorna o mais recente deste usuário
    pastas = sorted(
        (p for p in base.iterdir() if p.is_dir()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for pasta in pastas:
        relatorio = pasta / "relatorio.json"
        if relatorio.exists():
            return json.loads(relatorio.read_text(encoding="utf-8"))
    return None


def salvar_resultado(user_id: int, protocolo: str, dados: dict):
    pasta = pasta_resultados_usuario(user_id) / protocolo
    pasta.mkdir(parents=True, exist_ok=True)
    (pasta / "relatorio.json").write_text(
        json.dumps(dados, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# ══════════════════════════════════════════════════════════════════════════════
# ROTAS DE AUTENTICAÇÃO
# ══════════════════════════════════════════════════════════════════════════════

class SignUpBody(BaseModel):
    nome: str
    email: str
    senha: str

class LoginBody(BaseModel):
    email: str
    senha: str

class RegenTokenBody(BaseModel):
    session_token: str

class LinkClientBody(BaseModel):
    token: str


@app.post("/auth/signup")
def signup(body: SignUpBody):
    if not body.nome.strip() or not body.email.strip() or not body.senha.strip():
        raise HTTPException(status_code=400, detail="Preencha todos os campos")
    usuario = db.criar_usuario(body.nome.strip(), body.email.strip().lower(), body.senha)
    if not usuario:
        raise HTTPException(status_code=409, detail="E-mail já cadastrado")
    session_token = db.criar_sessao(usuario["id"])
    return {
        "session_token": session_token,
        "user_id": usuario["id"],
        "nome": usuario["nome"],
        "email": usuario["email"],
        "token": usuario["token"],
        "client_linked": bool(usuario["client_linked"]),
    }


@app.post("/auth/login")
def login(body: LoginBody):
    usuario = db.verificar_senha(body.email.strip().lower(), body.senha)
    if not usuario:
        raise HTTPException(status_code=401, detail="E-mail ou senha incorretos")
    session_token = db.criar_sessao(usuario["id"])
    return {
        "session_token": session_token,
        "user_id": usuario["id"],
        "nome": usuario["nome"],
        "email": usuario["email"],
        "token": usuario["token"],
        "client_linked": bool(usuario["client_linked"]),
    }


@app.post("/auth/logout")
def logout(usuario: dict = Depends(usuario_autenticado), authorization: str = Header(None)):
    session_token = authorization.split(" ", 1)[1]
    db.deletar_sessao(session_token)
    return {"ok": True}


@app.get("/auth/me")
def me(usuario: dict = Depends(usuario_autenticado)):
    return {
        "user_id": usuario["id"],
        "nome": usuario["nome"],
        "email": usuario["email"],
        "token": usuario["token"],
        "client_linked": bool(usuario["client_linked"]),
    }


@app.post("/auth/regen-token")
def regen_token(usuario: dict = Depends(usuario_autenticado)):
    novo_token = db.regenerar_token(usuario["id"])
    return {"token": novo_token, "client_linked": False}


@app.get("/auth/check-link")
def check_link(usuario: dict = Depends(usuario_autenticado)):
    """Frontend consulta se o client já foi vinculado."""
    vinculado = db.verificar_client_vinculado(usuario["id"])
    return {"client_linked": vinculado}


@app.post("/auth/link-client")
def link_client(body: LinkClientBody):
    """Chamado pelo executável (.exe) para vincular o token."""
    ok = db.marcar_client_vinculado(body.token)
    if not ok:
        raise HTTPException(status_code=404, detail="Token não encontrado")
    return {"ok": True, "mensagem": "Client vinculado com sucesso"}


@app.get("/auth/me-by-token")
def me_by_token(token: str):
    """Chamado pelo executável para puxar o nome da conta após vincular."""
    usuario = db.buscar_usuario_por_token(token)
    if not usuario:
        raise HTTPException(status_code=404, detail="Token não encontrado")
    return {"nome": usuario["nome"], "email": usuario["email"]}


# ══════════════════════════════════════════════════════════════════════════════
# ROTA PRINCIPAL — recebe o .zip do cliente (autenticado por token)
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/scan")
async def receber_zip(
    background: BackgroundTasks,
    arquivo: UploadFile = File(...),
    repositorio: str = Form(...),
    token: str = Form(...),
):
    # Valida o token e extrai o user_id
    usuario = db.buscar_usuario_por_token(token)
    if not usuario:
        raise HTTPException(status_code=403, detail="Token inválido")

    user_id = usuario["id"]
    protocolo = str(uuid.uuid4())[:8]
    _status_jobs[protocolo] = {
        "status": "recebido",
        "repositorio": repositorio,
        "user_id": user_id,
    }

    pasta_job = JOBS_DIR / str(user_id) / protocolo
    pasta_job.mkdir(parents=True, exist_ok=True)

    zip_path = pasta_job / "repositorio.zip"
    conteudo = await arquivo.read()
    zip_path.write_bytes(conteudo)

    print(f"[{protocolo}] user={user_id} repo={repositorio} ({len(conteudo)/1024:.1f} KB)")

    background.add_task(pipeline_completo, user_id, protocolo, pasta_job, zip_path, repositorio)

    return {"status": "recebido", "protocolo": protocolo, "repositorio": repositorio}


# FIX v0.6.0 — Bug 1: /scan/ativo deve vir ANTES de /scan/{protocolo}/status.
# O FastAPI resolve rotas na ordem de registro. Com a ordem anterior,
# "ativo" era capturado como valor de {protocolo}, e scan_ativo nunca era chamado.

@app.get("/scan/ativo")
def scan_ativo(usuario: dict = Depends(usuario_autenticado)):
    for protocolo, job in _status_jobs.items():
        if job.get("user_id") == usuario["id"] and job.get("status") not in ["concluido", "erro"]:
            return {"protocolo": protocolo, **job}
    return None

@app.get("/scan/{protocolo}/status")
def status_scan(protocolo: str, usuario: dict = Depends(usuario_autenticado)):
    job = _status_jobs.get(protocolo)
    if not job:
        raise HTTPException(status_code=404, detail="Protocolo não encontrado")
    if job.get("user_id") != usuario["id"]:
        raise HTTPException(status_code=403, detail="Acesso negado")
    return job


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE
# ══════════════════════════════════════════════════════════════════════════════
def pipeline_completo(user_id: int, protocolo: str, pasta_job: Path, zip_path: Path, repositorio: str):
    pasta_resultado = pasta_resultados_usuario(user_id) / protocolo
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
        arquivo_findings = pasta_resultado / "findings.json"

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

        # ── 3. Analyser ───────────────────────────────────────────────────────
        _status_jobs[protocolo]["status"] = "analisando"
        arquivo_enriquecido = pasta_resultado / "resultado_enriquecido.json"

        # FIX v0.6.0 — Bug 2: passa PASTA_REPO via env para que o Analyser
        # consiga fazer a correlação Trivy × imports no código-fonte.
        # Sem isso, correlacionar_trivy_imports() nunca acha o repositório
        # e sempre retorna 0 findings confirmados em uso.
        env_analyser = {**os.environ, "PASTA_REPO": str(pasta_extraida)}

        print(f"[{protocolo}] Acionando analyser.py (PASTA_REPO={pasta_extraida})...")
        proc_analyser = subprocess.run(
            [SCANNER_PYTHON, ANALYSER_PATH, str(arquivo_findings), str(arquivo_enriquecido)],
            capture_output=True, text=True, timeout=SCANNER_TIMEOUT,
            env=env_analyser,
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
            "user_id":          user_id,
            "repositorio":      repositorio,
            "analisado_em":     achados.get("analisado_em"),
            "processado_em":    datetime.now(timezone.utc).isoformat(),
            "total_encontrado": achados.get("total_encontrado", len(vulnerabilidades)),
            "origem_semgrep":   achados.get("origem_semgrep", 0),
            "origem_zap":       achados.get("origem_zap", 0),
            "origem_gitleaks":  achados.get("origem_gitleaks", 0),
            "origem_trivy":     achados.get("origem_trivy", 0),
            "analisado_por_ia": achados_finais.get("analisado_por_agente", False),
            "modelo_ia":        achados_finais.get("modelo_ia", ""),
            "status":           "gerando_correcoes",
            "vulnerabilidades": vulnerabilidades,
        }
        salvar_resultado(user_id, protocolo, resultado)
        _status_jobs[protocolo]["status"] = "priorizado"

        # ── 5. Ghost (correções) ─────────────────────────────────────────────
        _status_jobs[protocolo]["status"] = "corrigindo"
        print(f"[{protocolo}] Acionando Ghost para {len(vulnerabilidades)} vulnerabilidades...")
        asyncio.run(processar_com_ghost(vulnerabilidades))

        # ── 6. Relatório final ───────────────────────────────────────────────
        resultado["status"]           = "concluido"
        resultado["corrigido_em"]     = datetime.now(timezone.utc).isoformat()
        resultado["vulnerabilidades"] = vulnerabilidades
        salvar_resultado(user_id, protocolo, resultado)

        _status_jobs[protocolo]["status"] = "concluido"
        print(f"[{protocolo}] Pipeline concluído → resultados/{user_id}/{protocolo}/")

    except subprocess.TimeoutExpired:
        _status_jobs[protocolo]["status"] = "erro"
        _status_jobs[protocolo]["detalhe"] = f"Timeout após {SCANNER_TIMEOUT}s"

    except Exception as e:
        _status_jobs[protocolo]["status"] = "erro"
        _status_jobs[protocolo]["detalhe"] = str(e)
        print(f"[{protocolo}] Erro: {e}")

    finally:
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
            await asyncio.sleep(1)
            return await solicitar_correcao(vuln, cliente)

    async with httpx.AsyncClient() as cliente:
        tarefas   = [com_semaforo(v, cliente) for v in vulnerabilidades]
        correcoes = await asyncio.gather(*tarefas)

    for vuln, correcao in zip(vulnerabilidades, correcoes):
        vuln.update(correcao)


# ══════════════════════════════════════════════════════════════════════════════
# ROTAS DO DASHBOARD (protegidas por sessão)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/")
def raiz():
    return {"status": "PhantomFix Core funcionando", "versao": "0.6.0"}


@app.get("/vulnerabilidades")
def listar_vulnerabilidades(
    protocolo:  Optional[str] = None,
    severidade: Optional[str] = None,
    origem:     Optional[str] = None,
    score_min:  Optional[int] = None,
    usuario:    dict = Depends(usuario_autenticado),
):
    resultado = carregar_resultado(usuario["id"], protocolo)
    if not resultado:
        raise HTTPException(status_code=404, detail="Nenhuma análise disponível ainda")

    if resultado.get("user_id") != usuario["id"]:
        raise HTTPException(status_code=403, detail="Acesso negado")

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
def relatorio_completo(
    protocolo: Optional[str] = None,
    usuario:   dict = Depends(usuario_autenticado),
):
    resultado = carregar_resultado(usuario["id"], protocolo)
    if not resultado:
        raise HTTPException(status_code=404, detail="Nenhuma análise disponível ainda")
    if resultado.get("user_id") != usuario["id"]:
        raise HTTPException(status_code=403, detail="Acesso negado")
    return resultado


@app.get("/resultados")
def listar_resultados(usuario: dict = Depends(usuario_autenticado)):
    """Lista todos os protocolos do usuário autenticado."""
    base = pasta_resultados_usuario(usuario["id"])
    if not base.exists():
        return {"resultados": []}
    protocolos = [
        {
            "protocolo":   p.name,
            "relatorio":   (p / "relatorio.json").exists(),
            "findings":    (p / "findings.json").exists(),
            "enriquecido": (p / "resultado_enriquecido.json").exists(),
        }
        for p in sorted(base.iterdir()) if p.is_dir()
    ]
    return {"resultados": protocolos}


@app.get("/status")
def status_analise(usuario: dict = Depends(usuario_autenticado)):
    resultado = carregar_resultado(usuario["id"])
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
