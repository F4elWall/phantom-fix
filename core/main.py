"""
PhantomFix — Core
Versão: 0.7.0

Recebe o .zip do cliente, extrai numa pasta temporária, aciona o scanner.py,
aciona o analyser.py, aciona o Ghost, gera relatório executivo via Spirit
e envia e-mail de notificação via Resend.

Novidades v0.7.0:
  - Recebe contexto_projeto do cliente (texto livre)
  - Padroniza o contexto via LLM antes de passar ao Analyser
  - Após Ghost, chama Spirit para gerar relatório executivo (linguagem de CISO)
  - Salva relatorio_executivo.json separado do relatorio.json
  - Dispara e-mail via Resend ao fim do pipeline
  - /relatorio-executivo — endpoint para o dashboard buscar o relatório executivo
  - /relatorio-executivo/{protocolo}/pdf — endpoint para download do PDF
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
import resend
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

sys.path.append(str(Path(__file__).parent.parent))
from database import db

app = FastAPI(title="PhantomFix Core", version="0.7.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

db.inicializar_banco()

# ── Configuração ──────────────────────────────────────────────────────────────
SCANNER_PATH    = os.getenv("SCANNER_PATH",    "../data-control/scanner.py")
ANALYSER_PATH   = os.getenv("ANALYSER_PATH",   "../analyser/analyser.py")
SCANNER_PYTHON  = os.getenv("SCANNER_PYTHON",  "python3")
SCANNER_TIMEOUT = int(os.getenv("SCANNER_TIMEOUT", "7200"))
GHOST_URL       = os.getenv("GHOST_URL",        "http://localhost:8002/corrigir")
SPIRIT_URL      = os.getenv("SPIRIT_URL",       "http://localhost:8001")

OLLAMA_API_KEY  = os.getenv("OLLAMA_ANALYSER_KEY")
OLLAMA_URL      = "https://ollama.com/v1/chat/completions"
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "gpt-oss:20b")

RESEND_API_KEY  = os.getenv("RESEND_API_KEY")
EMAIL_FROM      = os.getenv("EMAIL_FROM", "PhantomFix onboarding@resend.dev")
DASHBOARD_URL   = os.getenv("DASHBOARD_URL", "https://phantom-fix.southafricanorth.cloudapp.azure.com")

RESULTADOS_DIR  = Path(os.getenv("RESULTADOS_DIR", "../resultados"))
RESULTADOS_DIR.mkdir(parents=True, exist_ok=True)

JOBS_DIR = Path(os.getenv("JOBS_DIR", "./jobs"))
JOBS_DIR.mkdir(exist_ok=True)

# ── Estado dos jobs em memória ────────────────────────────────────────────────
_status_jobs: dict[str, dict] = {}


# ── Auth helpers ──────────────────────────────────────────────────────────────
def usuario_autenticado(authorization: str = Header(None)) -> dict:
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


def carregar_relatorio_executivo(user_id: int, protocolo: str | None = None) -> dict | None:
    base = pasta_resultados_usuario(user_id)
    if protocolo:
        path = base / protocolo / "relatorio_executivo.json"
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return None
    pastas = sorted(
        (p for p in base.iterdir() if p.is_dir()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for pasta in pastas:
        path = pasta / "relatorio_executivo.json"
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    return None


def salvar_resultado(user_id: int, protocolo: str, dados: dict):
    pasta = pasta_resultados_usuario(user_id) / protocolo
    pasta.mkdir(parents=True, exist_ok=True)
    (pasta / "relatorio.json").write_text(
        json.dumps(dados, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def salvar_relatorio_executivo(user_id: int, protocolo: str, dados: dict):
    pasta = pasta_resultados_usuario(user_id) / protocolo
    pasta.mkdir(parents=True, exist_ok=True)
    (pasta / "relatorio_executivo.json").write_text(
        json.dumps(dados, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# ══════════════════════════════════════════════════════════════════════════════
# CONTEXTO DO PROJETO — padroniza o texto livre do cliente via LLM
# ══════════════════════════════════════════════════════════════════════════════
def padronizar_contexto_projeto(texto_livre: str) -> dict:
    """
    Recebe o texto livre do usuário descrevendo o projeto e retorna um
    dicionário padronizado para ser embutido no prompt do Analyser.
    """
    if not OLLAMA_API_KEY:
        print("  ⚠ OLLAMA_API_KEY não configurada — contexto não padronizado")
        return {"descricao_livre": texto_livre}

    prompt = f"""Você receberá uma descrição livre de uma aplicação de software escrita por seu dono.
Extraia as informações e retorne APENAS um objeto JSON com estas chaves exatas:

{{
  "tipo_aplicacao": "ex: e-commerce, sistema interno, API pública, app mobile...",
  "exposicao": "internet-facing | interno | híbrido",
  "dados_sensiveis": "sim | não | parcial",
  "tipos_dados": "ex: dados pessoais, dados financeiros, dados de saúde... (ou 'nenhum')",
  "criticidade_negocio": "alta | média | baixa",
  "conformidade": "ex: LGPD, PCI-DSS, HIPAA... (ou 'não mencionada')",
  "objetivo_analise": "frase curta descrevendo o foco da análise de segurança"
}}

Se alguma informação não estiver na descrição, use "não informado".
Responda APENAS com o JSON, sem texto adicional.

Descrição do projeto:
{texto_livre}"""

    try:
        resp = httpx.post(
            OLLAMA_URL,
            headers={"Authorization": f"Bearer {OLLAMA_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": OLLAMA_MODEL,
                "messages": [
                    {"role": "system", "content": "Extraia informações estruturadas e retorne apenas JSON válido."},
                    {"role": "user",   "content": prompt},
                ],
                "temperature": 0.1,
                "max_tokens":  400,
            },
            timeout=30,
        )
        resp.raise_for_status()
        raw   = resp.json()["choices"][0]["message"]["content"].strip()
        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start != -1 and end > start:
            return json.loads(raw[start:end])
    except Exception as e:
        print(f"  ⚠ Erro ao padronizar contexto: {e}")

    return {"descricao_livre": texto_livre}


# ══════════════════════════════════════════════════════════════════════════════
# RELATÓRIO EXECUTIVO — gerado pelo Spirit após o Ghost
# ══════════════════════════════════════════════════════════════════════════════
async def gerar_relatorio_executivo(relatorio: dict) -> str | None:
    """
    Chama o Spirit com o relatório completo e pede um relatório executivo
    em linguagem de CISO. Retorna o texto gerado ou None em caso de falha.
    """
    total      = relatorio.get("total_encontrado", 0)
    vulns      = relatorio.get("vulnerabilidades", [])
    criticas   = sum(1 for v in vulns if float(v.get("score") or 0) >= 9.0)
    altas      = sum(1 for v in vulns if 7.0 <= float(v.get("score") or 0) < 9.0)
    medias     = sum(1 for v in vulns if 4.0 <= float(v.get("score") or 0) < 7.0)
    correlac   = sum(1 for v in vulns if v.get("tags_correlacao"))

    # Envia as 20 mais críticas para não estourar o contexto do Spirit
    top_vulns  = sorted(vulns, key=lambda v: float(v.get("score") or 0), reverse=True)[:20]

    pergunta = f"""Gere um RELATÓRIO EXECUTIVO DE SEGURANÇA completo e formal, em linguagem de CISO,
com base na análise abaixo. Este relatório será entregue à liderança da empresa.

DADOS DA ANÁLISE:
- Repositório: {relatorio.get("repositorio", "N/A")}
- Data da análise: {relatorio.get("analisado_em", "N/A")}
- Total de vulnerabilidades: {total}
  - Críticas (score ≥ 9.0): {criticas}
  - Altas (7.0–8.9): {altas}
  - Médias (4.0–6.9): {medias}
  - Confirmadas por múltiplas ferramentas: {correlac}
- Ferramentas utilizadas: Semgrep (SAST), OWASP ZAP (DAST), Gitleaks (Secrets), Trivy (SCA)

ESTRUTURA OBRIGATÓRIA DO RELATÓRIO (siga exatamente esta ordem):

1. SUMÁRIO EXECUTIVO
   Parágrafo de 3–5 linhas resumindo a situação geral. Comece pelo que é mais importante.
   Seja direto: se há risco crítico, diga isso primeiro.

2. POSTURA DE SEGURANÇA ATUAL
   Avaliação geral do nível de risco (Crítico / Alto / Médio / Baixo).
   Justifique com base nos números.

3. PRINCIPAIS AMEAÇAS IDENTIFICADAS
   Liste as 5 vulnerabilidades mais graves com: nome, score, impacto real em linguagem de negócio.
   Não use jargão técnico sem explicar.

4. IMPACTO POTENCIAL AO NEGÓCIO
   O que pode acontecer se as vulnerabilidades críticas forem exploradas?
   Mencione: impacto financeiro, operacional, reputacional e regulatório (LGPD quando aplicável).

5. CONFORMIDADE REGULATÓRIA
   Avalie o alinhamento com LGPD, ISO 27001 e NIST. Cite artigos e controles relevantes.

6. RECOMENDAÇÕES PRIORITÁRIAS
   3–5 ações concretas, ordenadas por urgência. Cada uma com prazo sugerido.

7. CONCLUSÃO
   Frase final de encaminhamento para a liderança.

TOP 20 VULNERABILIDADES (para embasar o relatório):
{json.dumps(top_vulns, indent=2, ensure_ascii=False)}"""

    try:
        async with httpx.AsyncClient(timeout=120) as cliente:
            resp = await cliente.post(
                f"{SPIRIT_URL}/perguntar",
                json={"pergunta": pergunta, "relatorio": None},
            )
            resp.raise_for_status()
            return resp.json().get("resposta")
    except Exception as e:
        print(f"  ⚠ Spirit não gerou relatório executivo: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# E-MAIL — notificação via Resend
# ══════════════════════════════════════════════════════════════════════════════
def enviar_email_conclusao(
    email_destino: str,
    nome_usuario: str,
    relatorio: dict,
    texto_executivo: str | None,
    protocolo: str,
):
    """Envia e-mail de notificação com resumo e link para o dashboard."""
    if not RESEND_API_KEY:
        print("  ⚠ RESEND_API_KEY não configurada — e-mail não enviado")
        return

    resend.api_key = RESEND_API_KEY

    total    = relatorio.get("total_encontrado", 0)
    vulns    = relatorio.get("vulnerabilidades", [])
    criticas = sum(1 for v in vulns if float(v.get("score") or 0) >= 9.0)
    altas    = sum(1 for v in vulns if 7.0 <= float(v.get("score") or 0) < 9.0)
    repo     = relatorio.get("repositorio", "N/A")

    cor_status = "#EF4444" if criticas > 0 else "#F59E0B" if altas > 0 else "#10B981"
    status_txt = "CRÍTICO" if criticas > 0 else "ALTO" if altas > 0 else "MÉDIO/BAIXO"

    resumo_executivo_html = ""
    if texto_executivo:
        # Converte quebras de linha em parágrafos simples para o e-mail
        paragrafos = [p.strip() for p in texto_executivo.split("\n\n") if p.strip()][:6]
        resumo_executivo_html = "".join(f"<p style='margin:0 0 12px 0'>{p}</p>" for p in paragrafos)

    link_dashboard = f"{DASHBOARD_URL}?protocolo={protocolo}"

    html = f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0B0F19;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0B0F19;padding:40px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1F2937;overflow:hidden;">

        <!-- Header -->
        <tr>
          <td style="background:#0B0F19;padding:32px 40px;text-align:center;border-bottom:1px solid #1F2937;">
            <p style="margin:0;font-size:32px">👻</p>
            <h1 style="margin:8px 0 4px;color:#F9FAFB;font-size:22px;font-weight:700">PhantomFix</h1>
            <p style="margin:0;color:#9CA3AF;font-size:13px;letter-spacing:1px">RELATÓRIO DE ANÁLISE CONCLUÍDO</p>
          </td>
        </tr>

        <!-- Saudação -->
        <tr>
          <td style="padding:32px 40px 0;">
            <p style="margin:0 0 8px;color:#F9FAFB;font-size:16px">Olá, <strong>{nome_usuario}</strong>.</p>
            <p style="margin:0;color:#9CA3AF;font-size:14px;line-height:1.6">
              A análise de segurança do repositório <strong style="color:#6366F1">{repo}</strong> foi concluída.
              Veja abaixo o resumo dos resultados.
            </p>
          </td>
        </tr>

        <!-- Badge de status -->
        <tr>
          <td style="padding:24px 40px 0;">
            <div style="background:#0B0F19;border:1px solid {cor_status};border-radius:8px;padding:16px 20px;text-align:center;">
              <p style="margin:0;color:{cor_status};font-size:13px;font-weight:700;letter-spacing:1px">
                NÍVEL DE RISCO: {status_txt}
              </p>
            </div>
          </td>
        </tr>

        <!-- Métricas -->
        <tr>
          <td style="padding:24px 40px 0;">
            <table width="100%" cellpadding="0" cellspacing="8">
              <tr>
                <td width="25%" style="background:#0B0F19;border-radius:8px;padding:16px;text-align:center;">
                  <p style="margin:0;color:#F9FAFB;font-size:28px;font-weight:700">{total}</p>
                  <p style="margin:4px 0 0;color:#9CA3AF;font-size:11px">TOTAL</p>
                </td>
                <td width="25%" style="background:#0B0F19;border-radius:8px;padding:16px;text-align:center;">
                  <p style="margin:0;color:#EF4444;font-size:28px;font-weight:700">{criticas}</p>
                  <p style="margin:4px 0 0;color:#9CA3AF;font-size:11px">CRÍTICAS</p>
                </td>
                <td width="25%" style="background:#0B0F19;border-radius:8px;padding:16px;text-align:center;">
                  <p style="margin:0;color:#F59E0B;font-size:28px;font-weight:700">{altas}</p>
                  <p style="margin:4px 0 0;color:#9CA3AF;font-size:11px">ALTAS</p>
                </td>
                <td width="25%" style="background:#0B0F19;border-radius:8px;padding:16px;text-align:center;">
                  <p style="margin:0;color:#6366F1;font-size:28px;font-weight:700">{relatorio.get("origem_semgrep", 0) + relatorio.get("origem_zap", 0) + relatorio.get("origem_gitleaks", 0) + relatorio.get("origem_trivy", 0)}</p>
                  <p style="margin:4px 0 0;color:#9CA3AF;font-size:11px">SCANNERS</p>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Resumo executivo (se existir) -->
        {"<tr><td style='padding:24px 40px 0;'><div style='background:#0B0F19;border-left:3px solid #6366F1;border-radius:0 8px 8px 0;padding:20px 24px;'><p style='margin:0 0 12px;color:#6366F1;font-size:12px;font-weight:700;letter-spacing:1px'>SUMÁRIO EXECUTIVO</p><div style='color:#D1D5DB;font-size:13px;line-height:1.7'>" + resumo_executivo_html + "</div></div></td></tr>" if resumo_executivo_html else ""}

        <!-- CTA -->
        <tr>
          <td style="padding:32px 40px;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td align="center">
                  <a href="{link_dashboard}" style="display:inline-block;background:#6366F1;color:#ffffff;text-decoration:none;font-size:14px;font-weight:700;padding:14px 36px;border-radius:8px;">
                    Acessar Relatório Completo →
                  </a>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#0B0F19;padding:20px 40px;text-align:center;border-top:1px solid #1F2937;">
            <p style="margin:0;color:#4B5563;font-size:12px">
              👻 PhantomFix · Este e-mail foi gerado automaticamente. Não responda.
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>
"""

    try:
        resend.Emails.send({
            "from":    EMAIL_FROM,
            "to":      email_destino,
            "subject": f"[PhantomFix] Análise concluída — {repo} ({status_txt})",
            "html":    html,
        })
        print(f"  ✓ E-mail enviado para {email_destino}")
    except Exception as e:
        print(f"  ⚠ Falha ao enviar e-mail: {e}")


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
        "session_token":  session_token,
        "user_id":        usuario["id"],
        "nome":           usuario["nome"],
        "email":          usuario["email"],
        "token":          usuario["token"],
        "client_linked":  bool(usuario["client_linked"]),
    }


@app.post("/auth/login")
def login(body: LoginBody):
    usuario = db.verificar_senha(body.email.strip().lower(), body.senha)
    if not usuario:
        raise HTTPException(status_code=401, detail="E-mail ou senha incorretos")
    session_token = db.criar_sessao(usuario["id"])
    return {
        "session_token":  session_token,
        "user_id":        usuario["id"],
        "nome":           usuario["nome"],
        "email":          usuario["email"],
        "token":          usuario["token"],
        "client_linked":  bool(usuario["client_linked"]),
    }


@app.post("/auth/logout")
def logout(usuario: dict = Depends(usuario_autenticado), authorization: str = Header(None)):
    session_token = authorization.split(" ", 1)[1]
    db.deletar_sessao(session_token)
    return {"ok": True}


@app.get("/auth/me")
def me(usuario: dict = Depends(usuario_autenticado)):
    return {
        "user_id":       usuario["id"],
        "nome":          usuario["nome"],
        "email":         usuario["email"],
        "token":         usuario["token"],
        "client_linked": bool(usuario["client_linked"]),
    }


@app.post("/auth/regen-token")
def regen_token(usuario: dict = Depends(usuario_autenticado)):
    novo_token = db.regenerar_token(usuario["id"])
    return {"token": novo_token, "client_linked": False}


@app.get("/auth/check-link")
def check_link(usuario: dict = Depends(usuario_autenticado)):
    vinculado = db.verificar_client_vinculado(usuario["id"])
    return {"client_linked": vinculado}


@app.post("/auth/link-client")
def link_client(body: LinkClientBody):
    ok = db.marcar_client_vinculado(body.token)
    if not ok:
        raise HTTPException(status_code=404, detail="Token não encontrado")
    return {"ok": True, "mensagem": "Client vinculado com sucesso"}


@app.get("/auth/me-by-token")
def me_by_token(token: str):
    usuario = db.buscar_usuario_por_token(token)
    if not usuario:
        raise HTTPException(status_code=404, detail="Token não encontrado")
    return {"nome": usuario["nome"], "email": usuario["email"]}


# ══════════════════════════════════════════════════════════════════════════════
# ROTA PRINCIPAL — recebe o .zip do cliente
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/scan")
async def receber_zip(
    background:        BackgroundTasks,
    arquivo:           UploadFile = File(...),
    repositorio:       str        = Form(...),
    token:             str        = Form(...),
    contexto_projeto:  str        = Form(None),   # NOVO — opcional
):
    usuario = db.buscar_usuario_por_token(token)
    if not usuario:
        raise HTTPException(status_code=403, detail="Token inválido")

    user_id   = usuario["id"]
    protocolo = str(uuid.uuid4())[:8]
    _status_jobs[protocolo] = {
        "status":      "recebido",
        "repositorio": repositorio,
        "user_id":     user_id,
    }

    pasta_job = JOBS_DIR / str(user_id) / protocolo
    pasta_job.mkdir(parents=True, exist_ok=True)

    zip_path = pasta_job / "repositorio.zip"
    conteudo = await arquivo.read()
    zip_path.write_bytes(conteudo)

    print(f"[{protocolo}] user={user_id} repo={repositorio} ({len(conteudo)/1024:.1f} KB)")

    background.add_task(
        pipeline_completo,
        user_id, protocolo, pasta_job, zip_path, repositorio,
        contexto_projeto, usuario["email"], usuario["nome"],
    )

    return {"status": "recebido", "protocolo": protocolo, "repositorio": repositorio}


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
def pipeline_completo(
    user_id:          int,
    protocolo:        str,
    pasta_job:        Path,
    zip_path:         Path,
    repositorio:      str,
    contexto_projeto: str | None,
    email_usuario:    str,
    nome_usuario:     str,
):
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

        # ── 2. Padroniza contexto do projeto (NOVO) ───────────────────────────
        contexto_padronizado = None
        if contexto_projeto and contexto_projeto.strip():
            _status_jobs[protocolo]["status"] = "processando_contexto"
            print(f"[{protocolo}] Padronizando contexto do projeto...")
            contexto_padronizado = padronizar_contexto_projeto(contexto_projeto.strip())
            print(f"[{protocolo}] Contexto: {contexto_padronizado}")

            # Salva o contexto para o Analyser ler via env
            ctx_path = pasta_resultado / "contexto_projeto.json"
            ctx_path.write_text(
                json.dumps(contexto_padronizado, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        # ── 3. Scanner ───────────────────────────────────────────────────────
        _status_jobs[protocolo]["status"] = "escaneando"
        arquivo_findings = pasta_resultado / "findings.json"

        print(f"[{protocolo}] Acionando scanner.py...")
        proc_scanner = subprocess.run(
            [SCANNER_PYTHON, SCANNER_PATH, str(pasta_extraida), str(arquivo_findings)],
            capture_output=True, text=True, timeout=SCANNER_TIMEOUT,
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

        achados          = json.loads(arquivo_findings.read_text(encoding="utf-8"))
        vulnerabilidades = achados.get("vulnerabilidades", [])
        print(f"[{protocolo}] {len(vulnerabilidades)} vulnerabilidades encontradas")

        # ── 4. Analyser ───────────────────────────────────────────────────────
        _status_jobs[protocolo]["status"] = "analisando"
        arquivo_enriquecido = pasta_resultado / "resultado_enriquecido.json"

        env_analyser = {**os.environ, "PASTA_REPO": str(pasta_extraida)}

        # Passa o contexto padronizado para o Analyser embutir no prompt
        if contexto_padronizado:
            env_analyser["CONTEXTO_PROJETO"] = json.dumps(
                contexto_padronizado, ensure_ascii=False
            )

        print(f"[{protocolo}] Acionando analyser.py...")
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

        # ── 5. Salva versão inicial do relatório ─────────────────────────────
        resultado = {
            "protocolo":          protocolo,
            "user_id":            user_id,
            "repositorio":        repositorio,
            "contexto_projeto":   contexto_padronizado,
            "analisado_em":       achados.get("analisado_em"),
            "processado_em":      datetime.now(timezone.utc).isoformat(),
            "total_encontrado":   achados.get("total_encontrado", len(vulnerabilidades)),
            "origem_semgrep":     achados.get("origem_semgrep", 0),
            "origem_zap":         achados.get("origem_zap", 0),
            "origem_gitleaks":    achados.get("origem_gitleaks", 0),
            "origem_trivy":       achados.get("origem_trivy", 0),
            "total_correlacionados": achados_finais.get("total_correlacionados", 0),
            "analisado_por_ia":   achados_finais.get("analisado_por_agente", False),
            "modelo_ia":          achados_finais.get("modelo_ia", ""),
            "status":             "gerando_correcoes",
            "vulnerabilidades":   vulnerabilidades,
        }
        salvar_resultado(user_id, protocolo, resultado)
        _status_jobs[protocolo]["status"] = "priorizado"

        # ── 6. Ghost ─────────────────────────────────────────────────────────
        _status_jobs[protocolo]["status"] = "corrigindo"
        print(f"[{protocolo}] Acionando Ghost para {len(vulnerabilidades)} vulnerabilidades...")
        asyncio.run(processar_com_ghost(vulnerabilidades))

        resultado["status"]           = "gerando_relatorio"
        resultado["vulnerabilidades"] = vulnerabilidades
        salvar_resultado(user_id, protocolo, resultado)

        # ── 7. Relatório executivo via Spirit (NOVO) ──────────────────────────
        _status_jobs[protocolo]["status"] = "gerando_relatorio"
        print(f"[{protocolo}] Gerando relatório executivo via Spirit...")

        texto_executivo = asyncio.run(gerar_relatorio_executivo(resultado))

        if texto_executivo:
            relatorio_executivo = {
                "protocolo":       protocolo,
                "user_id":         user_id,
                "repositorio":     repositorio,
                "gerado_em":       datetime.now(timezone.utc).isoformat(),
                "texto":           texto_executivo,
                "lido":            False,
            }
            salvar_relatorio_executivo(user_id, protocolo, relatorio_executivo)
            _status_jobs[protocolo]["relatorio_executivo_pronto"] = True
            print(f"[{protocolo}] Relatório executivo salvo")
        else:
            print(f"[{protocolo}] ⚠ Relatório executivo não gerado")

        # ── 8. Relatório final ────────────────────────────────────────────────
        resultado["status"]       = "concluido"
        resultado["corrigido_em"] = datetime.now(timezone.utc).isoformat()
        salvar_resultado(user_id, protocolo, resultado)
        _status_jobs[protocolo]["status"] = "concluido"

        # ── 9. E-mail de notificação (NOVO) ───────────────────────────────────
        print(f"[{protocolo}] Enviando e-mail para {email_usuario}...")
        enviar_email_conclusao(
            email_destino=email_usuario,
            nome_usuario=nome_usuario,
            relatorio=resultado,
            texto_executivo=texto_executivo,
            protocolo=protocolo,
        )

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
            "correcao":   correcao.get("correcao",   "Correção indisponível"),
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
# ROTAS DO DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/")
def raiz():
    return {"status": "PhantomFix Core funcionando", "versao": "0.7.0"}


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


@app.get("/relatorio-executivo")
def relatorio_executivo(
    protocolo: Optional[str] = None,
    usuario:   dict = Depends(usuario_autenticado),
):
    """Retorna o relatório executivo gerado pelo Spirit."""
    resultado = carregar_relatorio_executivo(usuario["id"], protocolo)
    if not resultado:
        raise HTTPException(status_code=404, detail="Relatório executivo não disponível ainda")
    if resultado.get("user_id") != usuario["id"]:
        raise HTTPException(status_code=403, detail="Acesso negado")
    return resultado


@app.post("/relatorio-executivo/{protocolo}/lido")
def marcar_relatorio_lido(protocolo: str, usuario: dict = Depends(usuario_autenticado)):
    """Dashboard chama este endpoint quando o usuário clica em 'Acessar Dashboard completo'."""
    resultado = carregar_relatorio_executivo(usuario["id"], protocolo)
    if not resultado:
        raise HTTPException(status_code=404, detail="Relatório executivo não encontrado")
    if resultado.get("user_id") != usuario["id"]:
        raise HTTPException(status_code=403, detail="Acesso negado")
    resultado["lido"] = True
    salvar_relatorio_executivo(usuario["id"], protocolo, resultado)
    return {"ok": True}


@app.get("/resultados")
def listar_resultados(usuario: dict = Depends(usuario_autenticado)):
    base = pasta_resultados_usuario(usuario["id"])
    if not base.exists():
        return {"resultados": []}
    protocolos = [
        {
            "protocolo":          p.name,
            "relatorio":          (p / "relatorio.json").exists(),
            "findings":           (p / "findings.json").exists(),
            "enriquecido":        (p / "resultado_enriquecido.json").exists(),
            "relatorio_executivo": (p / "relatorio_executivo.json").exists(),
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
