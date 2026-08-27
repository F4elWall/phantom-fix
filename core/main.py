"""
PhantomFix — Core
Versão: 0.8.0

Recebe o .zip do cliente, extrai numa pasta temporária, aciona o scanner.py,
aciona o analyser.py, aciona o Ghost, gera relatório executivo via Spirit
e envia e-mail de notificação via Gmail (smtplib — sem dependência externa).

Novidades v0.8.0:
  - Migração de Resend → smtplib + Gmail App Password
  - PDF do relatório executivo gerado via WeasyPrint e anexado ao e-mail
  - Endpoint /relatorio-executivo/{protocolo}/pdf para download direto
  - Spirit recebe max_tokens=8192 no relatório executivo (evita corte)
"""

import html as html_lib
import json
import os
import re
import shutil
import smtplib
import subprocess
import sys
import uuid
import zipfile
import asyncio
import httpx
from datetime import datetime, timezone
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from weasyprint import HTML

sys.path.append(str(Path(__file__).parent.parent))
from database import db

app = FastAPI(title="PhantomFix Core", version="0.8.0")

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

# E-mail via Gmail (smtplib)
GMAIL_USER          = os.getenv("GMAIL_USER")           # seuemail@gmail.com
GMAIL_APP_PASSWORD  = os.getenv("GMAIL_APP_PASSWORD")   # App Password de 16 chars (sem espaços)
EMAIL_FROM_NAME     = os.getenv("EMAIL_FROM_NAME", "PhantomFix")

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
    total    = relatorio.get("total_encontrado", 0)
    vulns    = relatorio.get("vulnerabilidades", [])
    criticas = sum(1 for v in vulns if float(v.get("score") or 0) >= 9.0)
    altas    = sum(1 for v in vulns if 7.0 <= float(v.get("score") or 0) < 9.0)
    medias   = sum(1 for v in vulns if 4.0 <= float(v.get("score") or 0) < 7.0)
    correlac = sum(1 for v in vulns if v.get("tags_correlacao"))

    top_vulns = sorted(vulns, key=lambda v: float(v.get("score") or 0), reverse=True)[:15]

    # Remove campos volumosos que não agregam ao relatório executivo
    # mas consomem a maior parte do contexto (trecho_do_codigo sozinho pode
    # ter centenas de linhas; correcao e explicacao são igualmente grandes)
    CAMPOS_EXECUTIVO = {
        "id", "tipo", "severidade", "score", "descricao",
        "arquivo", "linha", "categoria", "recomendacao",
        "origem", "tags_correlacao",
    }
    top_vulns_slim = [
        {k: v for k, v in vuln.items() if k in CAMPOS_EXECUTIVO}
        for vuln in top_vulns
    ]

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
2. POSTURA DE SEGURANÇA ATUAL
3. PRINCIPAIS AMEAÇAS IDENTIFICADAS
4. IMPACTO POTENCIAL AO NEGÓCIO
5. CONFORMIDADE REGULATÓRIA
6. RECOMENDAÇÕES PRIORITÁRIAS
7. CONCLUSÃO

TOP 10 VULNERABILIDADES:
{json.dumps(top_vulns_slim, indent=2, ensure_ascii=False)}"""

    try:
        async with httpx.AsyncClient(timeout=240) as cliente:
            resp = await cliente.post(
                f"{SPIRIT_URL}/perguntar",
                json={"pergunta": pergunta, "relatorio": None, "max_tokens": 8192},
            )
            resp.raise_for_status()
            return resp.json().get("resposta")
    except Exception as e:
        print(f"  ⚠ Spirit não gerou relatório executivo: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# PDF — gera o relatório executivo em PDF real (backend), via WeasyPrint
# ══════════════════════════════════════════════════════════════════════════════
def _texto_executivo_para_html(texto: str | None) -> str:
    texto_html = html_lib.escape(texto or "Conteúdo não disponível.")
    texto_html = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", texto_html)
    texto_html = re.sub(r"^### (.+)$", r"<h3>\1</h3>", texto_html, flags=re.MULTILINE)
    texto_html = re.sub(r"^## (.+)$",  r"<h2>\1</h2>", texto_html, flags=re.MULTILINE)
    texto_html = re.sub(r"^# (.+)$",   r"<h1>\1</h1>", texto_html, flags=re.MULTILINE)
    texto_html = re.sub(r"^---+$",     r"<hr>",        texto_html, flags=re.MULTILINE)
    texto_html = texto_html.replace("\n\n", "</p><p>").replace("\n", "<br>")
    return texto_html


def gerar_pdf_relatorio_executivo(relatorio_executivo: dict) -> bytes:
    texto_html = _texto_executivo_para_html(relatorio_executivo.get("texto"))

    gerado_em = relatorio_executivo.get("gerado_em")
    data_fmt  = "—"
    if gerado_em:
        try:
            data_fmt = datetime.fromisoformat(gerado_em).strftime("%d/%m/%Y %H:%M")
        except ValueError:
            data_fmt = gerado_em

    repo      = html_lib.escape(relatorio_executivo.get("repositorio") or "—")
    protocolo = html_lib.escape(relatorio_executivo.get("protocolo")   or "—")

    html_doc = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <style>
    @page {{ margin: 2.2cm 2cm; }}
    body {{ font-family: 'Segoe UI', Arial, sans-serif; color: #111827; line-height: 1.7; font-size: 12px; }}
    .header {{ border-bottom: 2px solid #6366F1; padding-bottom: 16px; margin-bottom: 24px; }}
    .header-titulo {{ font-size: 20px; font-weight: 700; color: #6366F1; margin: 0; }}
    .header-sub {{ font-size: 11px; color: #6B7280; margin: 2px 0 0; }}
    .meta {{ background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 8px;
             padding: 12px 16px; margin-bottom: 24px; font-size: 12px; color: #374151; }}
    h1, h2, h3 {{ color: #374151; margin: 20px 0 8px; }}
    h2 {{ font-size: 14px; border-bottom: 1px solid #E5E7EB; padding-bottom: 4px; }}
    h3 {{ font-size: 13px; color: #6366F1; }}
    p  {{ margin: 0 0 10px; }}
    hr {{ border: none; border-top: 1px solid #E5E7EB; margin: 16px 0; }}
    strong {{ color: #111827; }}
    .footer {{ margin-top: 32px; padding-top: 10px; border-top: 1px solid #E5E7EB;
               font-size: 10px; color: #9CA3AF; text-align: center; }}
  </style>
</head>
<body>
  <div class="header">
    <p class="header-titulo">👻 PhantomFix — Relatório Executivo</p>
    <p class="header-sub">Gerado automaticamente ao final da análise de segurança</p>
  </div>
  <div class="meta">
    <strong>Repositório:</strong> {repo} &nbsp;·&nbsp;
    <strong>Gerado em:</strong> {data_fmt} &nbsp;·&nbsp;
    <strong>Protocolo:</strong> {protocolo}
  </div>
  <div><p>{texto_html}</p></div>
  <div class="footer">
    PhantomFix · Relatório gerado automaticamente · Não substitui auditoria de segurança profissional.
  </div>
</body>
</html>"""
    return HTML(string=html_doc, base_url=".").write_pdf()


# ══════════════════════════════════════════════════════════════════════════════
# E-MAIL — notificação via Gmail (smtplib, sem dependência externa)
# ══════════════════════════════════════════════════════════════════════════════
def enviar_email_conclusao(
    email_destino:  str,
    nome_usuario:   str,
    relatorio:      dict,
    texto_executivo: str | None,
    protocolo:      str,
):
    """Envia e-mail de notificação com PDF do relatório executivo em anexo."""
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        print("  ⚠ GMAIL_USER / GMAIL_APP_PASSWORD não configurados — e-mail não enviado")
        return

    total    = relatorio.get("total_encontrado", 0)
    vulns    = relatorio.get("vulnerabilidades", [])
    criticas = sum(1 for v in vulns if float(v.get("score") or 0) >= 9.0)
    altas    = sum(1 for v in vulns if 7.0 <= float(v.get("score") or 0) < 9.0)
    repo     = relatorio.get("repositorio", "N/A")

    cor_status = "#EF4444" if criticas > 0 else "#F59E0B" if altas > 0 else "#10B981"
    status_txt = "CRÍTICO"    if criticas > 0 else "ALTO" if altas > 0 else "MÉDIO/BAIXO"

    resumo_executivo_html = ""
    if texto_executivo:
        paragrafos = [p.strip() for p in texto_executivo.split("\n\n") if p.strip()][:6]
        resumo_executivo_html = "".join(
            f"<p style='margin:0 0 12px 0'>{p}</p>" for p in paragrafos
        )

    link_dashboard = f"{DASHBOARD_URL}?protocolo={protocolo}"

    total_scanners = (
        relatorio.get("origem_semgrep",  0) +
        relatorio.get("origem_zap",      0) +
        relatorio.get("origem_gitleaks", 0) +
        relatorio.get("origem_trivy",    0)
    )

# Define o corpo do e-mail
    html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0B0F19;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0B0F19;padding:40px 0;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:12px;border:1px solid #1F2937;overflow:hidden;">

        <tr>
          <td style="padding:40px 40px 32px;text-align:center;">
            <p style="margin:0 0 8px;font-size:36px">👻</p>
            <h1 style="margin:0 0 6px;color:#F9FAFB;font-size:22px;font-weight:700">Análise concluída</h1>
            <p style="margin:0;color:#9CA3AF;font-size:14px">{repo}</p>
          </td>
        </tr>

        <tr>
          <td style="padding:0 40px 32px;">
            <p style="margin:0 0 16px;color:#D1D5DB;font-size:15px;line-height:1.6">
              Olá, <strong style="color:#F9FAFB">{nome_usuario}</strong>. Sua análise de segurança terminou.
              O relatório executivo completo está em anexo neste e-mail.
            </p>
            <p style="margin:0;color:#D1D5DB;font-size:15px;line-height:1.6">
              Para ver os detalhes das vulnerabilidades, correções sugeridas e conversar com o Spirit,
              acesse o dashboard com a sua conta:
            </p>
          </td>
        </tr>

        <tr>
          <td style="padding:0 40px 40px;text-align:center;">
            <a href="{link_dashboard}"
               style="display:inline-block;background:#6366F1;color:#ffffff;text-decoration:none;
                      font-size:15px;font-weight:700;padding:14px 40px;border-radius:8px;">
              Acessar Dashboard →
            </a>
          </td>
        </tr>

        <tr>
          <td style="background:#0B0F19;padding:20px 40px;text-align:center;border-top:1px solid #1F2937;">
            <p style="margin:0;color:#4B5563;font-size:12px">
              👻 PhantomFix · Gerado automaticamente · Não responda este e-mail
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""

    # ── Monta a mensagem ──────────────────────────────────────────────────────
    msg = MIMEMultipart()
    msg["From"]    = f"{EMAIL_FROM_NAME} <{GMAIL_USER}>"
    msg["To"]      = email_destino
    msg["Subject"] = f"[PhantomFix] Análise concluída — {repo} ({status_txt})"
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    # ── Anexa o PDF do relatório executivo ───────────────────────────────────
    pdf_anexado = False
    if texto_executivo:
        try:
            pdf_bytes = gerar_pdf_relatorio_executivo({
                "texto":       texto_executivo,
                "repositorio": repo,
                "protocolo":   protocolo,
                "gerado_em":   datetime.now(timezone.utc).isoformat(),
            })
            parte = MIMEBase("application", "octet-stream")
            parte.set_payload(pdf_bytes)
            encoders.encode_base64(parte)
            parte.add_header(
                "Content-Disposition",
                f'attachment; filename="relatorio-executivo-{protocolo}.pdf"',
            )
            msg.attach(parte)
            pdf_anexado = True
        except Exception as e:
            print(f"  ⚠ Falha ao gerar PDF para anexo: {e}")

    # ── Envia via Gmail SMTP ──────────────────────────────────────────────────
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            smtp.sendmail(GMAIL_USER, email_destino, msg.as_string())
        sufixo = " (PDF anexado)" if pdf_anexado else ""
        print(f"  ✓ E-mail enviado para {email_destino}{sufixo}")
    except Exception as e:
        print(f"  ⚠ Falha ao enviar e-mail: {e}")

# ══════════════════════════════════════════════════════════════════════════════
# ROTAS DE AUTENTICAÇÃO
# ══════════════════════════════════════════════════════════════════════════════
class SignUpBody(BaseModel):
    nome:  str
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
    background:       BackgroundTasks,
    arquivo:          UploadFile = File(...),
    repositorio:      str        = Form(...),
    token:            str        = Form(...),
    contexto_projeto: str        = Form(None),
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

        # ── 2. Padroniza contexto do projeto ──────────────────────────────────
        contexto_padronizado = None
        if contexto_projeto and contexto_projeto.strip():
            _status_jobs[protocolo]["status"] = "processando_contexto"
            print(f"[{protocolo}] Padronizando contexto do projeto...")
            contexto_padronizado = padronizar_contexto_projeto(contexto_projeto.strip())
            print(f"[{protocolo}] Contexto: {contexto_padronizado}")
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
            "protocolo":             protocolo,
            "user_id":               user_id,
            "repositorio":           repositorio,
            "contexto_projeto":      contexto_padronizado,
            "analisado_em":          achados.get("analisado_em"),
            "processado_em":         datetime.now(timezone.utc).isoformat(),
            "total_encontrado":      achados.get("total_encontrado", len(vulnerabilidades)),
            "origem_semgrep":        achados.get("origem_semgrep",  0),
            "origem_zap":            achados.get("origem_zap",      0),
            "origem_gitleaks":       achados.get("origem_gitleaks", 0),
            "origem_trivy":          achados.get("origem_trivy",    0),
            "total_correlacionados": achados_finais.get("total_correlacionados", 0),
            "analisado_por_ia":      achados_finais.get("analisado_por_agente", False),
            "modelo_ia":             achados_finais.get("modelo_ia", ""),
            "status":                "gerando_correcoes",
            "vulnerabilidades":      vulnerabilidades,
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

        # ── 7. Relatório executivo via Spirit ─────────────────────────────────
        _status_jobs[protocolo]["status"] = "gerando_relatorio"
        print(f"[{protocolo}] Gerando relatório executivo via Spirit...")
        texto_executivo = asyncio.run(gerar_relatorio_executivo(resultado))

        if texto_executivo:
            relatorio_executivo = {
                "protocolo":   protocolo,
                "user_id":     user_id,
                "repositorio": repositorio,
                "gerado_em":   datetime.now(timezone.utc).isoformat(),
                "texto":       texto_executivo,
                "lido":        False,
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

        # ── 9. E-mail de notificação ──────────────────────────────────────────
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
    return {"status": "PhantomFix Core funcionando", "versao": "0.8.0"}


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
def relatorio_executivo_endpoint(
    protocolo: Optional[str] = None,
    usuario:   dict = Depends(usuario_autenticado),
):
    resultado = carregar_relatorio_executivo(usuario["id"], protocolo)
    if not resultado:
        raise HTTPException(status_code=404, detail="Relatório executivo não disponível ainda")
    if resultado.get("user_id") != usuario["id"]:
        raise HTTPException(status_code=403, detail="Acesso negado")
    return resultado


@app.get("/relatorio-executivo/{protocolo}/pdf")
def baixar_relatorio_executivo_pdf(protocolo: str, usuario: dict = Depends(usuario_autenticado)):
    resultado = carregar_relatorio_executivo(usuario["id"], protocolo)
    if not resultado:
        raise HTTPException(status_code=404, detail="Relatório executivo não encontrado")
    if resultado.get("user_id") != usuario["id"]:
        raise HTTPException(status_code=403, detail="Acesso negado")

    pdf_bytes = gerar_pdf_relatorio_executivo(resultado)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="relatorio-executivo-{protocolo}.pdf"'},
    )


@app.post("/relatorio-executivo/{protocolo}/lido")
def marcar_relatorio_lido(protocolo: str, usuario: dict = Depends(usuario_autenticado)):
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
            "protocolo":           p.name,
            "relatorio":           (p / "relatorio.json").exists(),
            "findings":            (p / "findings.json").exists(),
            "enriquecido":         (p / "resultado_enriquecido.json").exists(),
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
