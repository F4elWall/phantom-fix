"""
PhantomFix — Spirit
Agente que usa Gemini 1.5 Flash com PDFs de legislação (LGPD, ISO 27001)
para responder perguntas sobre impacto real de vulnerabilidades.

Ao iniciar, faz upload dos PDFs da pasta ./legislacao/ para a File API
do Gemini. Cada pergunta recebe: PDFs + relatório atual + pergunta.

POST /perguntar  { pergunta } → { resposta }
GET  /saude               → status dos PDFs e cache
"""

import json
import os
from pathlib import Path

import httpx
import google.generativeai as genai
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── Configuração ───────────────────────────────────────────────────────────────
GEMINI_API_KEY  = os.getenv("GEMINI_API_KEY",  "")
CORE_URL        = os.getenv("CORE_URL",        "http://localhost:8000")
MODELO          = os.getenv("SPIRIT_MODEL",    "gemini-1.5-flash")
LEGISLACAO_DIR  = Path(os.getenv("LEGISLACAO_DIR", "./legislacao"))

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="PhantomFix Spirit", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Estado global ──────────────────────────────────────────────────────────────
# Referências dos PDFs já enviados à File API do Gemini (válidos por 48h)
_arquivos_gemini: list = []
_relatorio_cache: dict | None = None

# ── Prompt base ───────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """Você é o Spirit, assistente especializado em segurança de aplicações do PhantomFix.

Sua missão é TRADUZIR vulnerabilidades técnicas em impacto de negócio real,
tornando segurança da informação compreensível para qualquer pessoa — gestores,
diretores, equipes jurídicas e pessoas fora da área de TI.

Os documentos de legislação e normas técnicas foram fornecidos acima.
Use-os para embasar suas respostas com artigos e controles específicos.

DIRETRIZES:
1. Use linguagem acessível — explique como se a pessoa não soubesse o que é SQL Injection
2. Conecte cada vulnerabilidade ao impacto real: o que pode acontecer se for explorada?
3. Cite a LGPD com valores de multa (Art. 52: até 2% do faturamento ou R$ 50 mi por infração)
   e obrigação de notificação (Art. 48) quando houver risco a dados pessoais
4. Cite o controle ISO 27001 que está sendo violado (ex: A.8.28 — Codificação Segura)
5. Dê exemplos concretos: "um atacante poderia fazer X, acessando Y, causando Z"
6. Quando perguntado sobre prioridade, justifique com base em impacto e esforço de correção
7. Seja direto — vá ao ponto que importa para o negócio, sem enrolar
8. Tom: profissional, humano e construtivo

Responda sempre em português brasileiro."""


# ── Upload dos PDFs ao iniciar ─────────────────────────────────────────────────
@app.on_event("startup")
async def carregar_legislacao():
    """
    Faz upload dos PDFs de ./legislacao/ para a File API do Gemini.
    Os arquivos ficam disponíveis por 48h — para demos isso é suficiente.
    Para uso contínuo, basta reiniciar o serviço.
    """
    global _arquivos_gemini

    if not GEMINI_API_KEY:
        print("[Spirit] ⚠  GEMINI_API_KEY não configurada — PDFs não carregados")
        return

    if not LEGISLACAO_DIR.exists():
        print(f"[Spirit] ⚠  Pasta '{LEGISLACAO_DIR}' não encontrada — crie e adicione os PDFs")
        return

    pdfs = sorted(LEGISLACAO_DIR.glob("*.pdf"))
    if not pdfs:
        print(f"[Spirit] ⚠  Nenhum PDF em '{LEGISLACAO_DIR}' — adicione lgpd.pdf, iso27001.pdf etc.")
        return

    print(f"[Spirit] Enviando {len(pdfs)} PDF(s) para o Gemini File API...")
    for pdf in pdfs:
        try:
            arquivo = genai.upload_file(path=str(pdf), display_name=pdf.stem)
            _arquivos_gemini.append(arquivo)
            print(f"[Spirit]   ✓ {pdf.name}")
        except Exception as e:
            print(f"[Spirit]   ✗ {pdf.name}: {e}")

    print(f"[Spirit] {len(_arquivos_gemini)} PDF(s) prontos — Spirit no ar 👻")


# ── Cache do relatório ─────────────────────────────────────────────────────────
async def obter_relatorio() -> dict | None:
    """Busca o relatório mais recente do Core. Usa cache se o Core não responder."""
    global _relatorio_cache
    try:
        async with httpx.AsyncClient() as cliente:
            resp = await cliente.get(
                f"{CORE_URL}/relatorio",
                headers={"ngrok-skip-browser-warning": "true"},
                timeout=10,
            )
            if resp.status_code == 200:
                _relatorio_cache = resp.json()
    except Exception as e:
        print(f"[Spirit] Não conseguiu buscar relatório do Core: {e}")
    return _relatorio_cache


# ── Model ──────────────────────────────────────────────────────────────────────
class PerguntaRequest(BaseModel):
    pergunta: str


# ── Endpoints ──────────────────────────────────────────────────────────────────
@app.get("/")
def raiz():
    return {"status": "PhantomFix Spirit funcionando", "versao": "0.2.0"}


@app.get("/saude")
def saude():
    return {
        "status":              "ok",
        "modelo":              MODELO,
        "pdfs_carregados":     len(_arquivos_gemini),
        "nomes_pdfs":          [a.display_name for a in _arquivos_gemini],
        "relatorio_em_cache":  _relatorio_cache is not None,
        "protocolo_em_cache":  _relatorio_cache.get("protocolo") if _relatorio_cache else None,
    }


@app.post("/perguntar")
async def perguntar(body: PerguntaRequest):
    if not GEMINI_API_KEY:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY não configurada")

    # 1. Busca o relatório atual
    relatorio = await obter_relatorio()

    contexto_relatorio = (
        "\n\n=== Relatório de vulnerabilidades da aplicação ===\n"
        + json.dumps(relatorio, indent=2, ensure_ascii=False)
        if relatorio
        else "\n\n[Relatório indisponível no momento — responda de forma geral.]"
    )

    # 2. Monta o prompt final
    prompt = f"{SYSTEM_PROMPT}{contexto_relatorio}\n\n=== Pergunta ===\n{body.pergunta}"

    # 3. Chama o Gemini com os PDFs + prompt
    try:
        model = genai.GenerativeModel(MODELO)

        # PDFs vêm primeiro, depois o prompt — o Gemini lê nessa ordem
        partes = _arquivos_gemini + [prompt]

        response = model.generate_content(partes)
        return {"resposta": response.text}

    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro no Gemini: {e}")
