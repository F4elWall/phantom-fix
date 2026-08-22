"""
PhantomFix — Spirit
Agente que usa Groq (llama-3.3-70b-versatile) com texto extraído dos PDFs
de legislação (LGPD, ISO 27001) para responder perguntas sobre impacto
real de vulnerabilidades.

POST /perguntar  { pergunta, relatorio? } → { resposta }
GET  /saude               → status dos PDFs e cache
"""

import json
import os
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── Configuração ───────────────────────────────────────────────────────────────
OLLAMA_API_KEY = os.getenv("OLLAMA_SPIRIT_KEY")
CORE_URL       = os.getenv("CORE_URL",     "http://localhost:8000")
MODELO         = os.getenv("SPIRIT_MODEL", "gpt-oss:20b")
LEGISLACAO_DIR = Path(os.getenv("LEGISLACAO_DIR", "./legislacao"))

OLLAMA_URL = "https://ollama.com/api/chat/completions"

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="PhantomFix Spirit", version="0.3.1")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Estado global ──────────────────────────────────────────────────────────────
_legislacao_texto: str = ""
_relatorio_cache: dict | None = None

# ── Prompt base ───────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """Você é o Spirit, assistente especializado em segurança de aplicações do PhantomFix.

Sua missão é TRADUZIR vulnerabilidades técnicas em impacto de negócio real,
tornando segurança da informação compreensível para qualquer pessoa — gestores,
diretores, equipes jurídicas e pessoas fora da área de TI.

{legislacao}

DIRETRIZES:
1. Use linguagem acessível — explique como se a pessoa não soubesse o que é SQL Injection
2. Conecte cada vulnerabilidade ao impacto real: o que pode acontecer se for explorada?
3. Cite a LGPD com valores de multa (Art. 52: até 2% do faturamento ou R$ 50 mi por infração)
   e obrigação de notificação (Art. 48) quando houver risco a dados pessoais
4. Cite o controle ISO 27001 que está sendo violado (ex: A.8.28 — Codificação Segura)
5. Dê exemplos concretos: "um atacante poderia fazer X, acessando Y, causando Z"
6. Seja direto — vá ao ponto que importa para o negócio, sem enrolar
7. Tom: profissional, humano e construtivo
8. Quando houver relatório de vulnerabilidades no contexto, BASE sua resposta nelas —
   cite tipos, scores e arquivos quando fizer sentido. Não diga que não tem acesso ao relatório
   se o relatório estiver presente no contexto.

Responda sempre em português brasileiro."""


def extrair_texto_pdf(caminho: Path) -> str:
    try:
        import pypdf
        reader = pypdf.PdfReader(str(caminho))
        texto = "\n".join(
            page.extract_text() or "" for page in reader.pages
        )
        return texto[:8000]
    except Exception as e:
        print(f"[Spirit] ✗ Erro ao extrair {caminho.name}: {e}")
        return ""


@app.on_event("startup")
async def carregar_legislacao():
    global _legislacao_texto

    if not LEGISLACAO_DIR.exists():
        print(f"[Spirit] ⚠  Pasta '{LEGISLACAO_DIR}' não encontrada")
        return

    pdfs = sorted(LEGISLACAO_DIR.glob("*.pdf"))
    if not pdfs:
        print(f"[Spirit] ⚠  Nenhum PDF em '{LEGISLACAO_DIR}'")
        return

    print(f"[Spirit] Extraindo texto de {len(pdfs)} PDF(s)...")
    partes = []
    for pdf in pdfs:
        texto = extrair_texto_pdf(pdf)
        if texto:
            partes.append(f"=== {pdf.name} ===\n{texto}")
            print(f"[Spirit]   ✓ {pdf.name} ({len(texto)} chars)")
        else:
            print(f"[Spirit]   ✗ {pdf.name} (sem texto)")

    _legislacao_texto = "\n\n".join(partes)
    print(f"[Spirit] Legislação carregada — Spirit no ar 👻")


async def obter_relatorio() -> dict | None:
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
        print(f"[Spirit] Não conseguiu buscar relatório: {e}")
    return _relatorio_cache


class PerguntaRequest(BaseModel):
    pergunta: str
    relatorio: dict | None = None


@app.get("/")
def raiz():
    return {"status": "PhantomFix Spirit funcionando", "versao": "0.3.1"}


@app.get("/saude")
def saude():
    return {
        "status":             "ok",
        "modelo":             MODELO,
        "legislacao_chars":   len(_legislacao_texto),
        "relatorio_em_cache": _relatorio_cache is not None,
    }


@app.post("/perguntar")
async def perguntar(body: PerguntaRequest):
    if not OLLAMA_API_KEY:
        raise HTTPException(status_code=500, detail="OLLAMA_API_KEY não configurada")

    # Prioriza o relatório enviado pelo Dashboard
    relatorio = body.relatorio if body.relatorio else await obter_relatorio()

    if relatorio and isinstance(relatorio.get("vulnerabilidades"), list):
        relatorio = {
            **relatorio,
            "vulnerabilidades": relatorio["vulnerabilidades"][:15],
        }

    contexto_relatorio = (
        "\n\n=== Relatório de vulnerabilidades da aplicação ===\n"
        + json.dumps(relatorio, indent=2, ensure_ascii=False)
        if relatorio
        else "\n\n[Relatório indisponível — responda de forma geral.]"
    )

    legislacao_bloco = (
        f"=== Legislação e normas de referência ===\n{_legislacao_texto}"
        if _legislacao_texto
        else "[Documentos de legislação não disponíveis.]"
    )

    system = SYSTEM_PROMPT.format(legislacao=legislacao_bloco)

    try:
        async with httpx.AsyncClient(timeout=60) as cliente:
            resp = await cliente.post(
                OLLAMA_URL,
                headers={"Authorization": f"Bearer {OLLAMA_API_KEY}"},
                json={
                    "model": MODELO,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user",   "content": f"{contexto_relatorio}\n\n=== Pergunta ===\n{body.pergunta}"},
                    ],
                    "max_tokens": 1024,
                    "temperature": 0.4,
                },
            )
            resp.raise_for_status()
        return {"resposta": resp.json()["choices"][0]["message"]["content"]}

    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro no Ollama: {e}")
