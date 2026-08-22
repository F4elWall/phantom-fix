"""
PhantomFix — Ghost (v1.1)
Gera correções automáticas de código usando LLM (Groq).
"""

import json
import os
from typing import Dict, Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="PhantomFix Ghost", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Configuração ───────────────────────────────────────────────────────────────
GHOST_API_KEY = os.getenv("OLLAMA_GHOST_KEY")
GHOST_MODEL   = os.getenv("GHOST_MODEL", "gpt-oss:20b")

if not GHOST_API_KEY:
    print("⚠️  AVISO: OLLAMA_API_KEY não configurada!")

# ── Models ─────────────────────────────────────────────────────────────────────
class Vulnerability(BaseModel):
    id: str
    arquivo: str
    linha: int
    tipo: str
    severidade: str
    descricao: str
    trecho_do_codigo: str
    score: float
    justificativa: str
    categoria: str = ""
    recomendacao: str = ""

class CorrectionResponse(BaseModel):
    correcao: str
    explicacao: str
    diff: Optional[str] = None
    confianca: float = 0.0

# ── Histórico em memória ───────────────────────────────────────────────────────
historico: Dict[str, CorrectionResponse] = {}

# ── Helpers ────────────────────────────────────────────────────────────────────
def extrair_json(text: str) -> dict:
    """Extrai JSON do texto mesmo que venha com markdown ou texto extra."""
    # Remove blocos markdown
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0]
    elif "```" in text:
        text = text.split("```")[1].split("```")[0]

    # Encontra o bloco JSON
    start = text.find("{")
    end   = text.rfind("}") + 1
    if start == -1 or end <= start:
        raise ValueError("Nenhum JSON encontrado na resposta do modelo")

    return json.loads(text[start:end])

# ── Endpoints ──────────────────────────────────────────────────────────────────
@app.get("/")
def raiz():
    return {"status": "PhantomFix Ghost funcionando", "versao": "1.1.0"}

@app.get("/health")
def health():
    return {
        "status":          "healthy",
        "model":           GHOST_MODEL,
        "historico_size":  len(historico),
        "api_key_ok":      bool(GHOST_API_KEY),
    }

@app.get("/historico")
def get_historico():
    return historico

@app.post("/corrigir", response_model=CorrectionResponse)
async def corrigir_vulnerabilidade(vuln: Vulnerability):
    """Gera correção segura para uma vulnerabilidade usando o Groq."""
    if not GHOST_API_KEY:
        raise HTTPException(status_code=500, detail="GHOST_API_KEY não configurada")

    prompt = f"""Você é um expert em segurança de aplicações e refatoração segura.

Analise a vulnerabilidade abaixo e forneça uma correção completa.

VULNERABILIDADE:
- ID:          {vuln.id}
- Tipo:        {vuln.tipo}
- Severidade:  {vuln.severidade}
- Score:       {vuln.score}
- Arquivo:     {vuln.arquivo} (linha {vuln.linha})
- Descrição:   {vuln.descricao}
- Justificativa: {vuln.justificativa}
- Recomendação existente: {vuln.recomendacao or "nenhuma"}

TRECHO DO CÓDIGO VULNERÁVEL:
{vuln.trecho_do_codigo}

INSTRUÇÕES:
1. Corrija o código de forma segura e moderna
2. Adicione comentários explicando cada mudança importante
3. Mantenha o estilo e a lógica original sempre que possível
4. Seja preciso — não invente imports ou funções que não existem no contexto

Responda APENAS com JSON válido, sem texto antes ou depois, sem markdown:
{{"correcao": "código corrigido completo", "explicacao": "explicação clara do problema e da solução", "diff": "resumo das mudanças principais", "confianca": 0.85}}
"""

    try:
        async with httpx.AsyncClient(timeout=90) as client:
            resp = await client.post(
                "https://ollama.com/api/chat/completions",
                headers={"Authorization": f"Bearer {GHOST_API_KEY}"},
                json={
                    "model":       GHOST_MODEL,
                    "messages":    [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "max_tokens":  1800,
                    "reasoning_effort": "low",
                    "include_reasoning": False
                },
            )
            resp.raise_for_status()

        content = resp.json()["choices"][0]["message"]["content"].strip()
        result  = extrair_json(content)

        correction = CorrectionResponse(**result)
        historico[vuln.id] = correction
        return correction

    except json.JSONDecodeError as e:
        raise HTTPException(status_code=502, detail=f"Resposta inválida do modelo: {e}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Erro na API Groq: {e.response.text}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao gerar correção: {e}")
