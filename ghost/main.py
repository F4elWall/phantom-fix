"""
PhantomFix — Ghost (v1.0)
Gera correções automáticas de código usando LLM.
"""

import json
import os
from datetime import datetime
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx

app = FastAPI(title="PhantomFix Ghost", version="1.0.0")

# Configuração
GHOST_API_KEY = os.getenv("GHOST_API_KEY")
GHOST_MODEL = os.getenv("GHOST_MODEL", "llama-3.3-70b-versatile")

if not GHOST_API_KEY:
    print("⚠️  AVISO: GHOST_API_KEY não configurada!")

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

# Histórico simples (em memória)
historico: Dict[str, CorrectionResponse] = {}

@app.post("/corrigir", response_model=CorrectionResponse)
async def corrigir_vulnerabilidade(vuln: Vulnerability):
    """Gera correção usando LLM (Groq)."""
    if not GHOST_API_KEY:
        raise HTTPException(status_code=500, detail="GHOST_API_KEY não configurada")

    prompt = f"""Você é um expert em segurança de aplicações e refatoração segura.

Vulnerabilidade:
- Tipo: {vuln.tipo}
- Severidade: {vuln.severidade}
- Arquivo: {vuln.arquivo}:{vuln.linha}
- Descrição: {vuln.descricao}
- Justificativa: {vuln.justificativa}
- Trecho do código: {vuln.trecho_do_codigo}


Forneça uma correção segura, moderna e bem comentada.

Responda **apenas** com JSON válido:
{{
  "correcao": "código corrigido completo com comentários",
  "explicacao": "explicação clara e detalhada do problema e da solução",
  "diff": "resumo das principais mudanças",
  "confianca": 0.85
}}
"""

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GHOST_API_KEY}"},
                json={
                    "model": GHOST_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "max_tokens": 1200
                },
                timeout=90
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"].strip()

            # Limpa markdown se existir
            if content.startswith("```json"):
                content = content.split("```json")[1].split("```")[0].strip()
            elif content.startswith("```"):
                content = content.split("```")[1].split("```")[0].strip()

            result = json.loads(content)
            correction = CorrectionResponse(**result)

            # Salva no histórico
            historico[vuln.id] = correction
            return correction

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao gerar correção: {str(e)}")


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "model": GHOST_MODEL,
        "historico_size": len(historico)
    }


@app.get("/historico")
async def get_historico():
    return historico


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
