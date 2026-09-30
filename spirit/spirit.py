"""
Autora e revisor: Giovana Esmelardi
PhantomFix — Spirit v0.4.0
RAG triplo: PDFs de legislação (estático) + vault do projeto + postura histórica

POST /perguntar   { pergunta, relatorio?, user_id?, protocolo? } → { resposta }
GET  /saude                                                      → status
POST /indexar     { user_id, protocolo }  → força reindexação do vault
"""

import json
import os
import re
import hashlib
from pathlib import Path
from typing import Optional

import httpx
import chromadb
from chromadb.config import Settings
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from langchain_text_splitters import RecursiveCharacterTextSplitter
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

# ── Configuração ───────────────────────────────────────────────────────────────
OLLAMA_API_KEY  = os.getenv("OLLAMA_SPIRIT_KEY")
CORE_URL        = os.getenv("CORE_URL",       "http://localhost:8000")
MODELO          = os.getenv("SPIRIT_MODEL",   "gpt-oss:120b")
LEGISLACAO_DIR  = Path(os.getenv("LEGISLACAO_DIR",  "./legislacao"))
RESULTADOS_DIR  = Path(os.getenv("RESULTADOS_DIR",  "../resultados"))
CHROMA_DIR      = Path(os.getenv("CHROMA_DIR",      "./chroma_db"))
EMBED_MODEL     = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")

OLLAMA_URL = "https://ollama.com/v1/chat/completions"

# Chunks menores = mais precisão na recuperação
CHUNK_SIZE    = 512
CHUNK_OVERLAP = 64
TOP_K         = 4   # chunks por corpus

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="PhantomFix Spirit", version="0.4.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Modelos e clientes globais ─────────────────────────────────────────────────
_embedder: SentenceTransformer | None = None
_chroma:   chromadb.Client     | None = None
_relatorio_cache: dict | None = None


def get_embedder() -> SentenceTransformer:
    global _embedder
    if _embedder is None:
        print(f"[Spirit] Carregando modelo de embedding '{EMBED_MODEL}'...")
        _embedder = SentenceTransformer(EMBED_MODEL)
        print("[Spirit] Embedding model pronto.")
    return _embedder


def get_chroma() -> chromadb.Client:
    global _chroma
    if _chroma is None:
        CHROMA_DIR.mkdir(parents=True, exist_ok=True)
        _chroma = chromadb.PersistentClient(
            path=str(CHROMA_DIR),
            settings=Settings(anonymized_telemetry=False),
        )
    return _chroma


def embed(textos: list[str]) -> list[list[float]]:
    return get_embedder().encode(textos, show_progress_bar=False).tolist()


# ── Chunking ──────────────────────────────────────────────────────────────────
splitter = RecursiveCharacterTextSplitter(
    chunk_size=CHUNK_SIZE,
    chunk_overlap=CHUNK_OVERLAP,
    separators=["\n\n", "\n", ". ", " ", ""],
)


def _chunks(texto: str) -> list[str]:
    return [c for c in splitter.split_text(texto) if c.strip()]


# ── Extração de PDF ───────────────────────────────────────────────────────────
def extrair_texto_pdf(caminho: Path) -> str:
    try:
        import pypdf
        reader = pypdf.PdfReader(str(caminho))
        return "\n".join(p.extract_text() or "" for p in reader.pages)
    except Exception as e:
        print(f"[Spirit] ✗ Erro ao extrair {caminho.name}: {e}")
        return ""


# ── Corpus 1 — Legislação (estático, compartilhado) ──────────────────────────
COLECAO_LEG = "legislacao_v1"


def _hash_pdfs() -> str:
    """Hash dos PDFs para detectar mudança e forçar reindexação."""
    h = hashlib.md5()
    for pdf in sorted(LEGISLACAO_DIR.glob("*.pdf")):
        h.update(pdf.read_bytes())
    return h.hexdigest()


def indexar_legislacao():
    client = get_chroma()
    pdfs   = sorted(LEGISLACAO_DIR.glob("*.pdf"))
    if not pdfs:
        print("[Spirit] ⚠  Nenhum PDF de legislação encontrado.")
        return

    hash_atual = _hash_pdfs()

    # Verifica se já está indexado com os mesmos PDFs
    try:
        col = client.get_collection(COLECAO_LEG)
        meta = col.metadata or {}
        if meta.get("pdf_hash") == hash_atual:
            print(f"[Spirit] ✓ Legislação já indexada ({col.count()} chunks) — pulando.")
            return
        client.delete_collection(COLECAO_LEG)
    except Exception:
        pass

    print(f"[Spirit] Indexando {len(pdfs)} PDF(s) de legislação...")
    col = client.create_collection(
        COLECAO_LEG,
        metadata={"pdf_hash": hash_atual},
    )

    ids, docs, embeds, metas = [], [], [], []
    for pdf in pdfs:
        texto = extrair_texto_pdf(pdf)
        if not texto:
            continue
        for i, chunk in enumerate(_chunks(texto)):
            ids.append(f"{pdf.stem}_{i}")
            docs.append(chunk)
            metas.append({"fonte": pdf.name, "chunk": i})

    if ids:
        embeds = embed(docs)
        col.add(ids=ids, documents=docs, embeddings=embeds, metadatas=metas)
        print(f"[Spirit] ✓ Legislação indexada — {len(ids)} chunks.")


# ── Corpus 2 — Vault do projeto (por protocolo) ───────────────────────────────
def _nome_colecao_vault(user_id: int, protocolo: str) -> str:
    return f"vault_{user_id}_{protocolo}"


def indexar_vault(user_id: int, protocolo: str) -> int:
    """Indexa o vault de um scan específico. Retorna nº de chunks."""
    vault_path = RESULTADOS_DIR / str(user_id) / protocolo / "vault"
    if not vault_path.exists():
        print(f"[Spirit] ⚠  Vault não encontrado: {vault_path}")
        return 0

    client   = get_chroma()
    nome_col = _nome_colecao_vault(user_id, protocolo)

    # Apaga versão anterior se existir
    try:
        client.delete_collection(nome_col)
    except Exception:
        pass

    col  = client.create_collection(nome_col)
    mds  = list(vault_path.rglob("*.md"))
    ids, docs, embeds, metas = [], [], [], []

    for md in mds:
        texto = md.read_text(encoding="utf-8", errors="ignore")
        rel   = str(md.relative_to(vault_path))
        for i, chunk in enumerate(_chunks(texto)):
            ids.append(f"{rel}_{i}")
            docs.append(chunk)
            metas.append({"arquivo": rel, "chunk": i})

    if ids:
        embeds = embed(docs)
        col.add(ids=ids, documents=docs, embeddings=embeds, metadatas=metas)

    print(f"[Spirit] ✓ Vault {protocolo} indexado — {len(ids)} chunks ({len(mds)} arquivos .md).")
    return len(ids)


def _garantir_vault_indexado(user_id: int, protocolo: str):
    """Indexa o vault se ainda não estiver na base."""
    client   = get_chroma()
    nome_col = _nome_colecao_vault(user_id, protocolo)
    try:
        col = client.get_collection(nome_col)
        if col.count() > 0:
            return  # já indexado
    except Exception:
        pass
    indexar_vault(user_id, protocolo)


# ── Corpus 3 — Postura histórica (por usuário) ───────────────────────────────
def _nome_colecao_postura(user_id: int) -> str:
    return f"postura_{user_id}"


def _resumo_scan(relatorio: dict) -> str:
    """Transforma um relatório em texto narrativo para o corpus histórico."""
    vulns = relatorio.get("vulnerabilidades", [])
    criticas = sum(1 for v in vulns if (float(v.get("score") or 0)) >= 9)
    altas    = sum(1 for v in vulns if 7 <= (float(v.get("score") or 0)) < 9)
    medias   = sum(1 for v in vulns if 4 <= (float(v.get("score") or 0)) < 7)
    baixas   = sum(1 for v in vulns if (float(v.get("score") or 0)) < 4)

    top = sorted(vulns, key=lambda v: float(v.get("score") or 0), reverse=True)[:5]
    top_txt = "\n".join(
        f"  - {v.get('tipo','?')} em {v.get('arquivo','?')} (score {v.get('score','?')})"
        for v in top
    )

    return (
        f"Scan {relatorio.get('protocolo','?')} em {relatorio.get('analisado_em','?')[:10]}:\n"
        f"Repositório: {relatorio.get('repositorio','?')}\n"
        f"Total: {relatorio.get('total_encontrado', len(vulns))} vulnerabilidades "
        f"({criticas} críticas, {altas} altas, {medias} médias, {baixas} baixas)\n"
        f"Score médio: {relatorio.get('score_medio', '?')}\n"
        f"Top vulnerabilidades:\n{top_txt}"
    )


def indexar_postura(user_id: int):
    """Varre todos os relatórios do usuário e constrói corpus histórico."""
    base = RESULTADOS_DIR / str(user_id)
    if not base.exists():
        return

    client   = get_chroma()
    nome_col = _nome_colecao_postura(user_id)

    try:
        client.delete_collection(nome_col)
    except Exception:
        pass

    col  = client.create_collection(nome_col)
    ids, docs, embeds, metas = [], [], [], []

    for pasta in sorted(base.iterdir()):
        path = pasta / "relatorio.json"
        if not path.exists():
            continue
        try:
            rel = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        resumo = _resumo_scan(rel)
        protocolo = rel.get("protocolo", pasta.name)
        for i, chunk in enumerate(_chunks(resumo)):
            ids.append(f"{protocolo}_{i}")
            docs.append(chunk)
            metas.append({"protocolo": protocolo, "data": rel.get("analisado_em", "")[:10]})

    if ids:
        embeds = embed(docs)
        col.add(ids=ids, documents=docs, embeddings=embeds, metadatas=metas)
        print(f"[Spirit] ✓ Postura do user {user_id} indexada — {len(ids)} chunks.")


def _garantir_postura_indexada(user_id: int):
    client   = get_chroma()
    nome_col = _nome_colecao_postura(user_id)
    try:
        col = client.get_collection(nome_col)
        if col.count() > 0:
            return
    except Exception:
        pass
    indexar_postura(user_id)


# ── Busca vetorial ────────────────────────────────────────────────────────────
def _buscar(colecao: str, pergunta: str, k: int = TOP_K) -> list[str]:
    try:
        client = get_chroma()
        col    = client.get_collection(colecao)
        if col.count() == 0:
            return []
        vetor = embed([pergunta])[0]
        res   = col.query(query_embeddings=[vetor], n_results=min(k, col.count()))
        return res["documents"][0] if res["documents"] else []
    except Exception as e:
        print(f"[Spirit] ⚠  Busca em '{colecao}' falhou: {e}")
        return []


# ── Prompt ────────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """Você é o Spirit, assistente especializado em segurança de aplicações do PhantomFix.

Sua missão é TRADUZIR vulnerabilidades técnicas em impacto de negócio real,
tornando segurança da informação compreensível para qualquer pessoa — gestores,
diretores, equipes jurídicas e pessoas fora da área de TI.

DIRETRIZES:
1. Use linguagem acessível — explique como se a pessoa não soubesse o que é SQL Injection
2. Conecte cada vulnerabilidade ao impacto real: o que pode acontecer se for explorada?
3. Cite a LGPD com valores de multa (Art. 52: até 2% do faturamento ou R$ 50 mi por infração)
   e obrigação de notificação (Art. 48) quando houver risco a dados pessoais
4. Cite o controle ISO 27001 que está sendo violado (ex: A.8.28 — Codificação Segura)
5. Dê exemplos concretos: "um atacante poderia fazer X, acessando Y, causando Z"
6. Seja direto — vá ao ponto que importa para o negócio, sem enrolar
7. Tom: profissional, humano e construtivo
8. BASE sua resposta nos trechos de contexto fornecidos — cite tipos, scores e arquivos quando fizer sentido
9. NUNCA use tabelas markdown. Use listas numeradas ou tópicos com marcadores.

Responda sempre em português brasileiro."""


# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    print("[Spirit] Iniciando RAG triplo...")
    get_embedder()   # carrega modelo de embedding
    get_chroma()     # abre base vetorial
    indexar_legislacao()
    print("[Spirit] Spirit no ar 👻")


# ── Helpers de cache de relatório ─────────────────────────────────────────────
async def obter_relatorio(user_id: int | None = None, protocolo: str | None = None) -> dict | None:
    global _relatorio_cache
    params = {}
    if protocolo:
        params["protocolo"] = protocolo

    headers = {}
    if user_id:
        # Tenta carregar direto do disco (sem depender de auth)
        base = RESULTADOS_DIR / str(user_id)
        if protocolo:
            path = base / protocolo / "relatorio.json"
        else:
            pastas = sorted(
                (p for p in base.iterdir() if p.is_dir()),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            path = next(
                (p / "relatorio.json" for p in pastas if (p / "relatorio.json").exists()),
                None,
            )
        if path and path.exists():
            try:
                _relatorio_cache = json.loads(path.read_text(encoding="utf-8"))
                return _relatorio_cache
            except Exception:
                pass

    try:
        async with httpx.AsyncClient() as c:
            resp = await c.get(f"{CORE_URL}/relatorio", params=params, timeout=10)
            if resp.status_code == 200:
                _relatorio_cache = resp.json()
    except Exception as e:
        print(f"[Spirit] Não conseguiu buscar relatório: {e}")
    return _relatorio_cache


# ── Recomendação proativa de postura ──────────────────────────────────────────
async def gerar_recomendacao_proativa(user_id: int) -> str | None:
    """Chamado ao abrir a tela de postura — gera próximo passo com base no histórico."""
    _garantir_postura_indexada(user_id)

    pergunta = "Qual é a tendência de segurança deste projeto e qual deve ser o próximo passo prioritário?"
    chunks_postura = _buscar(_nome_colecao_postura(user_id), pergunta, k=6)
    if not chunks_postura:
        return None

    contexto = "\n\n".join(chunks_postura)
    prompt   = (
        f"Com base no histórico de scans abaixo, identifique a tendência de segurança "
        f"e recomende o próximo passo mais importante:\n\n{contexto}"
    )

    try:
        async with httpx.AsyncClient(timeout=60) as c:
            resp = await c.post(
                OLLAMA_URL,
                headers={"Authorization": f"Bearer {OLLAMA_API_KEY}"},
                json={
                    "model": MODELO,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": prompt},
                    ],
                    "max_tokens": 1024,
                    "temperature": 0.3,
                },
            )
            resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"[Spirit] Recomendação proativa falhou: {e}")
        return None


# ── Endpoints ─────────────────────────────────────────────────────────────────
class PerguntaRequest(BaseModel):
    pergunta:  str
    relatorio: dict | None = None
    user_id:   int  | None = None
    protocolo: str  | None = None


class IndexarRequest(BaseModel):
    user_id:   int
    protocolo: str


@app.get("/")
def raiz():
    return {"status": "PhantomFix Spirit funcionando", "versao": "0.4.0"}


@app.get("/saude")
def saude():
    client = get_chroma()
    cols   = [c.name for c in client.list_collections()]
    try:
        leg_count = client.get_collection(COLECAO_LEG).count()
    except Exception:
        leg_count = 0
    return {
        "status":            "ok",
        "modelo":            MODELO,
        "embed_model":       EMBED_MODEL,
        "legislacao_chunks": leg_count,
        "colecoes_ativas":   cols,
        "relatorio_em_cache": _relatorio_cache is not None,
    }


@app.post("/indexar")
def indexar(body: IndexarRequest):
    """Force reindexação do vault e postura de um usuário/scan."""
    n_vault   = indexar_vault(body.user_id, body.protocolo)
    indexar_postura(body.user_id)
    return {"ok": True, "vault_chunks": n_vault}


@app.get("/postura/recomendacao/{user_id}")
async def recomendacao_postura(user_id: int):
    if not OLLAMA_API_KEY:
        raise HTTPException(500, "OLLAMA_API_KEY não configurada")
    rec = await gerar_recomendacao_proativa(user_id)
    if not rec:
        raise HTTPException(404, "Histórico insuficiente para gerar recomendação")
    return {"recomendacao": rec}


@app.post("/perguntar")
async def perguntar(body: PerguntaRequest):
    if not OLLAMA_API_KEY:
        raise HTTPException(500, "OLLAMA_API_KEY não configurada")

    pergunta  = body.pergunta
    user_id   = body.user_id
    protocolo = body.protocolo

    # ── 1. Recupera relatório ─────────────────────────────────────────────────
    relatorio = body.relatorio or await obter_relatorio(user_id, protocolo)
    if relatorio and isinstance(relatorio.get("vulnerabilidades"), list):
        relatorio = {
            **relatorio,
            "vulnerabilidades": relatorio["vulnerabilidades"][:10],
        }

    # ── 2. Garante índices ────────────────────────────────────────────────────
    if user_id and protocolo:
        _garantir_vault_indexado(user_id, protocolo)
    if user_id:
        _garantir_postura_indexada(user_id)

    # ── 3. Busca vetorial nos 3 corpus ────────────────────────────────────────
    chunks_leg     = _buscar(COLECAO_LEG, pergunta)
    chunks_vault   = _buscar(_nome_colecao_vault(user_id, protocolo), pergunta) \
                     if user_id and protocolo else []
    chunks_postura = _buscar(_nome_colecao_postura(user_id), pergunta) \
                     if user_id else []

    # ── 4. Monta contexto ─────────────────────────────────────────────────────
    partes_contexto = []

    if chunks_leg:
        partes_contexto.append(
            "=== Legislação e normas (LGPD / ISO 27001 / NIST) ===\n"
            + "\n---\n".join(chunks_leg)
        )

    if chunks_vault:
        partes_contexto.append(
            "=== Vault do projeto (findings e análises) ===\n"
            + "\n---\n".join(chunks_vault)
        )

    if chunks_postura:
        partes_contexto.append(
            "=== Histórico de postura de segurança ===\n"
            + "\n---\n".join(chunks_postura)
        )

    if relatorio:
        partes_contexto.append(
            "=== Relatório do scan atual ===\n"
            + json.dumps(relatorio, indent=2, ensure_ascii=False)
        )
    else:
        partes_contexto.append("[Relatório indisponível — responda de forma geral.]")

    contexto_final = "\n\n".join(partes_contexto)

    # ── 5. Chama o LLM ───────────────────────────────────────────────────────
    try:
        async with httpx.AsyncClient(timeout=120) as c:
            resp = await c.post(
                OLLAMA_URL,
                headers={"Authorization": f"Bearer {OLLAMA_API_KEY}"},
                json={
                    "model": MODELO,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": f"{contexto_final}\n\n=== Pergunta ===\n{pergunta}"},
                    ],
                    "max_tokens": 10000,
                    "temperature": 0.4,
                },
            )
            resp.raise_for_status()
        return {"resposta": resp.json()["choices"][0]["message"]["content"]}

    except Exception as e:
        raise HTTPException(502, f"Erro no Ollama: {e}")
