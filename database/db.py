"""
Autor e revisor: Rafael Pedro
PhantomFix — Database
SQLite simples para gerenciar usuários, tokens e sessões.
O arquivo phantomfix.db é criado automaticamente na primeira execução.
"""

import sqlite3
import secrets
import hashlib
import os
from pathlib import Path
from datetime import datetime

DB_PATH = Path(os.getenv("PHANTOMFIX_DB", Path(__file__).parent / "phantomfix.db"))


def _conexao():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def inicializar_banco():
    """Cria as tabelas se não existirem. Chamado uma vez ao subir o servidor."""
    with _conexao() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                nome          TEXT    NOT NULL,
                email         TEXT    NOT NULL UNIQUE,
                senha_hash    TEXT    NOT NULL,
                token         TEXT    NOT NULL UNIQUE,
                client_linked INTEGER NOT NULL DEFAULT 0,
                criado_em     TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessoes (
                session_token TEXT PRIMARY KEY,
                user_id       INTEGER NOT NULL,
                criado_em     TEXT    NOT NULL,
                FOREIGN KEY (user_id) REFERENCES usuarios(id)
            );
        """)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hash_senha(senha: str) -> str:
    return hashlib.sha256(senha.encode()).hexdigest()

def _gerar_token() -> str:
    return secrets.token_hex(16)


# ── Usuários ──────────────────────────────────────────────────────────────────

def criar_usuario(nome: str, email: str, senha: str) -> dict | None:
    """Cria um novo usuário. Retorna None se o e-mail já existir."""
    token = _gerar_token()
    agora = datetime.now().isoformat()
    try:
        with _conexao() as conn:
            conn.execute(
                "INSERT INTO usuarios (nome, email, senha_hash, token, client_linked, criado_em) VALUES (?, ?, ?, ?, 0, ?)",
                (nome, email, _hash_senha(senha), token, agora),
            )
        return buscar_usuario_por_email(email)
    except sqlite3.IntegrityError:
        return None  # e-mail duplicado


def buscar_usuario_por_email(email: str) -> dict | None:
    with _conexao() as conn:
        row = conn.execute("SELECT * FROM usuarios WHERE email = ?", (email,)).fetchone()
    return dict(row) if row else None


def buscar_usuario_por_id(user_id: int) -> dict | None:
    with _conexao() as conn:
        row = conn.execute("SELECT * FROM usuarios WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def buscar_usuario_por_token(token: str) -> dict | None:
    with _conexao() as conn:
        row = conn.execute("SELECT * FROM usuarios WHERE token = ?", (token,)).fetchone()
    return dict(row) if row else None


def verificar_senha(email: str, senha: str) -> dict | None:
    """Retorna o usuário se email+senha corretos, senão None."""
    usuario = buscar_usuario_por_email(email)
    if not usuario:
        return None
    if usuario["senha_hash"] != _hash_senha(senha):
        return None
    return usuario


def regenerar_token(user_id: int) -> str:
    """Gera novo token e reseta o vínculo com o client."""
    novo_token = _gerar_token()
    with _conexao() as conn:
        conn.execute(
            "UPDATE usuarios SET token = ?, client_linked = 0 WHERE id = ?",
            (novo_token, user_id),
        )
    return novo_token


def marcar_client_vinculado(token: str) -> bool:
    """Chamado pelo executável ao colar o token. Retorna True se encontrou o token."""
    with _conexao() as conn:
        cur = conn.execute(
            "UPDATE usuarios SET client_linked = 1 WHERE token = ?", (token,)
        )
    return cur.rowcount > 0


def verificar_client_vinculado(user_id: int) -> bool:
    usuario = buscar_usuario_por_id(user_id)
    return bool(usuario and usuario["client_linked"])


# ── Sessões ───────────────────────────────────────────────────────────────────

def criar_sessao(user_id: int) -> str:
    session_token = secrets.token_hex(32)
    agora = datetime.now().isoformat()
    with _conexao() as conn:
        conn.execute(
            "INSERT INTO sessoes (session_token, user_id, criado_em) VALUES (?, ?, ?)",
            (session_token, user_id, agora),
        )
    return session_token


def buscar_sessao(session_token: str) -> dict | None:
    with _conexao() as conn:
        row = conn.execute(
            """
            SELECT u.* FROM sessoes s
            JOIN usuarios u ON u.id = s.user_id
            WHERE s.session_token = ?
            """,
            (session_token,),
        ).fetchone()
    return dict(row) if row else None


def deletar_sessao(session_token: str):
    with _conexao() as conn:
        conn.execute("DELETE FROM sessoes WHERE session_token = ?", (session_token,))
