"""
Autor e revisor: Rafael Pedro
PhantomFix — Database
SQLite para gerenciar usuários, tokens, sessões e projetos.
O arquivo phantomfix.db é criado automaticamente na primeira execução.
"""

import sqlite3
import secrets
import os
import uuid
from pathlib import Path
from datetime import datetime

import bcrypt

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

            CREATE TABLE IF NOT EXISTS projetos (
                id          TEXT PRIMARY KEY,
                user_id     INTEGER NOT NULL,
                nome        TEXT    NOT NULL,
                contexto    TEXT,
                github_url  TEXT,
                criado_em   TEXT    NOT NULL,
                FOREIGN KEY (user_id) REFERENCES usuarios(id)
            );

            CREATE TABLE IF NOT EXISTS reset_senha (
                token      TEXT    PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                expira_em  TEXT    NOT NULL,
                usado      INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES usuarios(id)
            );
        """)


# ── Helpers de senha (bcrypt) ─────────────────────────────────────────────────

def _hash_senha(senha: str) -> str:
    return bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()


def _verificar_hash(senha: str, senha_hash: str) -> bool:
    """Aceita bcrypt novo e SHA-256 legado (migração transparente)."""
    try:
        if senha_hash.startswith("$2"):  # bcrypt
            return bcrypt.checkpw(senha.encode(), senha_hash.encode())
        # legado SHA-256 — compara e sinaliza para rehash no login
        import hashlib
        return senha_hash == hashlib.sha256(senha.encode()).hexdigest()
    except Exception:
        return False


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
        return None


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
    """Retorna o usuário se email+senha corretos, senão None.
    Faz upgrade transparente de hash SHA-256 → bcrypt no login."""
    usuario = buscar_usuario_por_email(email)
    if not usuario:
        return None
    if not _verificar_hash(senha, usuario["senha_hash"]):
        return None
    # Upgrade de hash legado
    if not usuario["senha_hash"].startswith("$2"):
        novo_hash = _hash_senha(senha)
        with _conexao() as conn:
            conn.execute(
                "UPDATE usuarios SET senha_hash = ? WHERE id = ?",
                (novo_hash, usuario["id"]),
            )
        usuario["senha_hash"] = novo_hash
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


# ── Projetos ──────────────────────────────────────────────────────────────────

def criar_projeto(
    user_id: int,
    nome: str,
    contexto: dict | str | None = None,
    github_url: str | None = None,
) -> dict:
    projeto_id = str(uuid.uuid4())
    agora = datetime.now().isoformat()
    import json
    contexto_str = None
    if contexto is not None:
        contexto_str = contexto if isinstance(contexto, str) else json.dumps(contexto, ensure_ascii=False)
    with _conexao() as conn:
        conn.execute(
            """
            INSERT INTO projetos (id, user_id, nome, contexto, github_url, criado_em)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (projeto_id, user_id, nome, contexto_str, github_url, agora),
        )
    return buscar_projeto(projeto_id)


def listar_projetos(user_id: int) -> list[dict]:
    with _conexao() as conn:
        rows = conn.execute(
            "SELECT * FROM projetos WHERE user_id = ? ORDER BY criado_em DESC",
            (user_id,),
        ).fetchall()
    return [_projeto_dict(r) for r in rows]


def buscar_projeto(projeto_id: str) -> dict | None:
    with _conexao() as conn:
        row = conn.execute(
            "SELECT * FROM projetos WHERE id = ?", (projeto_id,)
        ).fetchone()
    return _projeto_dict(row) if row else None


def atualizar_projeto(
    projeto_id: str,
    user_id: int,
    nome: str | None = None,
    contexto: dict | str | None = None,
    github_url: str | None = None,
) -> dict | None:
    projeto = buscar_projeto(projeto_id)
    if not projeto or projeto["user_id"] != user_id:
        return None
    import json
    novo_nome = nome if nome is not None else projeto["nome"]
    novo_ctx = projeto.get("contexto")
    if contexto is not None:
        novo_ctx = contexto if isinstance(contexto, str) else json.dumps(contexto, ensure_ascii=False)
    novo_gh = github_url if github_url is not None else projeto.get("github_url")
    with _conexao() as conn:
        conn.execute(
            "UPDATE projetos SET nome = ?, contexto = ?, github_url = ? WHERE id = ?",
            (novo_nome, novo_ctx, novo_gh, projeto_id),
        )
    return buscar_projeto(projeto_id)


# ── Reset de senha ────────────────────────────────────────────────────────────

def criar_token_reset(user_id: int) -> str:
    """Gera um token de reset válido por 30 minutos. Invalida tokens anteriores do mesmo usuário."""
    from datetime import timedelta
    token = secrets.token_urlsafe(32)
    expira = (datetime.now() + timedelta(minutes=30)).isoformat()
    with _conexao() as conn:
        # Invalida tokens anteriores não usados
        conn.execute(
            "UPDATE reset_senha SET usado = 1 WHERE user_id = ? AND usado = 0",
            (user_id,),
        )
        conn.execute(
            "INSERT INTO reset_senha (token, user_id, expira_em, usado) VALUES (?, ?, ?, 0)",
            (token, user_id, expira),
        )
    return token


def validar_token_reset(token: str) -> dict | None:
    """Retorna o usuário se o token for válido e não expirado. Senão, None."""
    with _conexao() as conn:
        row = conn.execute(
            """
            SELECT u.*, r.expira_em FROM reset_senha r
            JOIN usuarios u ON u.id = r.user_id
            WHERE r.token = ? AND r.usado = 0
            """,
            (token,),
        ).fetchone()
    if not row:
        return None
    row = dict(row)
    if datetime.fromisoformat(row["expira_em"]) < datetime.now():
        return None
    return row


def consumir_token_reset(token: str, nova_senha: str) -> bool:
    """Troca a senha e marca o token como usado. Retorna True se bem-sucedido."""
    usuario = validar_token_reset(token)
    if not usuario:
        return False
    novo_hash = _hash_senha(nova_senha)
    with _conexao() as conn:
        conn.execute(
            "UPDATE usuarios SET senha_hash = ? WHERE id = ?",
            (novo_hash, usuario["id"]),
        )
        conn.execute(
            "UPDATE reset_senha SET usado = 1 WHERE token = ?",
            (token,),
        )
    return True


def _projeto_dict(row) -> dict:
    import json
    d = dict(row)
    ctx = d.get("contexto")
    if ctx and isinstance(ctx, str):
        try:
            d["contexto"] = json.loads(ctx)
        except (json.JSONDecodeError, TypeError):
            pass
    return d
