# PhantomFix — Copyright (C) 2025–2026 Rafael Pedro, Bernardo Coroa,
   # Giovanna Esmelardi, Gustavo Enrique
   # SPDX-License-Identifier: GPL-3.0-or-later
   # Licenciado sob a GNU GPL v3. Veja LICENSE.md na raiz do repositório.

"""
PhantomFix — Data-Control
empacotador.py

Valida o repositório local, filtra arquivos desnecessários
e gera o .zip pronto para envio ao Core.
"""

import tempfile
import zipfile
from pathlib import Path

# ── Itens excluídos do zip ────────────────────────────────────────────────────
PASTAS_EXCLUIDAS = {
    ".git", ".svn", ".hg",
    "node_modules", ".venv", "venv", "env", "__pycache__",
    ".tox", ".eggs", ".mypy_cache", ".pytest_cache",
    "dist", "build", "out", ".next", ".nuxt", "target",
    ".idea", ".vscode", ".vs",
}

EXTENSOES_EXCLUIDAS = {
    ".exe", ".dll", ".so", ".dylib", ".pyd",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
    ".mp4", ".mp3", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".log", ".tmp", ".cache", ".lock",
    ".pyc", ".pyo",
}

TAMANHO_MAXIMO_MB = 200


# ── Helpers ───────────────────────────────────────────────────────────────────

def _deve_excluir(caminho: Path, raiz: Path) -> bool:
    partes = caminho.relative_to(raiz).parts
    # Exclui se qualquer parte do caminho for uma pasta bloqueada
    for parte in partes[:-1]:
        if parte in PASTAS_EXCLUIDAS:
            return True
    # Exclui por extensão
    if caminho.suffix.lower() in EXTENSOES_EXCLUIDAS:
        return True
    return False


# ── API pública ───────────────────────────────────────────────────────────────

def validar_repositorio(pasta: Path) -> tuple[bool, str]:
    """
    Verifica se o repositório é válido para envio.
    Retorna (True, "OK") ou (False, "motivo do erro").
    """
    if not pasta.exists():
        return False, f"Pasta não encontrada: {pasta}"

    if not pasta.is_dir():
        return False, f"O caminho não é uma pasta: {pasta}"

    arquivos = [
        f for f in pasta.rglob("*")
        if f.is_file() and not _deve_excluir(f, pasta)
    ]

    if not arquivos:
        return False, "Nenhum arquivo encontrado após filtragem"

    tamanho_mb = sum(f.stat().st_size for f in arquivos) / 1024 / 1024
    if tamanho_mb > TAMANHO_MAXIMO_MB:
        return False, f"Repositório muito grande: {tamanho_mb:.1f} MB (limite: {TAMANHO_MAXIMO_MB} MB)"

    return True, "OK"


def zipar_repositorio(pasta: Path, callback_status=None) -> Path:
    """
    Filtra e compacta o repositório em um arquivo .zip temporário.

    Args:
        pasta:           Path da pasta do repositório
        callback_status: função opcional para reportar progresso (recebe str)

    Returns:
        Path do arquivo .zip gerado (em pasta temporária do sistema)
    """
    pasta = Path(pasta)

    # Coleta arquivos válidos
    arquivos = sorted([
        f for f in pasta.rglob("*")
        if f.is_file() and not _deve_excluir(f, pasta)
    ])

    excluidos = [
        f for f in pasta.rglob("*")
        if f.is_file() and _deve_excluir(f, pasta)
    ]

    if callback_status:
        callback_status(f"Empacotando {len(arquivos)} arquivos ({len(excluidos)} excluídos)...")

    # Gera zip em pasta temporária
    tmp_dir  = Path(tempfile.mkdtemp())
    zip_path = tmp_dir / "repositorio.zip"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, arquivo in enumerate(arquivos):
            zf.write(arquivo, arquivo.relative_to(pasta))
            if callback_status and i % 50 == 0:
                callback_status(f"Empacotando... ({i}/{len(arquivos)})")

    tamanho_mb = zip_path.stat().st_size / 1024 / 1024

    if callback_status:
        callback_status(f"Zip gerado: {tamanho_mb:.1f} MB")

    return zip_path
