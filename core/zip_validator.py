"""
PhantomFix — Core / zip_validator.py
Validação do zip recebido em camadas, antes de qualquer extração.

Camadas (na ordem de execução):
  1. Magic bytes  — rejeita antes de abrir com zipfile
  2. Limite de upload — tamanho do arquivo comprimido
  3. Inspeção sem extração — Zip Slip, paths absolutos, symlinks, zip bomb
  4. Extração segura — arquivo por arquivo, com normalização e limite por arquivo
"""

import os
import zipfile
from pathlib import Path, PurePosixPath

# ── Limites configuráveis via env ─────────────────────────────────────────────
# Tamanho máximo do .zip recebido (bytes). Padrão: 500 MB.
MAX_ZIP_SIZE       = int(os.getenv("MAX_ZIP_SIZE",       str(500 * 1024 * 1024)))
# Tamanho máximo descomprimido total (bytes). Padrão: 2 GB.
MAX_UNCOMPRESSED   = int(os.getenv("MAX_UNCOMPRESSED",   str(2 * 1024 * 1024 * 1024)))
# Tamanho máximo de um único arquivo descomprimido (bytes). Padrão: 100 MB.
MAX_FILE_SIZE      = int(os.getenv("MAX_FILE_SIZE",      str(100 * 1024 * 1024)))
# Razão máxima de compressão (descomprimido / comprimido). Padrão: 100×.
MAX_COMPRESS_RATIO = int(os.getenv("MAX_COMPRESS_RATIO", "100"))
# Número máximo de entradas no zip. Padrão: 100 000.
MAX_ENTRIES        = int(os.getenv("MAX_ENTRIES",        "100000"))

# Magic bytes do ZIP: PK\x03\x04
_ZIP_MAGIC = b"PK\x03\x04"


class ZipValidationError(ValueError):
    """Lançada quando o zip falha em qualquer camada de validação."""
    pass


# ── Camada 1: Magic bytes ─────────────────────────────────────────────────────
def _verificar_magic_bytes(zip_path: Path) -> None:
    """
    Lê os primeiros 4 bytes do arquivo e rejeita se não for um ZIP real.
    Impede que arquivos disfarçados de .zip passem adiante.
    """
    try:
        with open(zip_path, "rb") as f:
            cabecalho = f.read(4)
    except OSError as e:
        raise ZipValidationError(f"Não foi possível ler o arquivo: {e}") from e

    if cabecalho != _ZIP_MAGIC:
        raise ZipValidationError(
            f"Arquivo rejeitado: magic bytes inválidos "
            f"(esperado PK\\x03\\x04, recebido {cabecalho.hex()!r}). "
            "Envie um arquivo .zip válido."
        )


# ── Camada 2: Tamanho do zip comprimido ───────────────────────────────────────
def _verificar_tamanho_zip(zip_path: Path) -> None:
    """
    Verifica o tamanho do arquivo .zip em disco antes de abrir.
    Protege contra uploads gigantes que consumiriam I/O desnecessário.
    """
    tamanho = zip_path.stat().st_size
    if tamanho > MAX_ZIP_SIZE:
        raise ZipValidationError(
            f"Arquivo .zip muito grande: {tamanho / 1024 / 1024:.1f} MB "
            f"(limite: {MAX_ZIP_SIZE / 1024 / 1024:.0f} MB)."
        )


# ── Camada 3: Inspeção sem extração ───────────────────────────────────────────
def _inspecionar_sem_extrair(zf: zipfile.ZipFile, destino: Path) -> None:
    """
    Percorre o índice do zip e rejeita entradas maliciosas SEM extrair nada.

    Verifica:
    - Número total de entradas (DoS por contagem)
    - Tamanho total descomprimido (zip bomb pelo volume)
    - Razão comprimido/descomprimido (zip bomb pela proporção)
    - Path traversal: entradas com ".." ou que comecem com "/"
    - Paths absolutos no Windows (ex: C:\\...)
    - Symlinks (file_attr bit 0xA no Unix ou external_attr específico)
    """
    entradas = zf.infolist()

    if len(entradas) > MAX_ENTRIES:
        raise ZipValidationError(
            f"Zip com entradas demais: {len(entradas):,} "
            f"(limite: {MAX_ENTRIES:,}). Envie apenas o código-fonte."
        )

    total_descomprimido = 0
    total_comprimido    = 0

    for info in entradas:
        # ── Zip Slip e paths absolutos ────────────────────────────────────────
        nome = info.filename

        # Normaliza separadores e rejeita ".." em qualquer segmento
        partes = PurePosixPath(nome.replace("\\", "/")).parts
        if ".." in partes:
            raise ZipValidationError(
                f"Path traversal detectado na entrada '{nome}'. "
                "Arquivo rejeitado por segurança."
            )

        # Rejeita paths absolutos (Unix: começa com "/"; Windows: "C:\...")
        if nome.startswith("/") or (len(nome) > 1 and nome[1] == ":"):
            raise ZipValidationError(
                f"Path absoluto detectado na entrada '{nome}'. "
                "Arquivo rejeitado por segurança."
            )

        # ── Symlinks ──────────────────────────────────────────────────────────
        # No ZIP, o tipo Unix é armazenado nos 4 bits superiores de
        # external_attr >> 16. 0xA000 = symlink no modo Unix.
        unix_type = (info.external_attr >> 16) & 0xF000
        if unix_type == 0xA000:
            # Symlink detectado — ignora silenciosamente (não extrai)
            info._pf_skip_symlink = True  # marcador para a extração segura

        # ── Acumuladores para zip bomb ────────────────────────────────────────
        total_descomprimido += info.file_size
        total_comprimido    += info.compress_size

    # Zip bomb pelo volume
    if total_descomprimido > MAX_UNCOMPRESSED:
        raise ZipValidationError(
            f"Conteúdo descomprimido muito grande: "
            f"{total_descomprimido / 1024 / 1024 / 1024:.2f} GB "
            f"(limite: {MAX_UNCOMPRESSED / 1024 / 1024 / 1024:.0f} GB)."
        )

    # Zip bomb pela razão (só aplica quando há algo comprimido)
    if total_comprimido > 0:
        razao = total_descomprimido / total_comprimido
        if razao > MAX_COMPRESS_RATIO:
            raise ZipValidationError(
                f"Razão de compressão suspeita: {razao:.0f}× "
                f"(limite: {MAX_COMPRESS_RATIO}×). Possível zip bomb."
            )


# ── Camada 4: Extração segura ─────────────────────────────────────────────────
def _extrair_com_seguranca(zf: zipfile.ZipFile, destino: Path) -> list[str]:
    """
    Extrai entrada por entrada com:
    - Normalização do path de destino (resolve ../ após junção)
    - Rejeição se o path resolvido sair do diretório de destino
    - Pulo de symlinks (marcados na inspeção anterior)
    - Limite de tamanho por arquivo individual durante a leitura

    Retorna lista dos caminhos extraídos (relativo ao destino).
    """
    extraidos: list[str] = []
    destino_resolvido = destino.resolve()

    for info in zf.infolist():
        # Pula symlinks detectados na inspeção
        if getattr(info, "_pf_skip_symlink", False):
            print(f"  [zip] Symlink ignorado: {info.filename!r}")
            continue

        # Pula diretórios — serão criados implicitamente via mkdir
        if info.filename.endswith("/"):
            continue

        # Normaliza o path: junta com destino e resolve
        nome_limpo   = info.filename.replace("\\", "/")
        caminho_alvo = (destino / nome_limpo).resolve()

        # Garante que o path resolvido está dentro do diretório de destino
        try:
            caminho_alvo.relative_to(destino_resolvido)
        except ValueError:
            raise ZipValidationError(
                f"Path traversal detectado durante extração: '{info.filename}'. "
                "Arquivo rejeitado por segurança."
            )

        # Cria diretório pai se necessário
        caminho_alvo.parent.mkdir(parents=True, exist_ok=True)

        # Extrai com limite de tamanho por arquivo
        with zf.open(info) as origem, open(caminho_alvo, "wb") as saida:
            bytes_escritos = 0
            while True:
                chunk = origem.read(65536)  # 64 KB por vez
                if not chunk:
                    break
                bytes_escritos += len(chunk)
                if bytes_escritos > MAX_FILE_SIZE:
                    # Remove o arquivo parcialmente escrito
                    saida.close()
                    caminho_alvo.unlink(missing_ok=True)
                    raise ZipValidationError(
                        f"Arquivo '{info.filename}' excede o limite individual de "
                        f"{MAX_FILE_SIZE / 1024 / 1024:.0f} MB durante extração."
                    )
                saida.write(chunk)

        extraidos.append(nome_limpo)

    return extraidos


# ── API pública ───────────────────────────────────────────────────────────────
def validar_e_extrair_zip(zip_path: Path, destino: Path) -> list[str]:
    """
    Ponto de entrada único. Executa todas as camadas de validação e,
    se aprovado, extrai o conteúdo de forma segura.

    Args:
        zip_path: Caminho para o arquivo .zip recebido.
        destino:  Diretório onde o conteúdo será extraído.

    Returns:
        Lista com os caminhos relativos de todos os arquivos extraídos.

    Raises:
        ZipValidationError: Em qualquer falha de validação.
        zipfile.BadZipFile:  Se o arquivo não puder ser aberto como ZIP.
    """
    # Garante que o destino existe
    destino.mkdir(parents=True, exist_ok=True)

    # ── Camada 1: Magic bytes (antes de abrir o zipfile) ──────────────────────
    _verificar_magic_bytes(zip_path)

    # ── Camada 2: Tamanho do zip em disco ────────────────────────────────────
    _verificar_tamanho_zip(zip_path)

    # Abre o zip uma única vez para as camadas 3 e 4
    with zipfile.ZipFile(zip_path, "r") as zf:

        # ── Camada 3: Inspeção sem extração ───────────────────────────────────
        _inspecionar_sem_extrair(zf, destino)

        # ── Camada 4: Extração segura ─────────────────────────────────────────
        extraidos = _extrair_com_seguranca(zf, destino)

    return extraidos
