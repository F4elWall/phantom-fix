"""
PhantomFix — Data-Control
bandeja.py

Ícone na bandeja do sistema Windows.
Menu contextual com "Analisar agora", "Configurações" e "Sair".
"""

import threading
import tkinter as tk
from tkinter import filedialog, simpledialog
from pathlib import Path

import requests
import pystray
from PIL import Image, ImageDraw
from plyer import notification

import config
from keychain import salvar_token, carregar_token, remover_token, token_configurado

CORE_URL_PADRAO = "https://phantom-fix.southafricanorth.cloudapp.azure.com/api/"


def _vincular_token_no_core(token: str) -> bool:
    """Chama POST /auth/link-client para marcar o client como vinculado."""
    try:
        core_url = config.get("core_url", CORE_URL_PADRAO).rstrip("/")
        resp = requests.post(
            f"{core_url}/auth/link-client",
            json={"token": token},
            timeout=10,
        )
        return resp.status_code == 200
    except Exception as e:
        print(f"[bandeja] Erro ao vincular token: {e}")
        return False

import sys
from pathlib import Path

def _caminho_recurso(nome: str) -> Path:
    """Retorna o caminho correto do recurso, dentro ou fora do .exe."""
    if hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / nome   # rodando como .exe
    return Path(__file__).parent / nome    # rodando como .py

# ── Estado global da bandeja ──────────────────────────────────────────────────
_icon: pystray.Icon | None = None
_status_atual = "Idle"


# ══════════════════════════════════════════════════════════════════════════════
# ÍCONE
# ══════════════════════════════════════════════════════════════════════════════

# Windows bandeja: 16/32 no tray clássico; com DPI alto usa 48–64.
# Geramos 64x64 com o desenho preenchendo o canvas (sem padding excessivo).
_ICONE_TAMANHO = 64


def _crop_conteudo(img: Image.Image, margem: float = 0.08) -> Image.Image:
    """Remove transparência ao redor do logo para ele ocupar o ícone inteiro."""
    if img.mode != "RGBA":
        img = img.convert("RGBA")
    alpha = img.split()[-1]
    bbox = alpha.getbbox()
    if not bbox:
        return img
    cropped = img.crop(bbox)
    # pequena margem para não colar nas bordas
    w, h = cropped.size
    pad = int(max(w, h) * margem)
    canvas = Image.new("RGBA", (w + pad * 2, h + pad * 2), (0, 0, 0, 0))
    canvas.paste(cropped, (pad, pad), cropped)
    return canvas


def _criar_imagem_icone(cor_status: tuple | None = None) -> Image.Image:
    """
    Ícone legível na bandeja do Windows (inclui DPI alto).
    cor_status opcional: (R,G,B) para badge de estado no canto.
    """
    size = _ICONE_TAMANHO
    ico_path = _caminho_recurso("phantom.ico")

    if ico_path.exists():
        try:
            src = Image.open(ico_path)
            # .ico multi-size: pega o maior frame disponível
            melhor = src
            try:
                n = getattr(src, "n_frames", 1) or 1
                maior = 0
                for i in range(n):
                    src.seek(i)
                    area = src.size[0] * src.size[1]
                    if area > maior:
                        maior = area
                        melhor = src.copy()
            except Exception:
                melhor = src
            img = melhor.convert("RGBA")
            img = _crop_conteudo(img)
            # LANCZOS: Pillow >= 9 usa Resampling; versões antigas usam constante direta
            try:
                resample = Image.Resampling.LANCZOS
            except AttributeError:
                resample = Image.LANCZOS
            img = img.resize((size, size), resample)
        except Exception:
            img = _icone_fallback(size)
    else:
        img = _icone_fallback(size)

    if cor_status:
        draw = ImageDraw.Draw(img)
        r = max(4, size // 8)
        # bolinha no canto inferior direito
        x0, y0 = size - r * 2 - 2, size - r * 2 - 2
        draw.ellipse([x0, y0, x0 + r * 2, y0 + r * 2], fill=cor_status + (255,))

    return img


def _icone_fallback(size: int = 64) -> Image.Image:
    """Fantasma simples preenchendo o canvas — legível em 16–64 px."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # corpo
    margin = size // 10
    body = [margin, margin + size // 6, size - margin, size - margin]
    draw.ellipse(
        [body[0], body[1], body[2], body[1] + (body[3] - body[1]) * 0.7],
        fill=(99, 102, 241, 255),  # indigo
    )
    # base ondulada
    mid_y = int(body[1] + (body[3] - body[1]) * 0.45)
    draw.rectangle([body[0], mid_y, body[2], body[3] - size // 12], fill=(99, 102, 241, 255))
    wave_h = size // 10
    for i in range(3):
        x0 = body[0] + i * (body[2] - body[0]) // 3
        x1 = body[0] + (i + 1) * (body[2] - body[0]) // 3
        draw.ellipse([x0, body[3] - wave_h * 2, x1, body[3]], fill=(99, 102, 241, 255))
    # olhos
    eye_r = max(2, size // 14)
    cy = margin + size // 3
    draw.ellipse([size // 3 - eye_r, cy - eye_r, size // 3 + eye_r, cy + eye_r], fill=(255, 255, 255, 255))
    draw.ellipse([2 * size // 3 - eye_r, cy - eye_r, 2 * size // 3 + eye_r, cy + eye_r], fill=(255, 255, 255, 255))
    return img


# ══════════════════════════════════════════════════════════════════════════════
# STATUS E NOTIFICAÇÕES
# ══════════════════════════════════════════════════════════════════════════════

def atualizar_status(texto: str):
    """Atualiza o tooltip do ícone na bandeja e badge de cor por estado."""
    global _status_atual, _icon
    _status_atual = texto
    if not _icon:
        return
    _icon.title = f"PhantomFix — {texto}"
    t = texto.lower()
    cor = None
    if any(x in t for x in ("erro", "falha", "⚠", "✗")):
        cor = (239, 68, 68)       # vermelho
    elif any(x in t for x in ("enviando", "validando", "empacot", "agendado")):
        cor = (245, 158, 11)      # âmbar
    elif any(x in t for x in ("sucesso", "✓", "enviado", "conclu")):
        cor = (16, 185, 129)      # verde
    try:
        _icon.icon = _criar_imagem_icone(cor_status=cor)
    except Exception:
        pass


def notificar(titulo: str, mensagem: str):
    """Envia notificação nativa do Windows."""
    try:
        notification.notify(
            title=titulo,
            message=mensagem,
            app_name="PhantomFix",
            timeout=5,
        )
    except Exception:
        pass   # notificação não crítica


# ══════════════════════════════════════════════════════════════════════════════
# TELA DE CONFIGURAÇÕES
# ══════════════════════════════════════════════════════════════════════════════

def _abrir_configuracoes():
    """Janela simples de configuração via tkinter."""
    root = tk.Tk()
    root.withdraw()   # esconde a janela principal

    cfg = config.carregar_config()

    # ── Token ─────────────────────────────────────────────────────────────────
    token_atual = "••••••••" if token_configurado() else "(não configurado)"
    novo_token = simpledialog.askstring(
        "PhantomFix — Token",
        f"Token de acesso atual: {token_atual}\n\nNovo token (deixe vazio para manter):",
        parent=root,
    )
    if novo_token and novo_token.strip():
        token_limpo = novo_token.strip()
        salvar_token(token_limpo)
        atualizar_status("Vinculando token...")
        ok = _vincular_token_no_core(token_limpo)
        if ok:
            atualizar_status("Token vinculado ✓")
            notificar("PhantomFix", "Conta vinculada com sucesso!")
        else:
            atualizar_status("Token salvo (sem conexão com o Core)")
            notificar("PhantomFix — Aviso", "Token salvo localmente, mas não foi possível confirmar com o servidor.")

    # ── Pasta do repositório ──────────────────────────────────────────────────
    pasta_atual = cfg.get("pasta_repo", "")
    resposta = simpledialog.askstring(
        "PhantomFix — Pasta",
        f"Pasta atual: {pasta_atual or '(não configurada)'}\n\n"
        "Clique OK para escolher uma pasta, ou Cancelar para manter:",
        parent=root,
    )
    if resposta is not None:
        nova_pasta = filedialog.askdirectory(
            title="Selecione a pasta do repositório",
            initialdir=pasta_atual or "/",
        )
        if nova_pasta:
            config.set("pasta_repo", nova_pasta)
            atualizar_status(f"Pasta configurada: {Path(nova_pasta).name}")

    root.destroy()


# ══════════════════════════════════════════════════════════════════════════════
# MENU
# ══════════════════════════════════════════════════════════════════════════════

def _menu_analisar(icon, item, ao_analisar):
    threading.Thread(target=ao_analisar, daemon=True).start()


def _menu_configuracoes(icon, item):
    threading.Thread(target=_abrir_configuracoes, daemon=True).start()


def _menu_sair(icon, item):
    icon.stop()


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def iniciar_bandeja(ao_analisar):
    """
    Inicia o ícone na bandeja. Bloqueia até o usuário clicar em Sair.

    Args:
        ao_analisar: função chamada quando o usuário clica em "Analisar agora"
    """
    global _icon

    menu = pystray.Menu(
        pystray.MenuItem("Analisar agora", lambda i, it: _menu_analisar(i, it, ao_analisar)),
        pystray.MenuItem("Configurações",  _menu_configuracoes),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(lambda text: f"Status: {_status_atual}", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Sair", _menu_sair),
    )

    _icon = pystray.Icon(
        name="PhantomFix",
        icon=_criar_imagem_icone(),
        title="PhantomFix — Idle",
        menu=menu,
    )

    _icon.run()
