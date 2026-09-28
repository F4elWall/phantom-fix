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

import pystray
from PIL import Image, ImageDraw
from plyer import notification

import config
from keychain import salvar_token, carregar_token, remover_token, token_configurado

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

def _criar_imagem_icone() -> Image.Image:
    ico_path = _caminho_recurso("phantom.ico")
    if ico_path.exists():
        return Image.open(ico_path).convert("RGBA").resize((64, 64), Image.LANCZOS)
    # fallback: desenha o fantasma programaticamente (como estava antes)
    img  = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # ... resto do código original ...
    return img


# ══════════════════════════════════════════════════════════════════════════════
# STATUS E NOTIFICAÇÕES
# ══════════════════════════════════════════════════════════════════════════════

def atualizar_status(texto: str):
    """Atualiza o tooltip do ícone na bandeja."""
    global _status_atual, _icon
    _status_atual = texto
    if _icon:
        _icon.title = f"PhantomFix — {texto}"


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
        salvar_token(novo_token.strip())
        atualizar_status("Token atualizado ✓")

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
