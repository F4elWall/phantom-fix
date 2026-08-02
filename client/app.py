"""
PhantomFix — Cliente
Duas telas:
  1. TelaVinculacao — cola o token, valida, puxa o nome da conta
  2. TelaAnalise    — escolhe pasta, envia para o Core
"""

import zipfile
import json
import os
import sys
import threading
import tempfile
from pathlib import Path
from tkinter import filedialog, messagebox

import requests
import customtkinter as ctk
from PIL import Image

# ── URLs ──────────────────────────────────────────────────────────────────────
CORE_URL = os.getenv("PHANTOMFIX_CORE_URL", "https://phantom-fix.duckdns.org/api/scan")
LINK_URL = CORE_URL.replace("/scan", "/auth/link-client")
ME_URL   = CORE_URL.replace("/scan", "/auth/me-by-token")   # rota que vamos criar

# ── Cores ─────────────────────────────────────────────────────────────────────
BG          = "#0B0F19"
CARD        = "#111827"
BORDER      = "#1F2937"
PRIMARY     = "#6366F1"
SUCCESS     = "#10B981"
DANGER      = "#EF4444"
WARNING     = "#F59E0B"
TEXT_MAIN   = "#F9FAFB"
TEXT_DIM    = "#9CA3AF"

# ── Token persistido localmente ───────────────────────────────────────────────
TOKEN_FILE = Path.home() / ".phantomfix_token"

def carregar_token() -> str:
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    return ""

def salvar_token(token: str):
    TOKEN_FILE.write_text(token.strip(), encoding="utf-8")

def apagar_token():
    if TOKEN_FILE.exists():
        TOKEN_FILE.unlink()

# ── Logo ──────────────────────────────────────────────────────────────────────
BASE_DIR = Path(sys._MEIPASS) if getattr(sys, "frozen", False) else Path(__file__).parent
PATH_LOGO = BASE_DIR / "ghost_logo_large.png"

def carregar_logo(tamanho=80):
    try:
        if PATH_LOGO.exists():
            img = Image.open(PATH_LOGO)
            w, h = img.size
            nh = int((tamanho / w) * h)
            return ctk.CTkImage(light_image=img, dark_image=img, size=(tamanho, nh))
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
# TELA 1 — Vinculação de Token
# ══════════════════════════════════════════════════════════════════════════════
class TelaVinculacao(ctk.CTkFrame):
    def __init__(self, master, on_vinculado):
        super().__init__(master, fg_color=BG)
        self.on_vinculado = on_vinculado
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=1)

        # Card central
        card = ctk.CTkFrame(self, fg_color=CARD, border_color=BORDER, border_width=1, corner_radius=16)
        card.grid(row=1, column=0, padx=80, pady=20, sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        # Logo
        logo = carregar_logo(72)
        if logo:
            ctk.CTkLabel(card, image=logo, text="").grid(row=0, column=0, pady=(32, 0))
        else:
            ctk.CTkLabel(card, text="👻", font=("Segoe UI", 48)).grid(row=0, column=0, pady=(32, 0))

        ctk.CTkLabel(card, text="PhantomFix", font=("Segoe UI", 28, "bold"), text_color=TEXT_MAIN).grid(row=1, column=0, pady=(8, 0))
        ctk.CTkLabel(card, text="Cole seu token para vincular esta máquina à sua conta.",
                     font=("Segoe UI", 13), text_color=TEXT_DIM, wraplength=340).grid(row=2, column=0, pady=(6, 24))

        # Campo token
        self.entry = ctk.CTkEntry(
            card, placeholder_text="Cole seu token aqui...",
            width=340, height=42,
            border_color=BORDER, fg_color=BG, text_color=TEXT_MAIN,
            font=("Segoe UI", 13), corner_radius=8
        )
        token_salvo = carregar_token()
        if token_salvo:
            self.entry.insert(0, token_salvo)
        self.entry.grid(row=3, column=0, padx=40, pady=(0, 8))
        self.entry.bind("<Return>", lambda e: self._vincular())

        # Mensagem de erro/status
        self.lbl_status = ctk.CTkLabel(card, text="", font=("Segoe UI", 12), text_color=DANGER)
        self.lbl_status.grid(row=4, column=0, pady=(0, 8))

        # Botão vincular
        self.btn = ctk.CTkButton(
            card, text="Vincular conta →",
            font=("Segoe UI", 14, "bold"),
            fg_color=PRIMARY, hover_color="#4F46E5",
            corner_radius=8, height=44, width=340,
            command=self._vincular
        )
        self.btn.grid(row=5, column=0, padx=40, pady=(0, 32))

        # Rodapé
        ctk.CTkLabel(self, text="👻 PhantomFix Client v1.0.0",
                     font=("Segoe UI", 11), text_color="#3F435C").grid(row=2, column=0, pady=12)

    def _vincular(self):
        token = self.entry.get().strip()
        if not token:
            self.lbl_status.configure(text="Cole o token antes de continuar.", text_color=DANGER)
            return

        self.btn.configure(state="disabled", text="Verificando...")
        self.lbl_status.configure(text="", text_color=DANGER)

        threading.Thread(target=self._verificar_token, args=(token,), daemon=True).start()

    def _verificar_token(self, token):
        try:
            resp = requests.post(LINK_URL, json={"token": token}, timeout=10)
            if resp.status_code == 200:
                salvar_token(token)
                # Tenta puxar o nome da conta
                nome = self._buscar_nome(token)
                self.after(0, lambda: self.on_vinculado(token, nome))
            elif resp.status_code == 404:
                self.after(0, lambda: self._erro("Token não encontrado. Verifique e tente novamente."))
            else:
                self.after(0, lambda: self._erro(f"Erro do servidor ({resp.status_code}). Tente novamente."))
        except requests.exceptions.ConnectionError:
            self.after(0, lambda: self._erro("Sem conexão com o servidor. Verifique sua internet."))
        except Exception as e:
            self.after(0, lambda: self._erro(f"Erro inesperado: {e}"))

    def _buscar_nome(self, token) -> str:
        """Tenta buscar o nome do usuário pelo token. Retorna string vazia se falhar."""
        try:
            resp = requests.get(ME_URL, params={"token": token}, timeout=5)
            if resp.status_code == 200:
                return resp.json().get("nome", "")
        except Exception:
            pass
        return ""

    def _erro(self, msg):
        self.lbl_status.configure(text=msg, text_color=DANGER)
        self.btn.configure(state="normal", text="Vincular conta →")


# ══════════════════════════════════════════════════════════════════════════════
# TELA 2 — Análise
# ══════════════════════════════════════════════════════════════════════════════
class TelaAnalise(ctk.CTkFrame):
    def __init__(self, master, token: str, nome: str, on_desvincular):
        super().__init__(master, fg_color=BG)
        self.token         = token
        self.nome          = nome or "Usuário"
        self.on_desvincular = on_desvincular
        self.pasta_selecionada = None
        self.timeline_steps    = []

        self.grid_columnconfigure(0, weight=1)
        for r in range(7):
            self.grid_rowconfigure(r, weight=0)
        self.grid_rowconfigure(6, weight=1)

        self._build()

    def _build(self):
        # ── Cabeçalho ────────────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, pady=(20, 5), sticky="n")

        logo = carregar_logo(100)
        if logo:
            ctk.CTkLabel(header, image=logo, text="").pack()
        else:
            ctk.CTkLabel(header, text="👻", font=("Segoe UI", 52)).pack()

        ctk.CTkLabel(header, text="PhantomFix", font=("Segoe UI", 30, "bold"), text_color=TEXT_MAIN).pack(pady=(4, 0))
        ctk.CTkLabel(header, text="ANÁLISE DE VULNERABILIDADES", font=("Segoe UI", 11, "bold"), text_color=TEXT_DIM).pack()

        # Badge de conta vinculada
        badge = ctk.CTkFrame(header, fg_color="#0D2B1F", border_color=SUCCESS, border_width=1, corner_radius=20)
        badge.pack(pady=(10, 0))
        ctk.CTkLabel(badge, text=f"✓  Conta vinculada  ·  {self.nome}",
                     font=("Segoe UI", 12, "bold"), text_color=SUCCESS).pack(padx=16, pady=6)

        # Botão desvincular discreto
        ctk.CTkButton(
            header, text="Trocar conta", font=("Segoe UI", 11),
            fg_color="transparent", hover_color="#1F2937",
            text_color=TEXT_DIM, height=24, width=100,
            command=self._confirmar_desvincular
        ).pack(pady=(4, 0))

        # ── Card repositório ──────────────────────────────────────────────────
        card_repo = self._card(row=1)
        card_repo.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card_repo, text="📁", font=("Segoe UI", 24), text_color=PRIMARY).grid(row=0, column=0, rowspan=2, padx=(20,15), sticky="w")
        ctk.CTkLabel(card_repo, text="Repositório", font=("Segoe UI", 14, "bold"), text_color=TEXT_MAIN).grid(row=0, column=1, sticky="w", pady=(12,0))
        self.lbl_repo = ctk.CTkLabel(card_repo, text="Selecione a pasta do seu projeto para iniciar a análise.",
                                      font=("Segoe UI", 12), text_color=TEXT_DIM)
        self.lbl_repo.grid(row=1, column=1, sticky="w", pady=(0,12))
        ctk.CTkButton(card_repo, text="📁  Escolher pasta", font=("Segoe UI", 12, "bold"),
                      fg_color=PRIMARY, hover_color="#4F46E5", corner_radius=8, height=38,
                      command=self._escolher_pasta).grid(row=0, column=2, rowspan=2, padx=20, sticky="e")

        # ── Card URL ──────────────────────────────────────────────────────────
        card_url = self._card(row=2)
        card_url.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card_url, text="🔗", font=("Segoe UI", 20), text_color=PRIMARY).grid(row=0, column=0, rowspan=2, padx=(20,15), sticky="w")
        ctk.CTkLabel(card_url, text="URL da aplicação (opcional)", font=("Segoe UI", 14, "bold"), text_color=TEXT_MAIN).grid(row=0, column=1, sticky="w", pady=(12,0))
        ctk.CTkLabel(card_url, text="Informe a URL em produção para o teste dinâmico.",
                     font=("Segoe UI", 12), text_color=TEXT_DIM).grid(row=1, column=1, sticky="w", pady=(0,12))
        self.entry_url = ctk.CTkEntry(card_url, placeholder_text="https://exemplo.com",
                                       width=280, height=36, border_color=BORDER,
                                       fg_color=BG, text_color=TEXT_MAIN, corner_radius=6)
        self.entry_url.grid(row=0, column=2, rowspan=2, padx=20, sticky="e")

        # ── Card progresso ────────────────────────────────────────────────────
        card_prog = ctk.CTkFrame(self, fg_color=CARD, border_color=BORDER, border_width=1, corner_radius=12, height=170)
        card_prog.grid(row=3, column=0, padx=30, pady=5, sticky="ew")
        card_prog.pack_propagate(False)

        ctk.CTkLabel(card_prog, text="Progresso da análise", font=("Segoe UI", 14, "bold"), text_color=TEXT_MAIN).pack(anchor="w", padx=20, pady=(12,5))

        tl_frame = ctk.CTkFrame(card_prog, fg_color="transparent")
        tl_frame.pack(fill="x", padx=40, pady=5)
        self._build_timeline(tl_frame)

        si = ctk.CTkFrame(card_prog, fg_color=BG, corner_radius=6, border_width=1, border_color=BORDER)
        si.pack(fill="x", padx=20, pady=(10,12))
        self.icon_status = ctk.CTkLabel(si, text="ℹ️", font=("Segoe UI", 14), text_color=PRIMARY)
        self.icon_status.pack(side="left", padx=(12,5), pady=8)
        self.lbl_status = ctk.CTkLabel(si, text="Selecione um repositório para iniciar.", font=("Segoe UI", 12), text_color=TEXT_DIM)
        self.lbl_status.pack(side="left", pady=8)

        # ── Botão iniciar ─────────────────────────────────────────────────────
        action = ctk.CTkFrame(self, fg_color="transparent")
        action.grid(row=4, column=0, padx=30, pady=10, sticky="e")
        self.btn_iniciar = ctk.CTkButton(
            action, text="🚀 Iniciar Análise", font=("Segoe UI", 14, "bold"),
            fg_color=PRIMARY, hover_color="#4F46E5", corner_radius=8,
            width=180, height=42, state="disabled", command=self._disparar
        )
        self.btn_iniciar.pack()

        # ── Rodapé ────────────────────────────────────────────────────────────
        ctk.CTkLabel(self, text="👻 PhantomFix Client v1.0.0",
                     font=("Segoe UI", 11), text_color="#3F435C").grid(row=6, column=0, pady=15, sticky="s")

    def _card(self, row):
        c = ctk.CTkFrame(self, fg_color=CARD, border_color=BORDER, border_width=1, corner_radius=12, height=100)
        c.grid(row=row, column=0, padx=30, pady=5, sticky="ew")
        c.grid_propagate(False)
        return c

    def _build_timeline(self, parent):
        steps = [("1","Repositório","📁"), ("2","Compactando","📄"), ("3","Enviando","☁️"), ("4","Analisando","🛡️")]
        parent.grid_columnconfigure(tuple(range(len(steps)*2-1)), weight=1)
        for i, (num, label, icon) in enumerate(steps):
            col = i * 2
            cont = ctk.CTkFrame(parent, fg_color="transparent")
            cont.grid(row=0, column=col, sticky="nsew")
            circle = ctk.CTkLabel(cont, text=num, width=28, height=28, corner_radius=14,
                                   fg_color="#1F2937", text_color=TEXT_DIM, font=("Segoe UI", 12, "bold"))
            circle.pack()
            lbl = ctk.CTkLabel(cont, text=label, font=("Segoe UI", 11, "bold"), text_color="#4B5563")
            lbl.pack(pady=(4,0))
            sub = ctk.CTkLabel(cont, text="Aguardando", font=("Segoe UI", 10), text_color="#374151")
            sub.pack()
            self.timeline_steps.append({"circle": circle, "label": lbl, "sub": sub, "line": None})
            if i < len(steps) - 1:
                line = ctk.CTkFrame(parent, fg_color="#1F2937", height=2)
                line.grid(row=0, column=col+1, sticky="ew", padx=5, pady=(12,0))
                self.timeline_steps[i]["line"] = line

    def _passo(self, idx, status, cor):
        self.timeline_steps[idx]["circle"].configure(fg_color=cor, text_color=TEXT_MAIN)
        self.timeline_steps[idx]["label"].configure(text_color=TEXT_MAIN)
        self.timeline_steps[idx]["sub"].configure(text=status, text_color=cor)
        if idx > 0 and self.timeline_steps[idx-1]["line"]:
            self.timeline_steps[idx-1]["line"].configure(fg_color=cor)

    def _escolher_pasta(self):
        pasta = filedialog.askdirectory(title="Escolha a pasta do repositório")
        if pasta:
            self.pasta_selecionada = Path(pasta)
            self.lbl_repo.configure(text=f"Selecionado: .../{self.pasta_selecionada.name}", text_color=PRIMARY)
            self.lbl_status.configure(text=f"Pronto para analisar '{self.pasta_selecionada.name}'.")
            self._passo(0, "Ok", PRIMARY)
            self.btn_iniciar.configure(state="normal")

    def _confirmar_desvincular(self):
        ok = messagebox.askyesno("Trocar conta", "Deseja desvincular esta máquina e trocar de conta?\nSeu token local será apagado.")
        if ok:
            apagar_token()
            self.on_desvincular()

    def _disparar(self):
        self.btn_iniciar.configure(state="disabled")
        url = self.entry_url.get().strip() or None
        threading.Thread(target=self._processar, args=(self.pasta_selecionada, url), daemon=True).start()

    def _processar(self, pasta, url):
        try:
            self._safe_status("Compactando repositório...", 1, "Executando", WARNING)
            with tempfile.TemporaryDirectory() as tmp:
                cfg = None
                if url:
                    cfg = pasta / "scan.config.json"
                    cfg.write_text(json.dumps({"url": url}, indent=2), encoding="utf-8")

                zip_path = Path(tmp) / f"{pasta.name}.zip"
                self._zipar(pasta, zip_path)
                if cfg and cfg.exists():
                    cfg.unlink()

                self._safe_status("Enviando...", 1, "Concluído", SUCCESS)
                self._safe_status("Enviando...", 2, "Enviando",  WARNING)
                self._enviar(zip_path, pasta.name)
        except Exception as e:
            self._safe_fim(erro=str(e))

    def _zipar(self, pasta, destino):
        ignorar = {"node_modules", ".git", "__pycache__", "venv"}
        with zipfile.ZipFile(destino, "w", zipfile.ZIP_DEFLATED) as zf:
            for arq in pasta.rglob("*"):
                if arq.is_file() and not any(p in ignorar for p in arq.relative_to(pasta).parts):
                    zf.write(arq, arq.relative_to(pasta))

    def _enviar(self, zip_path, repo_nome):
        try:
            with open(zip_path, "rb") as f:
                resp = requests.post(
                    CORE_URL,
                    files={"arquivo": (zip_path.name, f, "application/zip")},
                    data={"repositorio": repo_nome, "token": self.token},
                    timeout=300
                )
            if resp.status_code == 200:
                self._safe_fim(sucesso=resp.json())
            else:
                self._safe_fim(erro=f"Servidor respondeu {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            self._safe_fim(erro=str(e))

    def _safe_status(self, texto, idx=None, status=None, cor=None):
        def fn():
            self.lbl_status.configure(text=texto)
            if idx is not None:
                self._passo(idx, status, cor)
        self.after(0, fn)

    def _safe_fim(self, sucesso=None, erro=None):
        def fn():
            self.btn_iniciar.configure(state="normal")
            if erro:
                self.lbl_status.configure(text="Falha no envio", text_color=DANGER)
                self.icon_status.configure(text="❌", text_color=DANGER)
                for s in self.timeline_steps[1:]:
                    if s["sub"].cget("text") in ("Executando", "Enviando", "Aguardando"):
                        s["circle"].configure(fg_color=DANGER)
                        s["sub"].configure(text="Falhou", text_color=DANGER)
                messagebox.showerror("Erro", erro)
            else:
                self._passo(2, "Enviado",   SUCCESS)
                self._passo(3, "Finalizado", SUCCESS)
                self.lbl_status.configure(text="Enviado com sucesso!", text_color=SUCCESS)
                self.icon_status.configure(text="✅", text_color=SUCCESS)
                messagebox.showinfo("Enviado!", f"Repositório enviado!\n\nProtocolo: {sucesso.get('protocolo','N/A')}\n\nO resultado estará no dashboard em instantes.")
        self.after(0, fn)


# ══════════════════════════════════════════════════════════════════════════════
# APP PRINCIPAL — gerencia qual tela está visível
# ══════════════════════════════════════════════════════════════════════════════
class PhantomFixApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PhantomFix — Scanner")
        self.geometry("800x720")
        self.configure(fg_color=BG)
        self.resizable(True, True)

        self._tela_atual = None

        # Se já tem token salvo, tenta ir direto pra análise
        token = carregar_token()
        if token:
            self._ir_analise(token, nome="")
        else:
            self._ir_vinculacao()

    def _limpar(self):
        if self._tela_atual:
            self._tela_atual.destroy()
            self._tela_atual = None

    def _ir_vinculacao(self):
        self._limpar()
        tela = TelaVinculacao(self, on_vinculado=self._ir_analise)
        tela.pack(fill="both", expand=True)
        self._tela_atual = tela

    def _ir_analise(self, token: str, nome: str):
        self._limpar()
        tela = TelaAnalise(self, token=token, nome=nome, on_desvincular=self._ir_vinculacao)
        tela.pack(fill="both", expand=True)
        self._tela_atual = tela


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    app = PhantomFixApp()
    app.mainloop()