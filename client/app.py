"""
PhantomFix — Cliente
Executável que roda na máquina do usuário: escolhe a pasta do repositório,
opcionalmente informa a URL da aplicação já em produção, zipa tudo
e envia para o Data Control na nuvem via HTTPS.
"""

import zipfile
import json
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
import tempfile
import threading
import requests
import time
import customtkinter as ctk
from PIL import Image

# ── Configuração do Core (Mantida idêntica à original) ──────────────────────────
CORE_URL = os.getenv(
    "PHANTOMFIX_CORE_URL",
    "https://phantom-fix.duckdns.org/api/scan"
)

# Configurações de Cores do Tema Premium
COLOR_BG = "#0B0F19"         
COLOR_CARD = "#111827"       
COLOR_BORDER = "#1F2937"     
COLOR_PRIMARY = "#6366F1"    
COLOR_SUCCESS = "#10B981"    
COLOR_TEXT_MAIN = "#F9FAFB"  
COLOR_TEXT_DIM = "#9CA3AF"   

# Descobrir o caminho do logo para rodar como script ou executável compilado
if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys._MEIPASS)
else:
    BASE_DIR = Path(__file__).parent

PATH_LOGO = BASE_DIR / "ghost_logo_large.png"


class PhantomFixApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Configuração da Janela Principal Responsiva
        self.title("PhantomFix — Scanner")
        self.geometry("800x720")     
        self.configure(fg_color=COLOR_BG)
        self.resizable(True, True) 

        self.pasta_selecionada = None
        self.timeline_steps = []

        self._grid_layout_config()
        self._create_widgets()

    def _grid_layout_config(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0, pad=10) 
        self.grid_rowconfigure(1, weight=0, pad=10)
        self.grid_rowconfigure(2, weight=0, pad=10)
        self.grid_rowconfigure(3, weight=0, pad=10)
        self.grid_rowconfigure(4, weight=0, pad=10) 
        self.grid_rowconfigure(5, weight=1)         

    def _create_card_frame(self, row, height=100):
        card = ctk.CTkFrame(
            self, fg_color=COLOR_CARD, border_color=COLOR_BORDER, border_width=1, corner_radius=12, height=height
        )
        card.grid(row=row, column=0, padx=30, pady=5, sticky="ew")
        card.grid_propagate(False) if height != 170 else card.pack_propagate(False)
        return card

    def _create_widgets(self):
        # ── 0. Cabeçalho (Logo Proporcional e Títulos) ──
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, pady=(20, 5), sticky="n")

        try:
            if PATH_LOGO.exists():
                img = Image.open(PATH_LOGO)
                orig_width, orig_height = img.size
                target_width = 160
                target_height = int((target_width / orig_width) * orig_height)
                
                self.logo_img = ctk.CTkImage(light_image=img, dark_image=img, size=(target_width, target_height))
                self.label_logo = ctk.CTkLabel(header_frame, image=self.logo_img, text="")
                self.label_logo.pack()
            else:
                ctk.CTkLabel(header_frame, text="👻", font=("Segoe UI", 64)).pack()
        except Exception as e:
            print(f"Erro ao carregar logo: {e}")
            ctk.CTkLabel(header_frame, text="[LOGO]", font=("Segoe UI", 24)).pack()

        ctk.CTkLabel(header_frame, text="PhantomFix", font=("Segoe UI", 32, "bold"), text_color=COLOR_TEXT_MAIN).pack(pady=(5, 0))
        ctk.CTkLabel(header_frame, text="ANÁLISE DE VULNERABILIDADES", font=("Segoe UI", 11, "bold"), text_color=COLOR_TEXT_DIM).pack(pady=(0, 10))

        # ── 1. Cartão de Seleção do Repositório ──
        self.card_repo = self._create_card_frame(row=1)
        self.card_repo.grid_columnconfigure(0, weight=0)
        self.card_repo.grid_columnconfigure(1, weight=1)
        self.card_repo.grid_columnconfigure(2, weight=0)

        ctk.CTkLabel(self.card_repo, text="📁", font=("Segoe UI", 24), text_color=COLOR_PRIMARY).grid(row=0, column=0, rowspan=2, padx=(20, 15), sticky="w")
        ctk.CTkLabel(self.card_repo, text="Repositório", font=("Segoe UI", 14, "bold"), text_color=COLOR_TEXT_MAIN).grid(row=0, column=1, sticky="w", pady=(12,0))
        self.label_desc_repo = ctk.CTkLabel(self.card_repo, text="Selecione a pasta do seu projeto para iniciar a análise.", font=("Segoe UI", 12), text_color=COLOR_TEXT_DIM)
        self.label_desc_repo.grid(row=1, column=1, sticky="w", pady=(0, 12))

        self.btn_escolher = ctk.CTkButton(
            self.card_repo, text="📁  Escolher pasta", font=("Segoe UI", 12, "bold"),
            fg_color=COLOR_PRIMARY, hover_color="#4F46E5", corner_radius=8, height=38,
            command=self.escolher_pasta
        )
        self.btn_escolher.grid(row=0, column=2, rowspan=2, padx=20, sticky="e")

        # ── 2. Cartão de URL Opcional ──
        self.card_url = self._create_card_frame(row=2)
        self.card_url.grid_columnconfigure(0, weight=0)
        self.card_url.grid_columnconfigure(1, weight=1)
        self.card_url.grid_columnconfigure(2, weight=0)

        ctk.CTkLabel(self.card_url, text="🔗", font=("Segoe UI", 20), text_color=COLOR_PRIMARY).grid(row=0, column=0, rowspan=2, padx=(20, 15), sticky="w")
        ctk.CTkLabel(self.card_url, text="URL da aplicação (opcional)", font=("Segoe UI", 14, "bold"), text_color=COLOR_TEXT_MAIN).grid(row=0, column=1, sticky="w", pady=(12,0))
        ctk.CTkLabel(self.card_url, text="Informe a URL da aplicação já em produção para o teste dinâmico.", font=("Segoe UI", 12), text_color=COLOR_TEXT_DIM).grid(row=1, column=1, sticky="w", pady=(0, 12))

        self.entry_url = ctk.CTkEntry(
            self.card_url, placeholder_text="https://exemplo.com", width=280, height=36, 
            border_color=COLOR_BORDER, fg_color=COLOR_BG, text_color=COLOR_TEXT_MAIN, corner_radius=6
        )
        self.entry_url.grid(row=0, column=2, rowspan=2, padx=20, sticky="e")

        # ── 3. Cartão de Progresso da Análise (Timeline) ──
        self.card_progress = self._create_card_frame(row=3, height=170)
        ctk.CTkLabel(self.card_progress, text="Progresso da análise", font=("Segoe UI", 14, "bold"), text_color=COLOR_TEXT_MAIN).pack(anchor="w", padx=20, pady=(12, 5))

        self.timeline_frame = ctk.CTkFrame(self.card_progress, fg_color="transparent")
        self.timeline_frame.pack(fill="x", padx=40, pady=5)

        steps = [
            ("1", "Repositório", "📁"),
            ("2", "Compactando", "📄"),
            ("3", "Enviando", "☁️"),
            ("4", "Analisando", "🛡️")
        ]
        self._build_timeline(self.timeline_frame, steps)

        self.status_info_frame = ctk.CTkFrame(self.card_progress, fg_color=COLOR_BG, corner_radius=6, border_width=1, border_color=COLOR_BORDER)
        self.status_info_frame.pack(fill="x", padx=20, pady=(10, 12))
        
        self.icon_status = ctk.CTkLabel(self.status_info_frame, text="ℹ️", font=("Segoe UI", 14), text_color=COLOR_PRIMARY)
        self.icon_status.pack(side="left", padx=(12, 5), pady=8)
        
        self.status_label = ctk.CTkLabel(self.status_info_frame, text="Selecione um repositório para iniciar o processo de análise.", font=("Segoe UI", 12), text_color=COLOR_TEXT_DIM)
        self.status_label.pack(side="left", pady=8)

        # ── 4. Botão de Disparo / Envio Real ──
        self.action_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.action_frame.grid(row=4, column=0, padx=30, pady=10, sticky="e")
        
        self.btn_iniciar = ctk.CTkButton(
            self.action_frame, text="🚀 Iniciar Análise", font=("Segoe UI", 14, "bold"),
            fg_color=COLOR_PRIMARY, hover_color="#4F46E5", corner_radius=8, width=180, height=42,
            state="disabled", command=self.disparar_analise
        )
        self.btn_iniciar.pack()

        # ── 5. Rodapé ──
        footer_frame = ctk.CTkFrame(self, fg_color="transparent")
        footer_frame.grid(row=5, column=0, pady=15, sticky="s")
        ctk.CTkLabel(footer_frame, text="👻 PhantomFix Client v1.0.0", font=("Segoe UI", 11), text_color="#3F435C").pack()

    def _build_timeline(self, parent, steps):
        parent.grid_columnconfigure(tuple(range(len(steps) * 2 - 1)), weight=1)
        for i, (num, label_text, icon) in enumerate(steps):
            col_idx = i * 2
            step_container = ctk.CTkFrame(parent, fg_color="transparent")
            step_container.grid(row=0, column=col_idx, sticky="nsew")
            
            circle = ctk.CTkLabel(
                step_container, text=num, width=28, height=28, corner_radius=14,
                fg_color="#1F2937", text_color=COLOR_TEXT_DIM, font=("Segoe UI", 12, "bold")
            )
            circle.pack()
            
            lbl = ctk.CTkLabel(step_container, text=label_text, font=("Segoe UI", 11, "bold"), text_color="#4B5563")
            lbl.pack(pady=(4, 0))
            
            sub_lbl = ctk.CTkLabel(step_container, text="Aguardando", font=("Segoe UI", 10), text_color="#374151")
            sub_lbl.pack()
            
            self.timeline_steps.append({"circle": circle, "label": lbl, "sub": sub_lbl, "icon": icon, "line": None})
            if i < len(steps) - 1:
                line = ctk.CTkFrame(parent, fg_color="#1F2937", height=2)
                line.grid(row=0, column=col_idx + 1, sticky="ew", padx=5, pady=(12, 0))
                self.timeline_steps[i]["line"] = line

    def escolher_pasta(self):
        pasta = filedialog.askdirectory(title="Escolha a pasta do repositório")
        if pasta:
            self.pasta_selecionada = Path(pasta)
            nome_pasta = self.pasta_selecionada.name
            
            self.label_desc_repo.configure(text=f"Selecionado: .../{nome_pasta}", text_color=COLOR_PRIMARY)
            self.status_label.configure(text=f"Pronto para analisar o repositório '{nome_pasta}'. Preencha a URL se necessário e clique em 'Iniciar Análise'.")
            
            self._atualizar_passo_ui(0, status="Ok", cor_circulo=COLOR_PRIMARY, cor_texto=COLOR_TEXT_MAIN)
            self.btn_iniciar.configure(state="normal")

    def _atualizar_passo_ui(self, index, status, cor_circulo, cor_texto):
        self.timeline_steps[index]["circle"].configure(fg_color=cor_circulo, text_color=COLOR_TEXT_MAIN)
        self.timeline_steps[index]["label"].configure(text_color=COLOR_TEXT_MAIN)
        self.timeline_steps[index]["sub"].configure(text=status, text_color=cor_texto)
        if index > 0 and self.timeline_steps[index-1]["line"]:
            self.timeline_steps[index-1]["line"].configure(fg_color=cor_circulo)

    def disparar_analise(self):
        # Bloqueia a interface para evitar cliques duplicados durante o envio real
        self.btn_iniciar.configure(state="disabled")
        self.btn_escolher.configure(state="disabled")
        self.entry_url.configure(state="disabled")
        
        # Dispara o processamento real na Thread em background nativa (idêntico ao seu anterior)
        url_input = self.entry_url.get().strip()
        url = url_input if url_input else None
        
        threading.Thread(target=self._processar_real, args=(self.pasta_selecionada, url), daemon=True).start()

    # ── LOGICA DE NEGÓCIO ORIGINAL TOTALMENTE RESTAURADA ─────────────────────────
    def _processar_real(self, pasta: Path, url: str | None):
        try:
            # Passo 2: Compactando
            self._atualizar_status_safe("Compactando repositório...", passo_idx=1, status_passo="Executando", cor="#F59E0B")
            
            with tempfile.TemporaryDirectory() as tmp:
                config_temp = None
                if url:
                    config_temp = pasta / "scan.config.json"
                    config_temp.write_text(
                        json.dumps({"url": url}, indent=2),
                        encoding="utf-8"
                    )

                zip_path = Path(tmp) / f"{pasta.name}.zip"
                self._zipar_pasta_real(pasta, zip_path)

                if config_temp and config_temp.exists():
                    config_temp.unlink()

                # Passo 3: Enviando para o Data Control
                self._atualizar_status_safe("Enviando para o Data Control...", passo_idx=1, status_passo="Concluído", cor=COLOR_SUCCESS)
                self._atualizar_status_safe("Enviando para o Data Control...", passo_idx=2, status_passo="Enviando", cor="#F59E0B")
                
                self._enviar_real(zip_path, pasta.name)

        except Exception as e:
            self._finalizar_safe(erro=str(e))

    def _zipar_pasta_real(self, pasta: Path, destino: Path):
        with zipfile.ZipFile(destino, "w", zipfile.ZIP_DEFLATED) as zf:
            for arquivo in pasta.rglob("*"):
                if arquivo.is_file():
                    partes = arquivo.relative_to(pasta).parts
                    if any(p in ("node_modules", ".git", "__pycache__", "venv") for p in partes):
                        continue
                    zf.write(arquivo, arquivo.relative_to(pasta))

    def _enviar_real(self, zip_path: Path, repo_nome: str):
        try:
            with open(zip_path, "rb") as f:
                resposta = requests.post(
                    CORE_URL,
                    files={"arquivo": (zip_path.name, f, "application/zip")},
                    data={"repositorio": repo_nome},
                    timeout=30  
                )

            if resposta.status_code == 200:
                dados = resposta.json()
                self._finalizar_safe(sucesso=dados)
            else:
                self._finalizar_safe(erro=f"Servidor respondeu {resposta.status_code}: {resposta.text[:200]}")

        except requests.exceptions.ConnectionError:
            self._finalizar_safe(erro="Não foi possível conectar ao Core. Verifique sua internet ou a URL configurada.")
        except Exception as e:
            self._finalizar_safe(erro=str(e))

    # ── Helpers de UI Thread-Safe via after (Atualiza o CustomTkinter sem travar) ──
    def _atualizar_status_safe(self, texto: str, passo_idx=None, status_passo=None, cor=None):
        def atualizar():
            self.status_label.configure(text=texto)
            if passo_idx is not None:
                self._atualizar_passo_ui(passo_idx, status=status_passo, cor_circulo=cor, cor_texto=cor)
        self.after(0, atualizar)

    def _finalizar_safe(self, sucesso: dict | None = None, erro: str | None = None):
        def atualizar():
            self.btn_escolher.configure(state="normal")
            self.entry_url.configure(state="normal")
            self.btn_iniciar.configure(state="normal")

            if erro:
                self.status_label.configure(text="Falha no envio", text_color="red")
                self.icon_status.configure(text="❌", text_color="red")
                # Atualiza as bolinhas para refletir a falha
                for step in self.timeline_steps[1:]:
                    if step["sub"].cget("text") in ("Executando", "Enviando", "Aguardando"):
                        step["circle"].configure(fg_color="#EF4444")
                        step["sub"].configure(text="Falhou", text_color="#EF4444")
                messagebox.showerror("Erro", erro)
            else:
                # Conclui as etapas visuais restantes
                self._atualizar_passo_ui(2, status="Enviado", cor_circulo=COLOR_SUCCESS, cor_texto=COLOR_SUCCESS)
                self._atualizar_passo_ui(3, status="Finalizado", cor_circulo=COLOR_SUCCESS, cor_texto=COLOR_SUCCESS)
                
                self.status_label.configure(text="Enviado com sucesso!", text_color=COLOR_SUCCESS)
                self.icon_status.configure(text="✅", text_color=COLOR_SUCCESS)
                
                messagebox.showinfo(
                    "Enviado!",
                    f"Repositório enviado para análise.\n\n"
                    f"Protocolo: {sucesso.get('protocolo', 'N/A')}\n"
                    f"O resultado estará disponível no dashboard em instantes."
                )
        self.after(0, atualizar)


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    app = PhantomFixApp()
    app.mainloop()
