"""
PhantomFix — Cliente
Executável que roda na máquina do usuário: escolhe a pasta do repositório,
opcionalmente informa a URL da aplicação já em produção, zipa tudo
e envia para o Data Control na nuvem via HTTPS.
"""

import zipfile
import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from pathlib import Path
import tempfile
import threading
import requests

# ── Configuração ──────────────────────────────────────────────────────────────
# O executável fala direto com o Core — é ele quem recebe o .zip,
# aciona o Data Control (scanner.py) internamente e depois o Ghost.
CORE_URL = os.getenv(
    "PHANTOMFIX_CORE_URL",
    "https://seu-core.exemplo.com/scan"
)


class PhantomFixClient:
    def __init__(self, root):
        self.root = root
        self.root.title("PhantomFix — Scanner")
        self.root.geometry("420x220")
        self.root.resizable(False, False)

        self.pasta_selecionada = None

        tk.Label(root, text="PhantomFix", font=("Segoe UI", 16, "bold")).pack(pady=(20, 0))
        tk.Label(root, text="Análise de vulnerabilidades", fg="gray").pack(pady=(0, 20))

        self.btn_escolher = tk.Button(
            root,
            text="📁  Escolher pasta do repositório",
            command=self.escolher_pasta,
            padx=10, pady=8
        )
        self.btn_escolher.pack(pady=5)

        self.label_pasta = tk.Label(root, text="Nenhuma pasta selecionada", fg="gray")
        self.label_pasta.pack(pady=(0, 10))

        self.progress = ttk.Progressbar(root, mode="indeterminate", length=300)

        self.status_label = tk.Label(root, text="", fg="gray")
        self.status_label.pack()

    # ── Passo 1: escolher pasta ───────────────────────────────────────────────
    def escolher_pasta(self):
        pasta = filedialog.askdirectory(title="Escolha a pasta do repositório")
        if not pasta:
            return

        self.pasta_selecionada = Path(pasta)
        self.label_pasta.config(text=self.pasta_selecionada.name, fg="black")

        # Passo 2: pergunta se a aplicação já está rodando em algum lugar
        url = simpledialog.askstring(
            "URL da aplicação (opcional)",
            "Se a aplicação já está rodando em algum ambiente,\n"
            "cole a URL abaixo (usada para o teste dinâmico).\n\n"
            "Deixe em branco se não tiver.",
        )

        self._iniciar_envio(self.pasta_selecionada, url.strip() if url else None)

    # ── Passo 3: zipar e enviar em thread separada (não trava a UI) ─────────
    def _iniciar_envio(self, pasta: Path, url: str | None):
        self.btn_escolher.config(state="disabled")
        self.progress.pack(pady=10)
        self.progress.start(10)
        self.status_label.config(text="Compactando repositório...")

        thread = threading.Thread(target=self._processar, args=(pasta, url), daemon=True)
        thread.start()

    def _processar(self, pasta: Path, url: str | None):
        try:
            with tempfile.TemporaryDirectory() as tmp:
                # Gera scan.config.json temporário se houver URL
                config_temp = None
                if url:
                    config_temp = pasta / "scan.config.json"
                    config_temp.write_text(
                        json.dumps({"url": url}, indent=2),
                        encoding="utf-8"
                    )

                zip_path = Path(tmp) / f"{pasta.name}.zip"
                self._zipar_pasta(pasta, zip_path)

                # Remove o config temporário da pasta original (não sujar o repo do usuário)
                if config_temp and config_temp.exists():
                    config_temp.unlink()

                self._atualizar_status("Enviando para o Data Control...")
                self._enviar(zip_path, pasta.name)

        except Exception as e:
            self._finalizar(erro=str(e))

    def _zipar_pasta(self, pasta: Path, destino: Path):
        with zipfile.ZipFile(destino, "w", zipfile.ZIP_DEFLATED) as zf:
            for arquivo in pasta.rglob("*"):
                if arquivo.is_file():
                    # Ignora pastas pesadas e irrelevantes para o scan
                    partes = arquivo.relative_to(pasta).parts
                    if any(p in ("node_modules", ".git", "__pycache__", "venv") for p in partes):
                        continue
                    zf.write(arquivo, arquivo.relative_to(pasta))

    def _enviar(self, zip_path: Path, repo_nome: str):
        try:
            with open(zip_path, "rb") as f:
                resposta = requests.post(
                    CORE_URL,
                    files={"arquivo": (zip_path.name, f, "application/zip")},
                    data={"repositorio": repo_nome},
                    timeout=30  # o scan roda em background no Core, não esperamos aqui
                )

            if resposta.status_code == 200:
                dados = resposta.json()
                self._finalizar(sucesso=dados)
            else:
                self._finalizar(erro=f"Servidor respondeu {resposta.status_code}: {resposta.text[:200]}")

        except requests.exceptions.ConnectionError:
            self._finalizar(erro="Não foi possível conectar ao Core. Verifique sua internet ou a URL configurada.")
        except Exception as e:
            self._finalizar(erro=str(e))

    # ── Helpers de UI (thread-safe via root.after) ───────────────────────────
    def _atualizar_status(self, texto: str):
        self.root.after(0, lambda: self.status_label.config(text=texto))

    def _finalizar(self, sucesso: dict | None = None, erro: str | None = None):
        def atualizar():
            self.progress.stop()
            self.progress.pack_forget()
            self.btn_escolher.config(state="normal")

            if erro:
                self.status_label.config(text="Falha no envio", fg="red")
                messagebox.showerror("Erro", erro)
            else:
                self.status_label.config(text="Enviado com sucesso!", fg="green")
                messagebox.showinfo(
                    "Enviado!",
                    f"Repositório enviado para análise.\n\n"
                    f"Protocolo: {sucesso.get('protocolo', 'N/A')}\n"
                    f"O resultado estará disponível no dashboard em instantes."
                )

        self.root.after(0, atualizar)


if __name__ == "__main__":
    root = tk.Tk()
    app = PhantomFixClient(root)
    root.mainloop()
