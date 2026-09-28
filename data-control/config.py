"""
PhantomFix — Data-Control
config.py

Salva e carrega configurações locais em:
  %APPDATA%/PhantomFix/config.json

Campos:
  core_url    — URL do servidor Core
  pasta_repo  — caminho local do repositório a analisar
"""

import json
import os
from pathlib import Path


def _caminho_config() -> Path:
    appdata = os.getenv("APPDATA", Path.home() / "AppData" / "Roaming")
    pasta   = Path(appdata) / "PhantomFix"
    pasta.mkdir(parents=True, exist_ok=True)
    return pasta / "config.json"


def carregar_config() -> dict:
    caminho = _caminho_config()
    if caminho.exists():
        try:
            return json.loads(caminho.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def salvar_config(config: dict):
    _caminho_config().write_text(
        json.dumps(config, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def get(chave: str, padrao=None):
    return carregar_config().get(chave, padrao)


def set(chave: str, valor):
    config = carregar_config()
    config[chave] = valor
    salvar_config(config)
