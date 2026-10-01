"""
PhantomFix — Data-Control
Versão: 1.0.0

Entry point do agente local.
Inicia a bandeja do sistema e o loop de polling em background.
"""

import sys
import threading
import time

from config import carregar_config, salvar_config
from keychain import carregar_token
from enviador import enviar_repositorio
from bandeja import iniciar_bandeja, atualizar_status, notificar

import requests

# ── Configuração ──────────────────────────────────────────────────────────────
CORE_URL_PADRAO    = "https://phantom-fix.southafricanorth.cloudapp.azure.com/api/"   # trocar pelo domínio final
INTERVALO_POLLING  = 60   # segundos


# ══════════════════════════════════════════════════════════════════════════════
# AÇÕES
# ══════════════════════════════════════════════════════════════════════════════

def acao_analisar_agora():
    """Chamada quando o usuário clica em 'Analisar agora' na bandeja."""
    token    = carregar_token()
    config   = carregar_config()
    pasta    = config.get("pasta_repo", "")
    core_url = config.get("core_url", CORE_URL_PADRAO).rstrip("/")

    if not token:
        atualizar_status("⚠ Token não configurado")
        notificar("PhantomFix", "Configure o token de acesso antes de analisar.")
        return

    if not pasta:
        atualizar_status("⚠ Pasta do repositório não configurada")
        notificar("PhantomFix", "Configure a pasta do repositório antes de analisar.")
        return

    # Roda em thread para não travar a bandeja
    threading.Thread(
        target=enviar_repositorio,
        args=(pasta, core_url, token),
        daemon=True,
    ).start()


# ══════════════════════════════════════════════════════════════════════════════
# POLLING
# ══════════════════════════════════════════════════════════════════════════════

def loop_polling():
    """
    Verifica a cada INTERVALO_POLLING segundos se o Core tem
    um scan agendado para este usuário.
    Quando encontra, dispara o envio automaticamente.
    """
    while True:
        try:
            token    = carregar_token()
            config   = carregar_config()
            core_url = config.get("core_url", CORE_URL_PADRAO).rstrip("/")
            pasta    = config.get("pasta_repo", "")

            if token and pasta:
                resp = requests.get(
                    f"{core_url}/scan/pending",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10,
                )
                if resp.status_code == 200 and resp.json().get("pendente"):
                    atualizar_status("📡 Scan agendado detectado — enviando...")
                    enviar_repositorio(pasta, core_url, token)

        except requests.exceptions.ConnectionError:
            pass   # servidor indisponível — silencioso
        except Exception as e:
            print(f"[polling] Erro: {e}")

        time.sleep(INTERVALO_POLLING)


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    # Garante que a config existe
    config = carregar_config()
    if "core_url" not in config:
        config["core_url"] = CORE_URL_PADRAO
        salvar_config(config)

    # Inicia polling em background
    threading.Thread(target=loop_polling, daemon=True).start()

    # Inicia a bandeja (bloqueia até o usuário clicar em Sair)
    iniciar_bandeja(ao_analisar=acao_analisar_agora)


if __name__ == "__main__":
    main()
