"""
PhantomFix — Data-Control
enviador.py

Valida, empacota e envia o repositório ao Core.
Implementa retry com backoff exponencial.
"""

import time
from pathlib import Path

import requests

from empacotador import validar_repositorio, zipar_repositorio
from bandeja import atualizar_status, notificar

TENTATIVAS_MAX = 4
ESPERA_INICIAL = 5   # segundos — dobra a cada tentativa: 5 → 10 → 20 → 40


def enviar_repositorio(pasta: str, core_url: str, token: str):
    """
    Fluxo completo: valida → zipa → envia com retry.
    Chamado pelo main.py em thread separada.
    """
    pasta_path = Path(pasta)
    core_url   = core_url.rstrip("/")   # evita "/api//scan"

    # ── 1. Valida ─────────────────────────────────────────────────────────────
    atualizar_status("Validando repositório...")
    ok, motivo = validar_repositorio(pasta_path)
    if not ok:
        atualizar_status(f"⚠ {motivo}")
        notificar("PhantomFix — Erro", motivo)
        return

    # ── 2. Empacota ───────────────────────────────────────────────────────────
    try:
        zip_path = zipar_repositorio(pasta_path, callback_status=atualizar_status)
    except Exception as e:
        atualizar_status(f"⚠ Erro ao empacotar: {e}")
        notificar("PhantomFix — Erro", f"Falha ao empacotar repositório: {e}")
        return

    # ── 3. Envia com retry ────────────────────────────────────────────────────
    espera = ESPERA_INICIAL
    sucesso = False

    for tentativa in range(1, TENTATIVAS_MAX + 1):
        try:
            atualizar_status(f"Enviando... (tentativa {tentativa}/{TENTATIVAS_MAX})")

            with open(zip_path, "rb") as f:
                # O Core espera token e repositorio como campos de FORM
                # (mesmo formato do client/app.py), não como header.
                resp = requests.post(
                    f"{core_url}/scan",
                    files={"arquivo": ("repositorio.zip", f, "application/zip")},
                    data={
                        "repositorio": pasta_path.name,
                        "token":       token,
                    },
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=300,
                )

            if resp.status_code == 200:
                sucesso = True
                break

            print(f"[enviador] HTTP {resp.status_code}: {resp.text[:500]}")
            atualizar_status(f"⚠ Tentativa {tentativa} falhou: HTTP {resp.status_code}")

            # 4xx = erro do pedido (token inválido, payload errado, zip grande demais).
            # Tentar de novo não resolve — aborta o retry.
            if 400 <= resp.status_code < 500:
                break

        except requests.exceptions.ConnectionError:
            atualizar_status(f"⚠ Tentativa {tentativa} falhou: sem conexão")
        except requests.exceptions.Timeout:
            atualizar_status(f"⚠ Tentativa {tentativa} falhou: timeout")
        except Exception as e:
            atualizar_status(f"⚠ Tentativa {tentativa} falhou: {e}")

        if tentativa < TENTATIVAS_MAX:
            atualizar_status(f"Aguardando {espera}s antes de tentar novamente...")
            time.sleep(espera)
            espera *= 2

    # ── 4. Limpa o zip temporário ─────────────────────────────────────────────
    try:
        zip_path.unlink(missing_ok=True)
        zip_path.parent.rmdir()
    except Exception:
        pass

    # ── 5. Notifica resultado ─────────────────────────────────────────────────
    if sucesso:
        atualizar_status("✓ Enviado com sucesso")
        notificar("PhantomFix", "Repositório enviado! O scan está em andamento.")
    else:
        atualizar_status("✗ Falha no envio")
        notificar("PhantomFix — Erro", "Não foi possível enviar o repositório após 4 tentativas.")
