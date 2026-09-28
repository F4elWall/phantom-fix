"""
PhantomFix — Data-Control
keychain.py

Armazena e recupera o token de autenticação usando o
Windows Credential Manager via biblioteca keyring.

O token nunca toca o disco como texto plano.
"""

import keyring

SERVICO = "PhantomFix"
USUARIO = "token_acesso"


def salvar_token(token: str):
    keyring.set_password(SERVICO, USUARIO, token)


def carregar_token() -> str | None:
    return keyring.get_password(SERVICO, USUARIO)


def remover_token():
    try:
        keyring.delete_password(SERVICO, USUARIO)
    except keyring.errors.PasswordDeleteError:
        pass


def token_configurado() -> bool:
    return bool(carregar_token())
