# PhantomFix — Copyright (C) 2025–2026 Rafael Pedro, Bernardo Coroa,
# Giovanna Esmelardi, Gustavo Enrique
# SPDX-License-Identifier: GPL-3.0-or-later
# Licenciado sob a GNU GPL v3. Veja LICENSE.md na raiz do repositório.

"""
PhantomFix — Core
validacao.py

Validação das URLs que o usuário informa e que o servidor acessa em nome dele:

  • URL da aplicação (Nexus → DAST): normaliza e bloqueia destinos internos,
    para que o ZAP/Nuclei do servidor não sejam usados contra a rede interna
    (SSRF) ou contra o próprio Core.
  • URL do repositório GitHub: aceita somente https://github.com/<dono>/<repo>.
"""

import ipaddress
import os
import re
import socket
from urllib.parse import urlparse

# ── GitHub ────────────────────────────────────────────────────────────────────

_REPO_RE = re.compile(
    r"^https://(?:www\.)?github\.com/"
    r"(?P<dono>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


def validar_repo_github(url: str) -> str:
    """
    Retorna a URL canônica https://github.com/<dono>/<repo> ou levanta ValueError.

    Compara o host por igualdade (e não por substring), de modo que
    'github.com.evil.com' ou 'https://github.com@evil.com/x' sejam recusados —
    o token do GitHub é injetado na URL de clone e não pode vazar para outro host.
    """
    m = _REPO_RE.match((url or "").strip())
    if not m:
        raise ValueError(
            "Use o formato https://github.com/usuario/repositorio"
        )
    dono, repo = m.group("dono"), m.group("repo")
    if dono in (".", "..") or repo in (".", ".."):
        raise ValueError("URL do repositório inválida")
    return f"https://github.com/{dono}/{repo}"


# ── DAST ──────────────────────────────────────────────────────────────────────

_SUFIXOS_INTERNOS = (".localhost", ".local", ".internal", ".lan", ".intranet")


def _permitir_rede_privada() -> bool:
    return os.getenv("DAST_PERMITIR_REDE_PRIVADA", "").strip().lower() in ("1", "true", "sim", "yes")


def _ip_publico(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global


def _checar_host_publico(host: str, resolver_dns: bool) -> None:
    host = host.lower().rstrip(".")
    if host == "localhost" or host.endswith(_SUFIXOS_INTERNOS):
        raise ValueError("o endereço aponta para a rede interna do servidor")

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        if not _ip_publico(ip):
            raise ValueError("o endereço aponta para a rede interna do servidor")
        return

    if not resolver_dns:
        return

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValueError(f"não foi possível resolver o domínio {host!r}")
    for info in infos:
        if not _ip_publico(ipaddress.ip_address(info[4][0])):
            raise ValueError("o domínio resolve para a rede interna do servidor")


def normalizar_url_dast(url: str | None, resolver_dns: bool = False) -> str | None:
    """
    Normaliza a URL-alvo do DAST.

    - vazio/None → None (DAST desativado)
    - sem esquema → assume https://
    - só http/https, sem credenciais embutidas, porta válida
    - destinos internos (localhost, 10.x, 192.168.x, 169.254.x, *.local…) são
      recusados, a menos que DAST_PERMITIR_REDE_PRIVADA=1 (útil em laboratório)
    - resolver_dns=True também resolve o domínio e confere os IPs (usar no momento
      do scan; no cadastro basta a checagem sintática)

    Levanta ValueError com mensagem pronta para o usuário.
    """
    bruta = (url or "").strip()
    if not bruta:
        return None
    if "://" not in bruta:
        bruta = "https://" + bruta

    try:
        p = urlparse(bruta)
        _ = p.port  # valida a porta
    except ValueError:
        raise ValueError("URL inválida")

    if p.scheme not in ("http", "https"):
        raise ValueError("use uma URL http:// ou https://")
    if not p.hostname:
        raise ValueError("URL sem domínio")
    if p.username or p.password:
        raise ValueError("não inclua usuário/senha na URL")

    if not _permitir_rede_privada():
        _checar_host_publico(p.hostname, resolver_dns)

    return p._replace(fragment="").geturl()
