#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# PhantomFix — Setup completo para nova VM
# Roda uma vez após clonar o repositório.
# ══════════════════════════════════════════════════════════════════════════════

set -e  # para se qualquer comando falhar

VERDE="\033[0;32m"
AMARELO="\033[1;33m"
VERMELHO="\033[0;31m"
RESET="\033[0m"

ok()   { echo -e "${VERDE}✅ $1${RESET}"; }
info() { echo -e "${AMARELO}➤  $1${RESET}"; }
erro() { echo -e "${VERMELHO}❌ $1${RESET}"; exit 1; }

ROOT="$(cd "$(dirname "$0")" && pwd)"
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║       PhantomFix — Setup da VM           ║"
echo "╚══════════════════════════════════════════╝"
echo ""
info "Diretório raiz: $ROOT"
echo ""

# ── 1. Dependências de sistema ────────────────────────────────────────────────
info "Atualizando pacotes do sistema..."
sudo apt update -q && sudo apt upgrade -y -q
ok "Sistema atualizado"

info "Instalando Python, pip e venv..."
sudo apt install -y -q python3 python3-pip python3-venv
ok "Python $(python3 --version) instalado"

info "Instalando Semgrep..."
pip install semgrep --break-system-packages -q
ok "Semgrep $(semgrep --version) instalado"

info "Instalando OWASP ZAP..."
if ! command -v zaproxy &> /dev/null; then
    sudo snap install zaproxy --classic
    ok "ZAP instalado"
else
    ok "ZAP já instalado"
fi

# ── 2. Ambientes virtuais Python ──────────────────────────────────────────────
echo ""
info "Criando ambientes virtuais Python..."

setup_venv() {
    local pasta="$1"
    local nome="$2"
    info "  venv: $nome"
    cd "$ROOT/$pasta"
    python3 -m venv venv
    source venv/bin/activate
    if [ -f requirements.txt ]; then
        pip install -r requirements.txt -q
    fi
    deactivate
    cd "$ROOT"
    ok "  $nome pronto"
}

setup_venv "core"         "Core"
setup_venv "data-control" "Data Control"
setup_venv "analyser"     "Analyser"

# ── 3. Pastas necessárias ─────────────────────────────────────────────────────
echo ""
info "Criando pastas..."
mkdir -p "$ROOT/resultados"
mkdir -p "$ROOT/core/jobs"
ok "Pastas criadas"

# ── 4. Arquivo de chaves ──────────────────────────────────────────────────────
echo ""
if [ -f ~/.phantom-fix.env ]; then
    ok "~/.phantom-fix.env já existe — mantendo o existente"
else
    info "Criando ~/.phantom-fix.env..."
    cat > ~/.phantom-fix.env << 'EOF'
# PhantomFix — Chaves de API
# NÃO commite este arquivo no Git!
export OPENROUTER_API_KEY=""
export GROQ_API_KEY=""
EOF
    ok "~/.phantom-fix.env criado — preencha as chaves antes de rodar!"
fi

# ── 5. Permissões dos scripts ─────────────────────────────────────────────────
echo ""
info "Ajustando permissões dos scripts..."
chmod +x "$ROOT/start-core.sh"
chmod +x "$ROOT/start-zap.sh"
ok "Permissões ajustadas"

# ── 6. Verifica caminho do ZAP no start-zap.sh ───────────────────────────────
echo ""
info "Verificando caminho do ZAP..."
ZAP_PATH=$(which zaproxy 2>/dev/null || find /opt /snap/bin -name "zap.sh" 2>/dev/null | head -1)

if [ -z "$ZAP_PATH" ]; then
    echo -e "${AMARELO}⚠ ZAP não encontrado no PATH — ajuste o caminho em start-zap.sh manualmente${RESET}"
else
    ok "ZAP encontrado em: $ZAP_PATH"
    # Atualiza o caminho no start-zap.sh se necessário
    if ! grep -q "$ZAP_PATH" "$ROOT/start-zap.sh"; then
        info "Atualizando caminho do ZAP no start-zap.sh..."
        sed -i "s|/opt/ZAP/zap.sh|$ZAP_PATH|g" "$ROOT/start-zap.sh"
        ok "start-zap.sh atualizado com: $ZAP_PATH"
    fi
fi

# ── 7. Resumo final ───────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║            Setup concluído!              ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Próximos passos:"
echo ""
echo "  1. Preencha as chaves em ~/.phantom-fix.env:"
echo "       nano ~/.phantom-fix.env"
echo ""
echo "  2. Suba o ZAP (em uma aba separada):"
echo "       ~/phantom-fix/start-zap.sh"
echo ""
echo "  3. Suba o Core (em outra aba):"
echo "       ~/phantom-fix/start-core.sh"
echo ""
echo "  4. Confirme que está tudo de pé:"
echo "       curl http://localhost:8080/JSON/core/view/version/  # ZAP"
echo "       curl http://localhost:8000/                          # Core"
echo ""
