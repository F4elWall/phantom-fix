#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# PhantomFix — Setup completo para nova VM
# Versão: 2.0
#
# Roda uma vez após clonar o repositório em uma VM Ubuntu/Debian limpa.
# Instala todas as dependências de sistema, scanners e cria os venvs.
#
# Uso:
#   chmod +x setup.sh && ./setup.sh
# ══════════════════════════════════════════════════════════════════════════════

set -e

VERDE="\033[0;32m"
AMARELO="\033[1;33m"
VERMELHO="\033[0;31m"
CIANO="\033[0;36m"
RESET="\033[0m"

ok()   { echo -e "${VERDE}✅ $1${RESET}"; }
info() { echo -e "${CIANO}➤  $1${RESET}"; }
aviso(){ echo -e "${AMARELO}⚠️  $1${RESET}"; }
erro() { echo -e "${VERMELHO}❌ $1${RESET}"; exit 1; }

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║       PhantomFix — Setup da VM           ║"
echo "║              Versão 2.0                  ║"
echo "╚══════════════════════════════════════════╝"
echo ""
info "Diretório raiz: $ROOT"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# 1. DEPENDÊNCIAS DE SISTEMA
# ══════════════════════════════════════════════════════════════════════════════
info "Atualizando pacotes do sistema..."
sudo apt update -q && sudo apt upgrade -y -q
sudo apt install -y -q \
    python3 python3-pip python3-venv \
    git curl wget unzip nodejs npm
ok "Dependências de sistema instaladas"

# ══════════════════════════════════════════════════════════════════════════════
# 2. SEMGREP
# ══════════════════════════════════════════════════════════════════════════════
info "Instalando Semgrep..."
pip install semgrep --break-system-packages -q
ok "Semgrep $(semgrep --version 2>&1 | head -1) instalado"

# ══════════════════════════════════════════════════════════════════════════════
# 3. OWASP ZAP
# ══════════════════════════════════════════════════════════════════════════════
info "Instalando OWASP ZAP..."
if ! command -v zaproxy &> /dev/null; then
    sudo snap install zaproxy --classic
    ok "ZAP instalado"
else
    ok "ZAP já instalado"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 4. GITLEAKS
# ══════════════════════════════════════════════════════════════════════════════
info "Instalando Gitleaks..."
if ! command -v gitleaks &> /dev/null; then
    GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4)
    wget -qO /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz"
    sudo tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks
    rm /tmp/gitleaks.tar.gz
    ok "Gitleaks $(gitleaks version 2>&1) instalado"
else
    ok "Gitleaks já instalado"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 5. TRIVY
# ══════════════════════════════════════════════════════════════════════════════
info "Instalando Trivy..."
if ! command -v trivy &> /dev/null; then
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sudo sh -s -- -b /usr/local/bin
    ok "Trivy $(trivy --version 2>&1 | head -1) instalado"
else
    ok "Trivy já instalado"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 6. SYFT
# ══════════════════════════════════════════════════════════════════════════════
info "Instalando Syft..."
if ! command -v syft &> /dev/null; then
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
        | sudo sh -s -- -b /usr/local/bin
    ok "Syft $(syft version 2>&1 | head -1) instalado"
else
    ok "Syft já instalado"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 7. GRYPE
# ══════════════════════════════════════════════════════════════════════════════
info "Instalando Grype..."
if ! command -v grype &> /dev/null; then
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
        | sudo sh -s -- -b /usr/local/bin
    ok "Grype $(grype version 2>&1 | head -1) instalado"
else
    ok "Grype já instalado"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 8. TRUFFLEHOG
# ══════════════════════════════════════════════════════════════════════════════
info "Instalando TruffleHog..."
if ! command -v trufflehog &> /dev/null; then
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sudo sh -s -- -b /usr/local/bin
    ok "TruffleHog $(trufflehog --version 2>&1 | head -1) instalado"
else
    ok "TruffleHog já instalado"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 9. HADOLINT
# ══════════════════════════════════════════════════════════════════════════════
info "Instalando Hadolint..."
if ! command -v hadolint &> /dev/null; then
    wget -qO /usr/local/bin/hadolint \
        https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64
    sudo chmod +x /usr/local/bin/hadolint
    ok "Hadolint $(hadolint --version 2>&1) instalado"
else
    ok "Hadolint já instalado"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 10. NUCLEI + TEMPLATES
# ══════════════════════════════════════════════════════════════════════════════
info "Instalando Nuclei..."
if ! command -v nuclei &> /dev/null; then
    NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4)
    wget -qO /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip"
    cd /tmp && unzip -q nuclei.zip nuclei
    sudo mv /tmp/nuclei /usr/local/bin/
    sudo chmod +x /usr/local/bin/nuclei
    cd "$ROOT"
    ok "Nuclei $(nuclei -version 2>&1 | grep 'Engine Version') instalado"
else
    ok "Nuclei já instalado"
fi

info "Baixando templates do Nuclei..."
nuclei -update-templates -silent
ok "Templates do Nuclei atualizados"

# ══════════════════════════════════════════════════════════════════════════════
# 11. SPECTRAL (via npm na home do usuário)
# ══════════════════════════════════════════════════════════════════════════════
info "Instalando Spectral..."
if ! command -v spectral &> /dev/null; then
    # Configura npm global na home para evitar problemas de permissão
    mkdir -p "$HOME/.npm-global"
    npm config set prefix "$HOME/.npm-global"

    # Adiciona ao PATH se ainda não estiver
    if ! grep -q ".npm-global/bin" "$HOME/.bashrc"; then
        echo 'export PATH=$HOME/.npm-global/bin:$PATH' >> "$HOME/.bashrc"
    fi
    export PATH="$HOME/.npm-global/bin:$PATH"

    npm install -g @stoplight/spectral-cli -q
    ok "Spectral $(spectral --version 2>&1) instalado"
else
    ok "Spectral já instalado"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 12. CHECKOV (no venv do data-control — instalado depois do venv)
# ══════════════════════════════════════════════════════════════════════════════
# Será instalado na etapa de venvs abaixo, e depois linkado globalmente.

# ══════════════════════════════════════════════════════════════════════════════
# 13. AMBIENTES VIRTUAIS PYTHON
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "Criando ambientes virtuais Python..."

setup_venv() {
    local pasta="$1"
    local nome="$2"
    info "  venv: $nome"
    cd "$ROOT/$pasta"
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip -q
    if [ -f requirements.txt ]; then
        pip install -r requirements.txt -q
    fi
    deactivate
    cd "$ROOT"
    ok "  $nome pronto"
}

setup_venv "core"         "Core"
setup_venv "spirit"       "Spirit"
setup_venv "ghost"        "Ghost"
setup_venv "analyser"     "Analyser"

# data-control: instala requirements + checkov
info "  venv: Data Control + Checkov"
cd "$ROOT/data-control"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -q
if [ -f requirements.txt ]; then
    pip install -r requirements.txt -q
fi
pip install checkov -q
deactivate
cd "$ROOT"

# Linka Checkov globalmente para o PATH
if ! command -v checkov &> /dev/null; then
    sudo ln -sf "$ROOT/data-control/venv/bin/checkov" /usr/local/bin/checkov
fi
ok "  Data Control + Checkov prontos"

# ══════════════════════════════════════════════════════════════════════════════
# 14. PASTAS NECESSÁRIAS
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "Criando pastas..."
mkdir -p "$ROOT/resultados"
mkdir -p "$ROOT/core/jobs"
mkdir -p "$ROOT/logs"
ok "Pastas criadas"

# ══════════════════════════════════════════════════════════════════════════════
# 15. ARQUIVO DE CHAVES
# ══════════════════════════════════════════════════════════════════════════════
echo ""
if [ -f ~/.phantom-fix.env ]; then
    ok "~/.phantom-fix.env já existe — mantendo o existente"
else
    info "Criando ~/.phantom-fix.env com template..."
    cat > ~/.phantom-fix.env << 'EOF'
# ══════════════════════════════════════════════════════════════════════════════
# PhantomFix — Variáveis de ambiente
# NÃO commite este arquivo no Git!
# Preencha todos os valores antes de rodar o start-all.sh
# ══════════════════════════════════════════════════════════════════════════════

# ── LLM (Ollama Cloud) ────────────────────────────────────────────────────────
export OLLAMA_ANALYSER_KEY=""       # chave do Analyser
export OLLAMA_GHOST_KEY=""          # chave do Ghost
export OLLAMA_SPIRIT_KEY=""         # chave do Spirit
export OLLAMA_MODEL="gpt-oss:20b"  # modelo padrão (todos os serviços)

# ── Provedores alternativos ───────────────────────────────────────────────────
export OPENROUTER_API_KEY=""        # fallback via OpenRouter
export GROQ_API_KEY=""              # fallback via Groq
export GHOST_API_KEY=""             # chave interna do Ghost
export SPIRIT_API_KEY=""            # chave interna do Spirit

# ── Email (notificação ao fim do scan) ───────────────────────────────────────
export GMAIL_USER=""                # ex: seuemail@gmail.com
export GMAIL_APP_PASSWORD=""        # senha de app do Gmail (não a senha normal)
export RESEND_API_KEY=""            # alternativa: Resend (resend.com)

# ── URLs dos serviços internos (não alterar se rodar tudo na mesma VM) ────────
export ZAP_API_URL="http://localhost:8080"
export GHOST_URL="http://localhost:8002/corrigir"
export SPIRIT_URL="http://localhost:8001"

# ── Dashboard (URL pública do Nexus) ─────────────────────────────────────────
export DASHBOARD_URL="https://seu-dominio.com"

# ── Configurações do pipeline ─────────────────────────────────────────────────
export SCANNER_TIMEOUT="7200"       # timeout total do scanner em segundos
export ZAP_TIMEOUT="3600"           # timeout do ZAP em segundos
export ANALYSER_LIMITE="0"          # 0 = analisa tudo; N = limita a N findings
export CORRELACAO_LINHAS_PROXIMAS="10"  # tolerância de linha para correlação SAST×DAST
EOF
    ok "~/.phantom-fix.env criado — preencha as chaves antes de rodar!"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 16. PERMISSÕES DOS SCRIPTS
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "Ajustando permissões dos scripts..."
chmod +x "$ROOT/start-all.sh"
ok "Permissões ajustadas"

# ══════════════════════════════════════════════════════════════════════════════
# 17. VERIFICAÇÃO FINAL
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         Verificação dos scanners         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Recarrega PATH para pegar o que foi instalado nessa sessão
export PATH="$HOME/.npm-global/bin:$HOME/.local/bin:/usr/local/bin:$PATH"

TODOS_OK=true
for tool in semgrep gitleaks trivy syft grype trufflehog checkov hadolint nuclei spectral; do
    if command -v "$tool" > /dev/null 2>&1; then
        echo -e "  ${VERDE}✅ $tool${RESET}"
    else
        echo -e "  ${VERMELHO}❌ $tool — não encontrado${RESET}"
        TODOS_OK=false
    fi
done

echo ""

if [ "$TODOS_OK" = true ]; then
    ok "Todos os scanners instalados!"
else
    aviso "Alguns scanners não foram encontrados. Verifique os erros acima."
fi

# ══════════════════════════════════════════════════════════════════════════════
# 18. RESUMO FINAL
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║            Setup concluído!              ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "  Próximos passos:"
echo ""
echo "  1. Preencha as chaves em ~/.phantom-fix.env:"
echo "       nano ~/.phantom-fix.env"
echo ""
echo "  2. Recarregue o terminal para atualizar o PATH:"
echo "       source ~/.bashrc"
echo ""
echo "  3. Suba todos os serviços:"
echo "       $ROOT/start-all.sh"
echo ""
echo "  4. Confirme que está tudo no ar:"
echo "       curl http://localhost:8080/JSON/core/view/version/  # ZAP"
echo "       curl http://localhost:8001/saude                    # Spirit"
echo "       curl http://localhost:8002/health                   # Ghost"
echo "       curl http://localhost:8000/                         # Core"
echo ""
