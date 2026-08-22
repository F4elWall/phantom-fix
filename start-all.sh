#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# PhantomFix — Start All
# Sobe ZAP, Spirit, Ghost e Core em sequência, com logs unificados.
# ══════════════════════════════════════════════════════════════════════════════

VERDE="\033[0;32m"
AMARELO="\033[1;33m"
VERMELHO="\033[0;31m"
CIANO="\033[0;36m"
RESET="\033[0m"

ROOT="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$ROOT/logs"
mkdir -p "$LOG_DIR"

# ── PATH (Semgrep e bins do usuário) ──────────────────────────────────────────
export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"
export HOME="${HOME:-/home/coreuser}"

ok()   { echo -e "${VERDE}✅ $1${RESET}"; }
info() { echo -e "${CIANO}➤  $1${RESET}"; }
erro() { echo -e "${VERMELHO}❌ $1${RESET}"; }

# Carrega variáveis de ambiente
source /home/coreuser/.phantom-fix.env

# Atualiza o código antes de subir
info "Atualizando código..."
git pull origin main
ok "Código atualizado"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         PhantomFix — Iniciando...        ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── 1. ZAP ────────────────────────────────────────────────────────────────────
info "Subindo OWASP ZAP..."
/snap/bin/zaproxy -daemon -port 8080 \
  -config api.disablekey=true \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  > "$LOG_DIR/zap.log" 2>&1 &
ZAP_PID=$!

echo -n "  Aguardando ZAP"
for i in $(seq 1 30); do
  sleep 2
  if curl -s http://localhost:8080/JSON/core/view/version/ > /dev/null 2>&1; then
    echo ""
    ok "ZAP pronto (PID $ZAP_PID)"
    break
  fi
  echo -n "."
  if [ $i -eq 30 ]; then
    echo ""
    erro "ZAP não respondeu após 60s — verifique logs/zap.log"
  fi
done

# ── 2. Spirit ─────────────────────────────────────────────────────────────────
info "Subindo Spirit..."
cd "$ROOT/spirit"
source venv/bin/activate
export CORE_URL="http://localhost:8000"
export SPIRIT_MODEL="openai/gpt-oss-20b"
export SPIRIT_API_KEY="$SPIRIT_API_KEY"
uvicorn spirit:app --host 0.0.0.0 --port 8001 \
  > "$LOG_DIR/spirit.log" 2>&1 &
SPIRIT_PID=$!
deactivate

sleep 3
if curl -s http://localhost:8001/saude > /dev/null 2>&1; then
  ok "Spirit pronto (PID $SPIRIT_PID)"
else
  erro "Spirit não respondeu — verifique logs/spirit.log"
fi

# ── 3. Ghost ──────────────────────────────────────────────────────────────────
info "Subindo Ghost..."
cd "$ROOT/ghost"
source venv/bin/activate
export GHOST_MODEL="openai/gpt-oss-20b"
uvicorn main:app --host 0.0.0.0 --port 8002 \
  > "$LOG_DIR/ghost.log" 2>&1 &
GHOST_PID=$!
deactivate

sleep 3
if curl -s http://localhost:8002/health > /dev/null 2>&1; then
  ok "Ghost pronto (PID $GHOST_PID)"
else
  erro "Ghost não respondeu — verifique logs/ghost.log"
fi

# ── 4. Core ───────────────────────────────────────────────────────────────────
info "Subindo Core..."
cd "$ROOT/core"
source venv/bin/activate
export SCANNER_PATH="$ROOT/data-control/scanner.py"
export SCANNER_PYTHON="$ROOT/data-control/venv/bin/python3"
export SCANNER_TIMEOUT="7200"
export ZAP_API_URL="http://localhost:8080"
export ZAP_TIMEOUT="3600"
export GHOST_URL="http://localhost:8002/corrigir"
export JOBS_DIR="$ROOT/core/jobs"
export RESULTADOS_DIR="$ROOT/resultados"
mkdir -p "$JOBS_DIR"
uvicorn main:app --host 0.0.0.0 --port 8000 \
  > "$LOG_DIR/core.log" 2>&1 &
CORE_PID=$!
deactivate

sleep 3
if curl -s http://localhost:8000/ > /dev/null 2>&1; then
  ok "Core pronto (PID $CORE_PID)"
else
  erro "Core não respondeu — verifique logs/core.log"
fi

# ── Status final ──────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║           Tudo no ar! 👻                 ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "  ZAP    → http://localhost:8080  (PID $ZAP_PID)"
echo "  Spirit → http://localhost:8001  (PID $SPIRIT_PID)"
echo "  Ghost  → http://localhost:8002  (PID $GHOST_PID)"
echo "  Core   → http://localhost:8000  (PID $CORE_PID)"
echo ""
echo "  Logs em: $LOG_DIR/"
echo ""
echo "  Para parar tudo: kill $ZAP_PID $SPIRIT_PID $GHOST_PID $CORE_PID"
echo "  Ou pressione Ctrl+C agora."
echo ""

# ── Tail dos logs unificados ──────────────────────────────────────────────────
trap "echo ''; info 'Encerrando...'; kill $ZAP_PID $SPIRIT_PID $GHOST_PID $CORE_PID 2>/dev/null; exit 0" INT

wait
