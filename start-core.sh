#!/bin/bash

echo "🚀 Inicializando PhantomFix Core..."

cd ~/phantom-fix/core
source venv/bin/activate

# Variáveis principais
export SCANNER_PATH="../data-control/scanner.py"
export SCANNER_PYTHON="/home/phantomcore/phantom-fix/data-control/venv/bin/python3"
export SCANNER_TIMEOUT="7200"
export ZAP_API_URL="http://localhost:8080"
export ZAP_TIMEOUT="3600"

# Carrega as chaves de API
source ~/.phantom-fix.env

export OPENROUTER_MODEL="google/gemma-2-9b-it:free"
export GHOST_URL="http://localhost:8002/corrigir"
export JOBS_DIR="./jobs"

mkdir -p $JOBS_DIR

echo "Core rodando em http://localhost:8000"
echo "Pressione Ctrl+C para parar."

uvicorn main:app --host 0.0.0.0 --port 8000 --reload
