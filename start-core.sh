#!/bin/bash
echo "Inicializando o PhantomFix Core..."
cd ~/phantom-fix/core
source venv/bin/activate

export SCANNER_PATH="../data-control/scanner.py"
export SCANNER_PYTHON="/home/phantomcore/phantom-fix/data-control/venv/bin/python3"
export SCANNER_TIMEOUT="7200"
export ZAP_API_URL="http://localhost:8080"
export ZAP_TIMEOUT="3600"
source ~/.phantom-fix.env
export OPENROUTER_API_KEY=$OPENROUTER_API_KEY
export OPENROUTER_MODEL="meta-llama/llama-3.3-70b-instruct:free"
export GHOST_URL="http://localhost:8001/corrigir"
export JOBS_DIR="./jobs"
mkdir -p $JOBS_DIR

echo "Core rodando em http://localhost:8000"
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
