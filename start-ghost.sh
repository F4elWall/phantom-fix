#!/bin/bash
echo "👾 Inicializando PhantomFix Ghost..."

cd ~/phantom-fix/ghost
source venv/bin/activate
source ~/.phantom-fix.env

export GHOST_MODEL="llama-3.3-70b-versatile"

echo "Ghost rodando em http://localhost:8002"
echo "Pressione Ctrl+C para parar."

uvicorn main:app --host 0.0.0.0 --port 8002
