#!/bin/bash

echo "👻 Inicializando PhantomFix Spirit..."

cd ~/phantom-fix/spirit
source venv/bin/activate

# URL do Core (ajuste se estiver usando ngrok)
export CORE_URL="http://localhost:8000"

# Pasta com os PDFs de legislação
# Coloque aqui: lgpd.pdf, iso27001.pdf etc.
export LEGISLACAO_DIR="./legislacao"

# Carrega as chaves de API (mesmo arquivo do Core e Analyser)
source ~/.phantom-fix.env
# O arquivo deve conter: export GEMINI_API_KEY="sua_chave_aqui"

export SPIRIT_MODEL="gemini-1.5-flash"

mkdir -p $LEGISLACAO_DIR

echo "Spirit rodando em http://localhost:8001"
echo "PDFs esperados em: $(pwd)/$LEGISLACAO_DIR"
echo "Pressione Ctrl+C para parar."

uvicorn spirit:app --host 0.0.0.0 --port 8001 --reload
