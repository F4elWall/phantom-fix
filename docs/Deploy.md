# 🚀 PhantomFix — Guia de Implantação (Deploy)

Passo a passo para subir o PhantomFix em uma **infraestrutura nova**, do zero.
Para aprender a usar a plataforma depois de instalada, veja o [Guia de Uso](GUIA_DE_USO.md).

> Licença: GPL v3. Veja [LICENSE.md](../LICENSE.md).

---

## 1. Visão geral

O PhantomFix é composto por serviços que rodam em **uma única VM Linux**, mais o Dashboard (web) e, opcionalmente, o agente Windows.

| Componente | O que é | Porta | Onde roda |
|---|---|---|---|
| **Core** | API central, pipeline, autenticação, Nexus | 8000 | VM |
| **Spirit** | Assistente de compliance (RAG) e relatório executivo | 8001 | VM |
| **Ghost** | Geração de correções | 8002 | VM |
| **OWASP ZAP** | Daemon do DAST | 8080 | VM (somente local) |
| **Dashboard** | Interface web React (Vite) | 5173 (dev) | Vercel, VM ou sua máquina |
| **Data-Control** | Agente Windows (bandeja) para enviar repositórios locais | — | PC do usuário |

Os modelos de linguagem rodam no **Ollama Cloud** (nenhuma GPU é necessária na VM).

---

## 2. Pré-requisitos

### 2.1 Servidor (VM)

| Item | Requisito |
|---|---|
| Sistema | Ubuntu 22.04 ou 24.04 (ou Debian equivalente), **limpo** |
| Arquitetura | **x86_64 / amd64** (os scripts baixam binários só para essa arquitetura; ARM não é suportado) |
| Recursos recomendados | 4 vCPU, 8 GB de RAM, 40 GB de disco (os scanners e o ZAP consomem bastante memória) |
| Acesso | Usuário com `sudo` e acesso SSH |
| Internet de saída | Obrigatória: GitHub, NVD, EPSS, CISA KEV, Ollama Cloud e templates do Nuclei |
| Pacotes | Instalados automaticamente pelo `setup.sh`: Python 3, pip, venv, git, curl, wget, unzip, Node.js e npm |

### 2.2 Contas e chaves

| O que | Para quê | Obrigatório? |
|---|---|---|
| **Chaves do Ollama Cloud** (`OLLAMA_ANALYSER_KEY`, `OLLAMA_GHOST_KEY`, `OLLAMA_SPIRIT_KEY`) | IA do Analyser, Ghost e Spirit. Crie em [ollama.com](https://ollama.com) → Settings → API Keys (pode usar a mesma chave nas três variáveis) | **Sim** |
| **Gmail + senha de app** (`GMAIL_USER`, `GMAIL_APP_PASSWORD`) | Envio do relatório em PDF e e-mail de recuperação de senha. Exige verificação em duas etapas ativada na conta Google | Recomendado |
| `NVD_API_KEY` | Acelera as consultas ao NVD | Opcional |
| Domínio com HTTPS | Necessário se o Dashboard ficar em HTTPS (ex.: Vercel), pois o navegador bloqueia chamadas HTTP a partir de página HTTPS | Recomendado |

### 2.3 Rede / Firewall

- Libere **22** (SSH) e **80/443** (se usar proxy reverso).
- **Não exponha a porta 8080 (ZAP) à internet.** O ZAP sobe com a chave de API desativada (`api.disablekey=true`) e aceita qualquer origem. Deixe-a acessível apenas em `localhost`.
- Idealmente, mantenha 8000, 8001 e 8002 fechadas ao público e exponha-as só pelo proxy reverso (seção 6).

---

## 3. Instalação do backend

### 3.1 Clonar o repositório

```bash
git clone https://github.com/F4elWall/phantom-fix.git
cd phantom-fix
```

> ⚠️ **Atenção ao usuário.** O `start-all.sh` carrega as chaves de `/home/coreuser/.phantom-fix.env` (caminho fixo no script). Há duas opções:
> - **A)** Instalar tudo com um usuário chamado `coreuser` (`sudo adduser coreuser && sudo usermod -aG sudo coreuser`) e clonar o repositório na home dele; ou
> - **B)** Usar outro usuário e trocar, no `start-all.sh`, a linha
>   `source /home/coreuser/.phantom-fix.env` por `source "$HOME/.phantom-fix.env"`.

### 3.2 Rodar o setup

```bash
chmod +x setup.sh && ./setup.sh
```

O script (leva alguns minutos) faz tudo sozinho:

1. Atualiza o sistema e instala as dependências básicas.
2. Instala os **10 scanners**: Semgrep, OWASP ZAP (via snap), Gitleaks, Trivy, Syft, Grype, TruffleHog, Hadolint, Nuclei (com templates) e Spectral. O Checkov entra no venv do `data-control`.
3. Cria um ambiente virtual (`venv`) para cada serviço: `core`, `spirit`, `ghost`, `analyser` e `data-control`.
4. Cria as pastas `resultados/`, `core/jobs/` e `logs/`.
5. Gera o template de chaves em `~/.phantom-fix.env`.
6. Verifica se todos os scanners foram instalados e mostra ✅ ou ❌ para cada um.

Ao terminar, recarregue o PATH:

```bash
source ~/.bashrc
```

### 3.3 Configurar as chaves

```bash
nano ~/.phantom-fix.env
```

Preencha, no mínimo:

```bash
export OLLAMA_ANALYSER_KEY="sua-chave"
export OLLAMA_GHOST_KEY="sua-chave"
export OLLAMA_SPIRIT_KEY="sua-chave"
export GMAIL_USER="seuemail@gmail.com"
export GMAIL_APP_PASSWORD="senha-de-app-de-16-caracteres"
export DASHBOARD_URL="https://seu-dominio.com"   # usado nos links dos e-mails
```

| Variável | Uso |
|---|---|
| `OLLAMA_*_KEY` | Chaves do Ollama Cloud de cada serviço |
| `GMAIL_USER` / `GMAIL_APP_PASSWORD` | Envio de e-mails (relatório e recuperação de senha) |
| `DASHBOARD_URL` | URL pública do Dashboard (aparece nos e-mails) |
| `NVD_API_KEY` | Opcional; acelera o NVD |
| `SCANNER_TIMEOUT` / `ZAP_TIMEOUT` | Limites de tempo do scanner e do DAST, em segundos (padrão 7200 e 3600) |
| `ANALYSER_LIMITE` | `0` analisa todos os achados; `N` limita a N |
| `ZAP_API_URL`, `GHOST_URL`, `SPIRIT_URL` | Não altere se tudo roda na mesma VM |

> 🔒 **Nunca versione esse arquivo.** Ele fica na home do usuário, fora do repositório, justamente por isso.

> ℹ️ **Modelos de IA.** Os modelos são definidos dentro do `start-all.sh` (`nemotron-3-super` no Core e no Ghost, `nemotron-3-ultra` no Spirit). Para trocá-los, edite as linhas `export OLLAMA_MODEL=`, `GHOST_MODEL=` e `SPIRIT_MODEL=` desse script.

### 3.4 Subir os serviços

Rode **a partir da raiz do repositório** (o script faz `git pull` na pasta atual):

```bash
./start-all.sh
```

Ele sobe, nesta ordem: **ZAP → Spirit → Ghost → Core**, testa cada um e passa a exibir os logs unificados. Para parar, pressione `Ctrl+C`.

Para manter rodando depois de fechar o SSH, use `tmux`:

```bash
sudo apt install -y tmux
tmux new -s phantom
./start-all.sh
# Para sair sem encerrar: Ctrl+B e depois D   |   Para voltar: tmux attach -t phantom
```

### 3.5 Verificar se está tudo no ar

```bash
curl http://localhost:8080/JSON/core/view/version/   # ZAP
curl http://localhost:8001/saude                     # Spirit
curl http://localhost:8002/health                    # Ghost
curl http://localhost:8000/                          # Core
```

Os quatro devem responder. Se algum falhar, veja `logs/<serviço>.log`.

---

## 4. Dashboard (interface web)

O Dashboard lê os endereços das APIs das variáveis `VITE_CORE_URL` e `VITE_SPIRIT_URL` (padrão: `http://localhost:8000` e `http://localhost:8001`).

### Opção A — Vercel (usada pelo projeto)

1. Importe o repositório no Vercel e defina **Root Directory** como `dashboard`.
2. Em *Environment Variables*, defina:
   - `VITE_CORE_URL` = URL **HTTPS** pública do Core (ex.: `https://seu-dominio.com/api`)
   - `VITE_SPIRIT_URL` = URL **HTTPS** pública do Spirit
3. Faça o deploy.

### Opção B — Rodar localmente (desenvolvimento)

```bash
cd dashboard
npm install
VITE_CORE_URL=http://IP_DA_VM:8000 VITE_SPIRIT_URL=http://IP_DA_VM:8001 npm run dev
```

Acesse `http://localhost:5173`. Para gerar a versão estática (`dashboard/dist`) e servir em qualquer servidor web: `npm run build`.

---

## 5. Agente Windows — Data-Control (opcional)

Só é necessário para analisar repositórios **locais**. A análise por **URL do GitHub** funciona sem ele.

O agente fica na bandeja do sistema e é gerado a partir da pasta `data-control/`. O endereço padrão do Core está fixado no código (`CORE_URL_PADRAO` em `main_data_control.py`) apontando para a infraestrutura original da equipe. Em uma instalação nova, há duas formas de usar o seu servidor:

- **Sem recompilar:** edite `core_url` em `%APPDATA%\PhantomFix\config.json` (formato `https://seu-dominio.com/api/`).
- **Recompilando o `.exe`:** altere `CORE_URL_PADRAO` em `main_data_control.py` e rode `data-control\build.bat` (requer Python no PATH e, para gerar o instalador `PhantomFix-Setup.exe`, o Inno Setup 6).

> ⚠️ O botão de download do Dashboard aponta para o `.exe` publicado nas *Releases* do repositório original da equipe. Se você gerar um `.exe` novo, publique-o nas suas Releases e atualize a constante `EXE_URL` em `dashboard/src/components/Welcome.jsx`.

O executável não possui assinatura digital, então o Windows SmartScreen pode exibir um aviso na primeira execução.

---

## 6. HTTPS com proxy reverso (recomendado)

O agente Windows espera o Core em `https://dominio/api/...`, ou seja, com o prefixo `/api/`. Um exemplo de configuração Nginx:

```nginx
server {
    listen 80;
    server_name seu-dominio.com;

    client_max_body_size 200M;      # tamanho máximo do .zip enviado; ajuste conforme necessário
    proxy_read_timeout 3600;

    location /api/    { proxy_pass http://127.0.0.1:8000/; }   # Core (a barra final remove o /api)
    location /spirit/ { proxy_pass http://127.0.0.1:8001/; }   # Spirit
}
```

Depois, emita o certificado:

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
sudo certbot --nginx -d seu-dominio.com
```

---

## 7. Dados e backup

| O que | Onde |
|---|---|
| Banco SQLite (usuários, projetos, tokens) | `database/phantomfix.db` (ou o caminho em `PHANTOMFIX_DB`) |
| Resultados das análises | `resultados/` |
| Repositórios temporários | `core/jobs/` |
| Logs | `logs/` |
| Chaves | `~/.phantom-fix.env` |

Faça backup, no mínimo, do banco e do arquivo de chaves.

---

## 8. Problemas comuns

| Sintoma | Causa provável / solução |
|---|---|
| `start-all.sh` falha logo no início ao carregar o `.env` | Caminho `/home/coreuser/...` fixo. Veja o aviso da seção 3.1 |
| `command not found: spectral` | Rode `source ~/.bashrc` (o PATH do npm é configurado pelo setup) |
| ❌ em algum scanner na verificação final | Reexecute o `setup.sh`; ele pula o que já está instalado. Verifique a conexão com a internet |
| ZAP não responde em 60 s | Veja `logs/zap.log`; falta de memória é a causa mais comum |
| Spirit/Ghost respondem mas a IA falha | Chave do Ollama vazia ou inválida em `~/.phantom-fix.env` |
| Dashboard mostra erro de rede / *mixed content* | Dashboard em HTTPS chamando Core em HTTP. Configure HTTPS (seção 6) |
| E-mails não chegam | Use **senha de app** do Gmail (não a senha normal) e confira `GMAIL_USER` |
| Erro de CORS | O Core aceita qualquer origem por padrão; confira se `VITE_CORE_URL` está correta |

---

## 9. Checklist final

- [ ] `./setup.sh` concluído com todos os scanners em ✅
- [ ] `~/.phantom-fix.env` preenchido
- [ ] `./start-all.sh` rodando; os 4 `curl` de verificação respondem
- [ ] Dashboard apontando para o Core e o Spirit corretos
- [ ] Porta 8080 (ZAP) fechada ao público
- [ ] Conta criada e primeiro scan concluído (veja o [Guia de Uso](GUIA_DE_USO.md))
