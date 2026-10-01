<div align="center">

# 👻 PhantomFix

**Silêncio inteligente para um código verdadeiramente seguro.**

PhantomFix é uma plataforma ASPM *(Application Security Posture Management)* com IA que encontra o que importa, prioriza o que é crítico e te ajuda a corrigir antes que os problemas se tornem problemas.

<img width="1851" height="1019" alt="image" src="https://github.com/user-attachments/assets/7cd1491c-3e04-4ac1-8b51-f3a232e269db" />

</div>

---

## 🧩 O Problema

Ferramentas de segurança tradicionais costumam gerar centenas de alertas a cada análise. Sem uma boa priorização, o desenvolvedor não sabe por onde começar, e o que realmente importa se perde no ruído.

O PhantomFix resolve isso combinando **onze ferramentas** de análise (SAST, DAST, SCA, segredos, IaC e mais) com inteligência artificial para **correlacionar**, **priorizar**, **contextualizar** e **gerar correções automáticas** das vulnerabilidades que mais ameaçam a aplicação.

Além disso, sentimos falta de um "algo a mais": não só um lugar para ver problemas, mas onde se pudesse entender o significado dessas falhas para o seu negócio. Por isso o PhantomFix tem o **Spirit**, um assistente que se alimenta do contexto do seu projeto, dos resultados das ferramentas e da legislação para quantificar o grau das ameaças e apoiar a tomada de decisão.

---

## ✨ Funcionalidades

### Análise
- 🔍 **SAST** com Semgrep — vulnerabilidades no código-fonte
- 🌐 **DAST** com OWASP ZAP e **Nuclei** — testes na aplicação em execução (CVEs e misconfigurações)
- 🔑 **Segredos** com Gitleaks e TruffleHog (com validação ativa das credenciais)
- 📦 **SCA** com Trivy, Syft (SBOM) e Grype — vulnerabilidades em dependências
- 🏗️ **IaC e contêineres** com Checkov e Hadolint
- 📑 **Schemas de API** com Spectral

### Priorização
- 🧹 **Normalização** — remove ruído e funde duplicatas entre ferramentas
- 🔗 **Correlação** — Trivy × imports reais no código (dependência usada de fato vs. só no lockfile) e Semgrep × ZAP (mesmo tipo e localização)
- 📈 **Enriquecimento** com NVD (CVSS), EPSS (probabilidade de exploração) e CISA KEV (exploração ativa confirmada)
- 🕸️ **Grafo de ataque** — conecta achados de origens diferentes (por exemplo, um segredo exposto e uma injeção no mesmo módulo) e identifica caminhos de ataque
- 👻 **PhantomScore** — pontuação de 0 a 10 que combina CVSS (40%), EPSS (20%), KEV (15%) e alcançabilidade no grafo (25%)
- 🤖 **Análise por IA** — cada vulnerabilidade é analisada considerando o contexto do projeto

### Correção e contexto
- 🛠️ **Ghost** — gera patches de código prontos para uso
- 🧭 **Nexus** — cadastro do contexto do projeto (stack, ambiente, dados sensíveis, compliance, estágio, objetivo e URL para DAST) que calibra a análise
- ⚖️ **Spirit AI** — chatbot com RAG sobre LGPD, ISO 27001 e NIST CSF, além dos resultados e da postura do seu projeto
- 🗃️ **Vault Obsidian** — um cofre de notas por projeto, acumulado entre scans, com uma nota por vulnerabilidade, para baixar e navegar no Obsidian

### Plataforma
- 🐙 **Scan direto de repositório GitHub** — informe a URL do repositório, sem precisar enviar arquivos
- 🖥️ **Client desktop** — executável Windows para envio seguro de repositórios locais
- 👤 **Autenticação multi-tenant** — cada usuário vê apenas seus próprios scans
- 📊 **Dashboard** — acompanhamento do pipeline, resultados com filtros por severidade, histórico, **postura** do projeto ao longo do tempo e chat com o Spirit
- 📝 **Relatório executivo** — gerado pelo Spirit, em tela e em PDF
- 📧 **Notificação por e-mail** — relatório em PDF enviado ao fim de cada análise

---

## 🚀 Como Usar

> O PhantomFix é acessado pelo navegador e demanda pouquíssima configuração.

### 1. Crie sua conta
Acesse [phantom-fix.vercel.app](https://phantom-fix-f4elwalls-projects.vercel.app) e clique em **Criar conta**. Preencha nome, e-mail e senha.

### 2. Descreva seu projeto (Nexus)
Na tela **Projeto**, informe stack, ambiente, tipos de dados sensíveis, requisitos de compliance, estágio e objetivo. Se quiser análise dinâmica, informe também a **URL da aplicação**. Esse contexto faz a IA priorizar do jeito certo para o seu caso.

### 3. Escolha como enviar o código

**Opção A: repositório GitHub.** Cole a URL do repositório (`https://github.com/usuario/repositorio`) e inicie a análise. Para repositórios privados, informe um token de acesso.

**Opção B: Client desktop (Windows).**
1. Copie o **token único** exibido após criar a conta. Ele aparece **uma única vez**.
2. Clique em **Download PhantomFix Client** e execute o `.exe`.
3. Cole o token e clique em **Vincular conta**.
4. Selecione a pasta do projeto e clique em **Iniciar Análise**.

> **⚠️ Aviso de segurança**
>
> O PhantomFix é um projeto acadêmico e o executável **não possui assinatura digital (Code Signing Certificate)**. Por isso, o Windows, o Microsoft Defender SmartScreen ou o navegador podem exibir um aviso durante o download ou na primeira execução. Se você baixou o arquivo diretamente deste repositório ou do site oficial do projeto, esse comportamento é esperado.

### 4. Acompanhe e aja
O Dashboard mostra o andamento do pipeline e, ao final, os resultados ordenados por PhantomScore, as correções sugeridas pelo Ghost, o relatório executivo e o vault para download. Converse com o Spirit para entender o impacto de cada falha.

---

## 🏗️ Arquitetura

```
┌─────────────┐   token + zip    ┌───────────────────────────────────────────┐
│   Client    │ ───────────────► │                   Core                    │
│  (Windows)  │                  │  FastAPI · SQLite · Multi-tenant · Nexus  │
└─────────────┘                  └──┬──────────┬──────────┬──────────┬───────┘
 URL do GitHub ────────────────────►│          │          │          │
                                    │          │          │          │
                      ┌─────────────▼──┐  ┌────▼─────────┐│   ┌──────▼───────┐
                      │  Data Control  │  │   Analyser   ││   │    Vault     │
                      │ 11 ferramentas │  │ normaliza    ││   │   Obsidian   │
                      │ SAST/DAST/SCA  │  │ correlaciona ││   └──────────────┘
                      │ Secrets · IaC  │  │ NVD·EPSS·KEV ││
                      └────────────────┘  │ análise IA   ││
                                          └────┬─────────┘│
                                               │          │
                                         ┌─────▼──────┐   │
                                         │   Grafo    │   │
                                         │ PhantomScore│  │
                                         └─────┬──────┘   │
                                               │          │
                                         ┌─────▼──────┐ ┌─▼────────────────┐
                                         │   Ghost    │ │     Spirit AI    │
                                         │ Correções  │ │ RAG · ChromaDB   │
                                         └────────────┘ │ LGPD·ISO·NIST    │
                                                        └──────────────────┘

┌───────────────────────────────────────────────────────────────────────────┐
│                           Dashboard (React)                               │
│ Landing · Auth · Projeto (Nexus) · Pipeline · Resultados · Histórico ·    │
│ Postura · Relatório executivo · Vault · Spirit                            │
└───────────────────────────────────────────────────────────────────────────┘
```

### Fluxo do pipeline

1. **Recebimento:** zip enviado pelo Client ou clone do repositório GitHub, com o contexto lido do Nexus
2. **Scanner** (`data-control`): executa as ferramentas de análise
3. **Analyser:** normaliza, correlaciona, enriquece com NVD/EPSS/KEV e analisa com IA
4. **Grafo:** correlaciona achados entre ferramentas, monta os caminhos de ataque e calcula o PhantomScore
5. **Ghost:** gera correções, começando pelas vulnerabilidades mais críticas
6. **Spirit:** gera o relatório executivo e indexa os resultados para o chat
7. **Vault e e-mail:** atualiza o vault Obsidian e envia o relatório em PDF

### Serviços

| Serviço | Descrição | Porta padrão |
|---|---|---|
| **Core** | API central, autenticação, pipeline, Nexus, multi-tenancy | 8000 |
| **Spirit** | Assistente de compliance e relatório executivo (RAG com ChromaDB) | 8001 |
| **Ghost** | Geração de correções automáticas | 8002 |
| **OWASP ZAP** | Daemon do DAST, usado pelo scanner | 8080 |
| **Dashboard** | Interface web React (Vite, em desenvolvimento) | 5173 |
| **Data Control / Analyser / Grafo / Vault** | Módulos executados pelo Core | — |
| **Client** | Executável desktop Windows | — |

Os modelos de linguagem rodam no **Ollama Cloud** e podem ser trocados por variável de ambiente, de forma independente para cada serviço.

---

## 🛠️ Executando por conta própria

Requer uma VM Ubuntu/Debian.

```bash
git clone https://github.com/F4elWall/phantom-fix.git
cd phantom-fix
chmod +x setup.sh && ./setup.sh     # instala scanners, dependências e venvs
```

Defina as chaves antes de subir os serviços:

```bash
export OLLAMA_ANALYSER_KEY="..."
export OLLAMA_GHOST_KEY="..."
export OLLAMA_SPIRIT_KEY="..."
```

Em seguida:

```bash
./start-all.sh      # sobe ZAP, Spirit, Ghost e Core, com logs unificados
```

### Principais variáveis de ambiente

| Variável | Uso |
|---|---|
| `OLLAMA_ANALYSER_KEY` / `OLLAMA_GHOST_KEY` / `OLLAMA_SPIRIT_KEY` | Chaves do Ollama Cloud de cada serviço |
| `OLLAMA_MODEL` / `GHOST_MODEL` / `SPIRIT_MODEL` | Modelo usado por Analyser, Ghost e Spirit |
| `EMBED_MODEL` | Modelo de embeddings do Spirit (padrão `all-MiniLM-L6-v2`) |
| `NVD_API_KEY` | Opcional; acelera as consultas ao NVD |
| `GMAIL_USER` / `GMAIL_APP_PASSWORD` | Envio do relatório por e-mail |
| `ZAP_API_URL` / `ZAP_TIMEOUT` | Endereço do ZAP e limite de tempo do DAST |
| `SCANNER_TIMEOUT` | Limite de tempo total do scanner |
| `RESULTADOS_DIR` / `JOBS_DIR` | Onde ficam resultados e repositórios temporários |
| `VITE_CORE_URL` / `VITE_SPIRIT_URL` | Endereços das APIs usados pelo Dashboard |

Para rodar o Dashboard localmente:

```bash
cd dashboard
npm install
npm run dev
```

> **Segurança:** nunca versione chaves de API nem tokens. Use variáveis de ambiente ou um gerenciador de segredos.

---

## 📁 Estrutura do projeto

```
phantom-fix/
├── core/               # API central, pipeline, grafo de ataque e postura
├── analyser/           # Normalização, correlação e enriquecimento com IA
├── ghost/              # Geração de correções
├── spirit/             # Assistente de compliance (RAG)
│   └── legislacao/     # PDFs de referência (LGPD, ISO 27001, NIST CSF)
├── data-control/       # Scanner (11 ferramentas) e agente desktop
├── vault/              # Gerador do vault Obsidian
├── database/           # SQLite, autenticação e projetos (Nexus)
├── client/             # Client desktop
├── dashboard/          # Interface web React
├── setup.sh            # Instalação completa em uma VM nova
└── start-all.sh        # Sobe todos os serviços
```

---

## 👥 Equipe

Desenvolvido para o projeto Challenge, em parceria com a Pride e a FIAP

| Nome               | RM        | GitHub                                           |
|------------------- |-----------|--------------------------------------------------|
| Rafael Pedro       | RM 573656 | [@F4elWall](https://github.com/F4elWall)         |
| Bernardo Coroa     | RM 569261 | [@beracoroa](https://github.com/beracoroa)       |
| Giovanna Esmelardi | RM 569667 | [@Giovana-gigi](https://github.com/Giovana-gigi) |
| Gustavo Enrique    | RM 571529 |                                                  |

---

## 📄 Licença

Este projeto foi desenvolvido para fins acadêmicos.
