<div align="center">

# 👻 PhantomFix

**Silêncio inteligente para um código verdadeiramente seguro.**

PhantomFix é uma plataforma ASPM *(Application Security Posture Management)* com IA que encontra o que importa, prioriza o que é crítico e te ajuda a corrigir antes que os problemas se tornem problemas.

<img width="1919" height="907" alt="image" src="https://github.com/user-attachments/assets/8823c6f7-aa1e-46c0-aab2-771679939a55" />


</div>

---

## 🧩 O Problema

Ferramentas de segurança tradicionais costumam geram centenas de alertas a cada análise. Sem uma boa priorização, o desenvolvedor não sabe por onde começar, e o que realmente importa se perde no ruído.

O PhantomFix resolve isso combinando análise estática (SAST) e dinâmica (DAST) com inteligência artificial para **priorizar**, **contextualizar** e **gerar correções automáticas** das vulnerabilidades que mais ameaçam a aplicação ou o sistema.

---

## ✨ Funcionalidades

- 🔍 **Análise SAST** com Semgrep — detecta vulnerabilidades no código-fonte
- 🌐 **Análise DAST** com OWASP ZAP — testa a aplicação em tempo de execução
- 🤖 **Priorização com IA** — um agente ranqueia as vulnerabilidades por criticidade real
- 🛠️ **Correções automáticas (Ghost)** — gera patches de código, pronto para utilizar.
- ⚖️ **Compliance com Spirit AI** — analisa impacto na LGPD, ISO 27001 e NIST via chatbot
- 👤 **Autenticação multi-tenant** — cada usuário vê apenas seus próprios scans
- 🖥️ **Client desktop** — executável Windows para envio seguro de repositórios
- 📊 **Dashboard completo** — score de segurança, histórico de scans e filtros por severidade

---

## 🚀 Como Usar

> Não é necessária nenhuma instalação, e demanda pouquíssima configuração. O PhantomFix é acessado pelo navegador.

### 1. Crie sua conta
Acesse [phantom-fix.vercel.app](https://phantom-fix-f4elwalls-projects.vercel.app) e clique em **Criar conta**. Preencha nome, e-mail e senha.

### 2. Copie seu token único
Após criar a conta, seu token exclusivo será exibido **uma única vez**. Guarde-o — ele vincula o Client Desktop à sua conta.

### 3. Baixe o Client
Clique em **Download PhantomFix Client** e execute o arquivo `.exe` no Windows.

> **⚠️ Aviso de segurança**
>
> O PhantomFix é um projeto acadêmico e o executável **não possui assinatura digital (Code Signing Certificate)**. Por isso, o Windows, o Microsoft Defender SmartScreen ou o navegador podem exibir um aviso de segurança durante o download ou na primeira execução.
>
> Se você baixou o arquivo diretamente deste repositório ou do site oficial do projeto, esse comportamento é esperado. Basta confirmar a execução quando o Windows solicitar.

Ao abrir o Client, cole seu token e clique em **Vincular conta**.

### 4. Volte ao Dashboard
Com o client vinculado, clique em **Token vinculado — Acessar Dashboard** e você estará pronto para analisar.

### 5. Envie um repositório
No Client desktop, selecione a pasta do seu projeto e clique em **Iniciar Análise**. O Dashboard atualizará automaticamente com os resultados.

---

## 🏗️ Arquitetura

```
┌─────────────┐     token+zip      ┌──────────────────────────────────────────┐
│   Client    │ ─────────────────► │                  Core                    │
│  (Windows)  │                    │  FastAPI · SQLite · Multi-tenant         │
└─────────────┘                    └────────┬─────────────┬────────────────────┘
                                            │             │
                               ┌────────────▼──┐   ┌──────▼──────────┐
                               │  Data Control │   │     Analyser    │
                               │  Semgrep+ZAP  │   │   Groq (LLaMA)  │
                               └───────────────┘   └──────┬──────────┘
                                                          │
                                                   ┌──────▼──────────┐
                                                   │      Ghost      │
                                                   │  Correções IA   │
                                                   └─────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                     Dashboard (React)                       │
│  Landing · Auth · Welcome · Results · Histórico · Spirit   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                        Spirit AI                            │
│         FastAPI · Groq · LGPD · ISO 27001 · NIST           │
└─────────────────────────────────────────────────────────────┘
```

| Serviço | Descrição | Porta padrão |
|---|---|---|
| **Core** | API central, auth, pipeline, multi-tenancy | 8000 |
| **Data Control** | Scanner SAST (Semgrep) + DAST (ZAP) | — |
| **Analyser** | Enriquecimento e priorização com IA (Groq) | — |
| **Ghost** | Geração de correções automáticas | 8002 |
| **Spirit** | Assistente de compliance via chatbot | 8001 |
| **Dashboard** | Interface web React | 5173 |
| **Client** | Executável desktop Windows | — |

---
### Estrutura do projeto

```
phantom-fix/
├── core/               # API central e pipeline
├── analyser/           # Enriquecimento com IA
├── ghost/              # Geração de correções
├── spirit/             # Assistente de compliance
├── data-control/       # Scanner SAST + DAST
├── database/           # SQLite e lógica de auth
├── client/             # Executável desktop
├── dashboard/          # Interface web React
└── resultados/         # Relatórios por usuário
```

</details>

---

## 👥 Equipe

Desenvolvido para o projeto Challenge, em parceria com a Pride e a FIAP

| Nome               | RM        | GitHub                                           |
|------------------- |-----------|--------------------------------------------------|
| Rafael Pedro       | RM 573656 | [@F4elWall](https://github.com/F4elWall)         |
| Bernardo Coroa     | RM 569261 | [@beracoroa](https://github.com/beracoroa)       |
| Rafael Toschi      | RM 569258 | [@Rafatoschi](https://github.com/Rafatoschi)     |
| Giovanna Esmelardi | RM 569667 | [@Giovana-gigi](https://github.com/Giovana-gigi) |
| Gustavo Enrique    | RM 571529 |                                                  |


---

## 📄 Licença

Este projeto foi desenvolvido para fins acadêmicos.

---

<div align="center">

</div>
