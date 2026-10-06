# 👻 PhantomFix — Guia de Uso

Do primeiro acesso à leitura dos resultados. Se você ainda precisa instalar a plataforma, veja o [Guia de Implantação](DEPLOY.md).

> Licença: GPL v3. Veja [LICENSE.md](../LICENSE.md).

---

## 1. Criar sua conta

1. Abra o Dashboard do PhantomFix no navegador.
2. Na página inicial, clique em **Criar conta**.
3. Preencha **nome**, **e-mail** e **senha** e confirme.
4. Ao concluir, o sistema mostra o seu **token exclusivo**.

> ⚠️ **Copie o token agora.** Ele é exibido **uma única vez** e não pode ser recuperado. Se perder, gere um novo pelo menu superior; o token anterior é invalidado. Você só precisa dele para usar o agente desktop.

### Já tenho conta

Clique em **Entrar** e informe e-mail e senha.

### Esqueci minha senha

1. Na tela de login, clique em **Esqueci minha senha**.
2. Informe o e-mail da conta. Se ele existir, você recebe um link de redefinição.
3. Abra o link e defina a nova senha (**mínimo de 6 caracteres**).

Por segurança, o sistema responde da mesma forma exista ou não a conta, para não revelar quais e-mails estão cadastrados.

---

## 2. Configurar o projeto (Nexus)

O Nexus guarda o **contexto do seu projeto**. A IA usa essas informações para priorizar as vulnerabilidades do jeito certo para o seu caso. Quanto mais fiel o cadastro, melhor a análise.

| Campo | O que informar |
|---|---|
| **Nome do projeto** | Ex.: *Portal de pedidos* |
| **Stack** | Marque tudo o que o projeto usa (linguagens, frameworks, banco de dados…) |
| **Ambiente** | Onde a aplicação roda (produção, homologação, nuvem…) |
| **URL da aplicação** | *Opcional.* Habilita a análise dinâmica (DAST). **Em branco = o DAST é pulado** |
| **Estágio** | Fase do projeto (desenvolvimento, pré-lançamento, produção…) |
| **Dados sensíveis** | O que o sistema guarda ou processa (dados pessoais, financeiros, saúde…) |
| **Conformidade exigida** | Opcional. Ex.: LGPD, ISO 27001, NIST CSF |
| **Objetivo** | Ex.: *Validar conformidade com a LGPD antes do lançamento* |

Você também pode deixar o **Spirit** conduzir o cadastro: ele faz perguntas, você revisa as respostas e salva.

Para alterar o contexto depois, abra a tela **Projeto** a qualquer momento.

> ✅ Só informe uma URL de DAST de aplicações que **você tem autorização para testar**.

---

## 3. Enviar o código para análise

Escolha uma das duas formas.

### Opção A — Repositório GitHub

1. Cole a URL do repositório, no formato `https://github.com/usuario/repositorio`.
2. Se o repositório for **privado**, informe também um **token de acesso do GitHub** (`ghp_...` ou `github_pat_...`) com permissão de leitura.
3. Inicie a análise.

Nenhum arquivo precisa ser enviado: o PhantomFix clona o repositório.

### Opção B — Agente desktop (Windows)

Indicado para código que só existe na sua máquina.

1. Na tela de boas-vindas, clique em **Download PhantomFix Client** e execute o instalador.
   > O executável não tem assinatura digital. O Windows ou o navegador podem exibir um aviso de segurança. Isso é esperado em um projeto acadêmico.
2. O PhantomFix passa a rodar na **bandeja do sistema** (ao lado do relógio). Clique com o botão direito no ícone e abra **Configurações**.
3. Cole o **token exclusivo** copiado no cadastro e selecione a **pasta do projeto**.
4. Clique no ícone e escolha **Analisar agora**.

O agente compacta a pasta (ignorando `.git`, `node_modules`, `.venv`, `dist` e `build`), valida o arquivo e o envia ao Core, com novas tentativas em caso de falha. O token fica guardado no cofre de credenciais do Windows. O agente também consulta o Core a cada 60 segundos: se houver uma análise agendada para você, ele envia o código sozinho. O status atual aparece no menu do ícone.

---

## 4. Acompanhar o pipeline

Assim que a análise começa, a tela **Pipeline** mostra o andamento em tempo real, com os logs de cada etapa:

1. **Recebimento** do código e leitura do contexto do Nexus
2. **Scanners** (SAST, DAST, SCA, segredos, IaC e schemas de API)
3. **Analyser**: normaliza, remove duplicatas, correlaciona e enriquece com NVD, EPSS e CISA KEV
4. **Grafo de ataque** e cálculo do **PhantomScore**
5. **Ghost**: gera as correções
6. **Spirit**: gera o relatório executivo e indexa os resultados para o chat
7. **Vault** e **e-mail** com o relatório em PDF

A duração depende do tamanho do projeto e de o DAST estar habilitado. Você pode fechar a página: ao final, o relatório também chega por e-mail.

---

## 5. Ler os resultados

### Tela de Resultados

Os achados vêm ordenados pelo **PhantomScore**, de 0 a 10. Ele combina:

| Fator | Peso |
|---|---|
| CVSS (gravidade técnica) | 40% |
| EPSS (probabilidade de exploração) | 20% |
| CISA KEV (exploração ativa confirmada) | 15% |
| Alcançabilidade no grafo de ataque | 25% |

O que dá para fazer na tela:

- **Filtrar** por severidade, scanner e explorabilidade.
- Alternar entre **Bruto** (o achado original da ferramenta) e **Aprimorado** (análise da IA no contexto do seu projeto, com o **patch sugerido pelo Ghost**).
- Identificar achados com o selo **KEV** (exploração ativa conhecida) e as tags de rastreabilidade (de qual ferramenta veio cada achado).
- Marcar **Corrigido**. Se a falha reaparecer em um scan posterior, o achado é **reaberto automaticamente**.
- Marcar **Falso positivo**, com **justificativa obrigatória**.

### Relatório executivo

Resumo em linguagem de negócio, gerado pelo Spirit. Pode ser lido na tela ou baixado em **PDF**.

### Histórico e Postura

- **Histórico:** lista das análises anteriores.
- **Postura:** evolução da segurança do projeto ao longo das **10 últimas análises**: PhantomScore, variação (delta) e vulnerabilidades recorrentes. O Spirit também traz uma recomendação proativa.

### Vault Obsidian

Um cofre de notas do projeto, acumulado entre os scans, com **uma nota por vulnerabilidade**. Baixe o arquivo, extraia e abra a pasta no [Obsidian](https://obsidian.md) para navegar pelos achados.

---

## 6. Conversar com o Spirit

O **Spirit** é o assistente de IA do PhantomFix. Ele conhece:

- a **legislação**: LGPD, ISO 27001 e NIST CSF;
- os **resultados** das suas análises;
- a **postura** e o contexto do seu projeto.

Exemplos de perguntas:

- *"Qual falha devo corrigir primeiro e por quê?"*
- *"Essa vulnerabilidade pode gerar problema com a LGPD?"*
- *"Explique esse achado para alguém da diretoria."*

---

## 7. Perguntas frequentes

**O DAST não rodou.** O campo *URL da aplicação* do Nexus estava em branco. Preencha e rode uma nova análise.

**Perdi o token do agente.** Gere um novo pelo menu superior. O anterior deixa de funcionar e o agente precisa ser reconfigurado com o novo token.

**O e-mail com o relatório não chegou.** Confira a caixa de spam. Se você administra a instalação, veja a configuração de e-mail no [Guia de Implantação](DEPLOY.md).

**Outros usuários veem meus scans?** Não. A plataforma é multi-tenant: cada usuário vê apenas as próprias análises.

**O Windows bloqueou o executável.** O `.exe` não é assinado digitalmente. Se você o baixou do site ou do repositório oficial do projeto, pode prosseguir.
