{/*# PhantomFix — Copyright (C) 2025–2026 Rafael Pedro, Bernardo Coroa,
   # Giovanna Esmelardi, Gustavo Enrique
   # SPDX-License-Identifier: GPL-3.0-or-later
   # Licenciado sob a GNU GPL v3. Veja LICENSE.md na raiz do repositório.*/}

import logo from "../assets/logo.png";

/**
 * Primeira tela depois de criar a conta.
 *
 * Mostra os dois caminhos para a primeira análise:
 *   1. Criar o primeiro projeto e analisar pelo GitHub, direto no navegador (sem instalar nada);
 *   2. (opcional) Baixar o instalável — leva ao Welcome com token e vínculo do cliente.
 */
export default function Onboarding({ nome, onCriarProjeto, onInstalavel, onIrDashboard, onSair }) {
  const primeiroNome = (nome || "").trim().split(/\s+/)[0] || "";

  return (
    <>
      <style>{`
        .onb-tela { min-height: 100vh; display: flex; flex-direction: column;
          background: var(--void); color: var(--ink); font-family: var(--font-body); }
        .onb-topbar { display: flex; align-items: center; justify-content: space-between;
          padding: 16px 32px; border-bottom: 1px solid var(--mist); }
        .onb-logo { display: flex; align-items: center; gap: 10px; font-family: var(--font-display);
          font-size: 18px; }
        .onb-logo img { width: 30px; height: 30px; object-fit: contain; }
        .onb-sair { background: none; border: 1px solid var(--mist); color: var(--ink-dim);
          padding: 7px 14px; border-radius: 999px; font: inherit; font-size: 13px; cursor: pointer; }
        .onb-sair:hover { color: var(--ink); border-color: var(--ink-dim); }

        .onb-corpo { flex: 1; width: 100%; max-width: 980px; margin: 0 auto;
          padding: 56px 24px 40px; box-sizing: border-box; }
        .onb-selo { display: inline-flex; align-items: center; gap: 8px; padding: 5px 12px;
          border-radius: 999px; background: var(--ecto-dim); color: var(--ecto);
          font-size: 13px; font-weight: 500; margin: 0 0 18px; }
        .onb-titulo { font-family: var(--font-display); font-size: clamp(28px, 4.5vw, 40px);
          line-height: 1.15; margin: 0 0 12px; }
        .onb-titulo span { color: var(--ecto); }
        .onb-sub { color: var(--ink-dim); font-size: 16px; line-height: 1.55; margin: 0 0 40px;
          max-width: 620px; }

        .onb-cards { display: grid; grid-template-columns: 1.25fr 1fr; gap: 20px; align-items: stretch; }
        .onb-card { position: relative; display: flex; flex-direction: column; gap: 14px;
          padding: 26px; border-radius: var(--radius); background: var(--surface);
          border: 1px solid var(--mist); }
        .onb-card-principal { border-color: var(--ecto); box-shadow: 0 0 0 1px var(--ecto-dim), 0 10px 40px var(--ecto-dim); }
        .onb-badge { align-self: flex-start; font-size: 12px; font-weight: 600; letter-spacing: .02em;
          padding: 4px 10px; border-radius: 999px; }
        .onb-badge-rec { background: var(--ecto-dim); color: var(--ecto); }
        .onb-badge-opc { background: var(--violet-dim); color: var(--violet); }
        .onb-card h2 { font-family: var(--font-display); font-size: 22px; margin: 0; }
        .onb-card p { margin: 0; color: var(--ink-dim); font-size: 14.5px; line-height: 1.55; }
        .onb-passos { list-style: none; margin: 4px 0 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
        .onb-passos li { display: flex; align-items: flex-start; gap: 12px; font-size: 14px; line-height: 1.45; }
        .onb-passos b { flex: none; width: 24px; height: 24px; border-radius: 50%; display: grid;
          place-items: center; font-size: 12px; background: var(--ecto-dim); color: var(--ecto); }
        .onb-acao { margin-top: auto; padding-top: 6px; }
        .onb-btn { display: inline-flex; align-items: center; gap: 8px; padding: 12px 20px;
          border-radius: var(--radius-sm); font: inherit; font-size: 15px; font-weight: 600; cursor: pointer;
          border: 1px solid transparent; }
        .onb-btn-primario { background: var(--ecto); color: #07110f; }
        .onb-btn-primario:hover { filter: brightness(1.08); }
        .onb-btn-secundario { background: transparent; color: var(--ink); border-color: var(--ink-dim); }
        .onb-btn-secundario:hover { border-color: var(--ink); }

        .onb-rodape { margin-top: 32px; text-align: center; }
        .onb-link { background: none; border: none; color: var(--ink-dim); font: inherit; font-size: 14px;
          cursor: pointer; text-decoration: underline; text-underline-offset: 3px; }
        .onb-link:hover { color: var(--ink); }

        @media (max-width: 780px) {
          .onb-cards { grid-template-columns: 1fr; }
          .onb-topbar { padding: 14px 18px; }
          .onb-corpo { padding-top: 36px; }
        }
      `}</style>

      <div className="onb-tela">
        <header className="onb-topbar">
          <div className="onb-logo">
            <img src={logo} alt="" />
            <span>Phantom<strong>Fix</strong></span>
          </div>
          {onSair && (
            <button className="onb-sair" onClick={onSair}>Sair</button>
          )}
        </header>

        <main className="onb-corpo">
          <p className="onb-selo">✓ Conta criada com sucesso</p>
          <h1 className="onb-titulo">
            Bem-vindo ao <span>PhantomFix</span>{primeiroNome ? `, ${primeiroNome}` : ""}!
          </h1>
          <p className="onb-sub">
            Falta pouco para a sua primeira análise de segurança. Escolha por onde quer começar:
            você pode analisar direto pelo navegador, sem instalar nada.
          </p>

          <div className="onb-cards">
            {/* ── Caminho principal: projeto + GitHub ── */}
            <section className="onb-card onb-card-principal">
              <span className="onb-badge onb-badge-rec">Recomendado · sem instalar nada</span>
              <h2>Criar meu primeiro projeto</h2>
              <p>
                Conte ao PhantomFix o contexto do seu projeto e analise o código direto
                pelo navegador, a partir de um repositório do GitHub.
              </p>
              <ol className="onb-passos">
                <li><b>1</b><span>Descreva o projeto: stack, ambiente, dados sensíveis e compliance.</span></li>
                <li><b>2</b><span>Cole a URL do repositório no GitHub (token só para repositórios privados).</span></li>
                <li><b>3</b><span>Acompanhe o pipeline e receba as vulnerabilidades priorizadas.</span></li>
              </ol>
              <div className="onb-acao">
                <button className="onb-btn onb-btn-primario" onClick={onCriarProjeto}>
                  Criar projeto
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                    <path d="M3 8h9M9 4.5 12.5 8 9 11.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </button>
              </div>
            </section>

            {/* ── Caminho opcional: instalável ── */}
            <section className="onb-card">
              <span className="onb-badge onb-badge-opc">Opcional · Windows</span>
              <h2>Baixar o instalável</h2>
              <p>
                Prefere analisar uma pasta do seu computador, sem enviá-la ao GitHub?
                Instale o PhantomFix Client, que fica na bandeja do sistema, e vincule-o
                à sua conta com o seu token exclusivo.
              </p>
              <div className="onb-acao">
                <button className="onb-btn onb-btn-secundario" onClick={onInstalavel}>
                  Ver o instalável
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                    <path d="M8 2v8M4.5 7 8 10.5 11.5 7M2.5 13.5h11" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </button>
              </div>
            </section>
          </div>

          <div className="onb-rodape">
            <button className="onb-link" onClick={onIrDashboard}>
              Prefiro explorar o dashboard primeiro
            </button>
          </div>
        </main>
      </div>
    </>
  );
}
