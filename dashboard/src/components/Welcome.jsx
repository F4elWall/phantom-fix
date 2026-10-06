{/*# PhantomFix — Copyright (C) 2025–2026 Rafael Pedro, Bernardo Coroa,
   # Giovanna Esmelardi, Gustavo Enrique
   # SPDX-License-Identifier: GPL-3.0-or-later
   # Licenciado sob a GNU GPL v3. Veja LICENSE.md na raiz do repositório.*/}

import { useState, useEffect } from "react";
import logo from "../assets/logo.png";
import { regenToken, checkLink, buscarProjeto, salvarProjeto, baixarConfiguracoes, scanGithub } from "../api";

const EXE_URL = "https://github.com/F4elWall/phantom-fix/releases/download/phantom-fix.exe/PhantomFix.exe";

const OPT = {
  stack:  ["JavaScript/TS", "Python", "Java", "Go", "Docker", "Terraform", "Kubernetes", "API REST/GraphQL"],
  sens:   ["Dados pessoais", "Credenciais", "Pagamento", "Saúde"],
  comp:   ["LGPD", "ISO 27001", "NIST CSF", "PCI DSS"],
  env:    ["Internet pública", "Rede interna", "Somente local"],
  stage:  ["Protótipo", "MVP", "Produção"],
};

// ── Chip de seleção múltipla ──────────────────────────────────────────────────
function Chips({ campo, valores, onChange }) {
  function toggle(v) {
    onChange(campo, valores.includes(v) ? valores.filter(x => x !== v) : [...valores, v]);
  }
  return (
    <div className="nexus-chips">
      {OPT[campo].map(v => (
        <button
          key={v}
          type="button"
          className={`nexus-chip${valores.includes(v) ? " nexus-chip-ativo" : ""}`}
          onClick={() => toggle(v)}
        >
          {v}
        </button>
      ))}
    </div>
  );
}

// ── Select simples ────────────────────────────────────────────────────────────
function Select({ campo, valor, onChange }) {
  return (
    <select
      className="nexus-select"
      value={valor}
      onChange={e => onChange(campo, e.target.value)}
    >
      <option value="">Selecione</option>
      {OPT[campo].map(v => <option key={v}>{v}</option>)}
    </select>
  );
}

export default function Welcome({ usuario, onAcessarDashboard, onConfigurarProjeto }) {
  const token = usuario?.token || localStorage.getItem("user_token") || "";

  // ── Estado geral ────────────────────────────────────────────────────────────
  const [popupAberto,  setPopupAberto]  = useState(true);
  const [copiado,      setCopiado]      = useState(false);
  const [regenando,    setRegenando]    = useState(false);
  const [tokenAtual,   setTokenAtual]   = useState(token);
  const [verificando,  setVerificando]  = useState(false);
  const [erroLink,     setErroLink]     = useState("");
  const [passo,        setPasso]        = useState(1); // 1·2·3 = passos originais, 4 = contexto

  // ── Estado do formulário de contexto (Passo 4) ──────────────────────────────
  const [form, setForm] = useState({
    nome: "", stack: [], env: "", url: "",
    stage: "", sens: [], comp: [], objetivo: "",
  });
  const [projetoSalvo,   setProjetoSalvo]   = useState(false);
  const [salvando,       setSalvando]       = useState(false);
  const [erroProjeto,    setErroProjeto]    = useState("");

  // ── Estado do scan GitHub ───────────────────────────────────────────────────
  const [ghUrl,          setGhUrl]          = useState("");
  const [ghToken,        setGhToken]        = useState("");
  const [scanando,       setScanando]       = useState(false);
  const [erroScan,       setErroScan]       = useState("");
  const [scanIniciado,   setScanIniciado]   = useState(false);

  // Carrega projeto existente ao entrar no passo 4
  useEffect(() => {
    if (passo !== 4) return;
    buscarProjeto().then(p => {
      if (!p) return;
      setForm({
        nome:    p.nome    || "",
        stack:   p.stack   ? p.stack.split(",").map(s => s.trim()).filter(Boolean) : [],
        env:     p.ambiente || "",
        url:     p.zap_url || "",
        stage:   p.estagio || "",
        sens:    p.dados_sensiveis ? p.dados_sensiveis.split(",").map(s => s.trim()).filter(Boolean) : [],
        comp:    p.compliance      ? p.compliance.split(",").map(s => s.trim()).filter(Boolean) : [],
        objetivo: p.objetivo || "",
      });
      setProjetoSalvo(true);
    }).catch(() => {});
  }, [passo]);

  // ── Handlers gerais ─────────────────────────────────────────────────────────
  async function copiarToken() {
    await navigator.clipboard.writeText(tokenAtual);
    setCopiado(true);
    setTimeout(() => setCopiado(false), 2000);
  }

  async function handleRegen() {
    setRegenando(true);
    try {
      const dados = await regenToken();
      setTokenAtual(dados.token);
      localStorage.setItem("user_token", dados.token);
      setPopupAberto(true);
    } catch { /* ignore */ }
    finally { setRegenando(false); }
  }

  async function handleAcessar() {
    setErroLink("");
    setVerificando(true);
    try {
      const dados = await checkLink();
      if (dados.client_linked) {
        localStorage.setItem("client_linked", "true");
        onAcessarDashboard();
      } else {
        setErroLink("Client ainda não vinculado. Cole o token no executável e tente novamente.");
      }
    } catch {
      setErroLink("Não foi possível verificar. O Core está rodando?");
    } finally {
      setVerificando(false);
    }
  }

  // ── Handlers do formulário de contexto ─────────────────────────────────────
  function handleFormChange(campo, valor) {
    setForm(prev => ({ ...prev, [campo]: valor }));
    setProjetoSalvo(false);
    setErroProjeto("");
  }

  function formValido() {
    return form.nome.trim() && form.stack.length && form.env && form.stage;
  }

  async function handleSalvar() {
    if (!formValido()) return;
    setSalvando(true);
    setErroProjeto("");
    try {
      await salvarProjeto({
        nome:            form.nome.trim(),
        stack:           form.stack.join(", "),
        ambiente:        form.env,
        dados_sensiveis: form.sens.join(", ") || null,
        compliance:      form.comp.join(", ") || null,
        estagio:         form.stage,
        objetivo:        form.objetivo.trim() || null,
        zap_url:         form.env === "Internet pública" && form.url.trim() ? form.url.trim() : null,
      });
      setProjetoSalvo(true);
    } catch (e) {
      setErroProjeto(e.message);
    } finally {
      setSalvando(false);
    }
  }

  async function handleBaixarConfig() {
    try {
      await baixarConfiguracoes();
    } catch (e) {
      setErroProjeto(e.message);
    }
  }

  async function handleScanGithub() {
    setErroScan("");
    if (!ghUrl.trim() || !ghToken.trim()) {
      setErroScan("Preencha a URL do repositório e o token GitHub.");
      return;
    }
    setScanando(true);
    try {
      await scanGithub({
        githubToken: ghToken.trim(),
        repositorio: ghUrl.trim(),
        clientToken: tokenAtual,
      });
      setScanIniciado(true);
    } catch (e) {
      setErroScan(e.message);
    } finally {
      setScanando(false);
    }
  }

  // ── Render ──────────────────────────────────────────────────────────────────
  return (
    <>
      {/* ── Pop-up do token ──────────────────────────────────────────────────── */}
      {popupAberto && (
        <div className="wlc-overlay" onClick={() => setPopupAberto(false)}>
          <div className="wlc-popup" onClick={e => e.stopPropagation()}>
            <button className="wlc-popup-close" onClick={() => setPopupAberto(false)}>✕</button>
            <div className="wlc-popup-avatar">
              <img src={logo} alt="PhantomFix" />
              <span className="wlc-popup-star">✦</span>
            </div>
            <h2 className="wlc-popup-titulo">Seu token exclusivo</h2>
            <p className="wlc-popup-sub">
              Este token é exibido apenas uma vez.<br />Guarde-o com segurança.
            </p>
            <div className="wlc-token-row">
              <code className="wlc-token-code">pf_{tokenAtual}</code>
              <button className="wlc-token-copy" onClick={copiarToken} title="Copiar">
                {copiado
                  ? <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><path d="M3 9l4 4 8-8" stroke="var(--ecto)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  : <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><rect x="6" y="6" width="9" height="9" rx="2" stroke="currentColor" strokeWidth="1.5"/><path d="M3 12V3h9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>
                }
              </button>
            </div>
            <div className="wlc-aviso-box">
              <span className="wlc-aviso-icon">⚠</span>
              <div>
                <p className="wlc-aviso-titulo">Importante: este token não poderá ser recuperado.</p>
                <p className="wlc-aviso-desc">Caso perca, gere um novo quando necessário.</p>
              </div>
            </div>
            <button className="wlc-btn-regen" onClick={handleRegen} disabled={regenando}>
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2 8a6 6 0 1 0 1.5-3.9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/><path d="M2 4v4h4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
              {regenando ? "Gerando..." : "Gerar novo Token"}
            </button>
          </div>
        </div>
      )}

      {/* ── Tela principal ───────────────────────────────────────────────────── */}
      <div className="wlc-tela">

        {/* Topbar */}
        <div className="wlc-topbar">
          <div className="wlc-topbar-logo">
            <img src={logo} alt="" />
            <span>Phantom<strong>Fix</strong></span>
          </div>
          {/* Navegação entre passos */}
          <div className="wlc-topbar-steps">
            {[
              { n: 1, label: "Início" },
              { n: 4, label: "Configurar projeto" },
            ].map(({ n, label }) => (
              <button
                key={n}
                className={`wlc-step-tab${passo === n || (passo <= 3 && n === 1) ? " ativo" : ""}`}
                onClick={() => setPasso(n)}
              >
                {label}
              </button>
            ))}
          </div>
          <button className="wlc-help-btn">
            <svg width="15" height="15" viewBox="0 0 15 15" fill="none"><circle cx="7.5" cy="7.5" r="6.5" stroke="currentColor" strokeWidth="1.3"/><path d="M7.5 5a1.5 1.5 0 0 1 .87 2.72C7.8 8.15 7.5 8.58 7.5 9.1" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/><circle cx="7.5" cy="11" r=".6" fill="currentColor"/></svg>
            Precisa de ajuda?
          </button>
        </div>

        {/* ════════════════════════════════════════════════════════════════════
            PASSO 4 — CONFIGURAR PROJETO
        ════════════════════════════════════════════════════════════════════ */}
        {passo === 4 && (
          <div className="wlc-corpo wlc-corpo-unica">
            <div className="nexus-form-wrap">
              <h2 className="nexus-form-titulo">Configurar projeto</h2>
              <p className="nexus-form-sub">
                Preencha o contexto do seu projeto. Ele será usado pelo Core para
                guiar a análise e definir os scanners ativos.
              </p>

              {/* Nome */}
              <div className="nexus-campo">
                <label className="nexus-label">Nome do projeto</label>
                <input
                  className="nexus-input"
                  type="text"
                  value={form.nome}
                  onChange={e => handleFormChange("nome", e.target.value)}
                  placeholder="Ex.: Portal de pedidos"
                />
              </div>

              {/* Stack */}
              <div className="nexus-campo">
                <label className="nexus-label">Stack</label>
                <p className="nexus-hint">Marque tudo o que o projeto usa.</p>
                <Chips campo="stack" valores={form.stack} onChange={handleFormChange} />
              </div>

              {/* Ambiente */}
              <div className="nexus-campo">
                <label className="nexus-label">Ambiente</label>
                <Select campo="env" valor={form.env} onChange={handleFormChange} />
              </div>

              {/* URL do ZAP — só aparece se público */}
              {form.env === "Internet pública" && (
                <div className="nexus-campo">
                  <label className="nexus-label">
                    URL da aplicação{" "}
                    <span className="nexus-label-opt">(para o ZAP — opcional)</span>
                  </label>
                  <input
                    className="nexus-input"
                    type="url"
                    value={form.url}
                    onChange={e => handleFormChange("url", e.target.value)}
                    placeholder="https://app.exemplo.com"
                  />
                  <p className="nexus-hint">Deixe em branco para pular o scan DAST.</p>
                </div>
              )}

              {/* Estágio */}
              <div className="nexus-campo">
                <label className="nexus-label">Estágio</label>
                <Select campo="stage" valor={form.stage} onChange={handleFormChange} />
              </div>

              {/* Dados sensíveis */}
              <div className="nexus-campo">
                <label className="nexus-label">Dados sensíveis</label>
                <p className="nexus-hint">O que o sistema guarda ou processa?</p>
                <Chips campo="sens" valores={form.sens} onChange={handleFormChange} />
              </div>

              {/* Conformidade */}
              <div className="nexus-campo">
                <label className="nexus-label">Conformidade exigida</label>
                <Chips campo="comp" valores={form.comp} onChange={handleFormChange} />
              </div>

              {/* Objetivo */}
              <div className="nexus-campo">
                <label className="nexus-label">
                  Objetivo da análise{" "}
                  <span className="nexus-label-opt">(opcional)</span>
                </label>
                <textarea
                  className="nexus-textarea"
                  rows={3}
                  value={form.objetivo}
                  onChange={e => handleFormChange("objetivo", e.target.value)}
                  placeholder="Ex.: Identificar vulnerabilidades antes do lançamento"
                />
              </div>

              {erroProjeto && (
                <p className="nexus-erro">{erroProjeto}</p>
              )}

              {projetoSalvo && (
                <div className="nexus-salvo">
                  ✓ Contexto salvo. Baixe o arquivo e inclua no zip enviado pelo instalável.
                </div>
              )}

              {/* Ações do formulário */}
              <div className="nexus-acoes">
                <button
                  className="wlc-acessar-btn"
                  onClick={handleSalvar}
                  disabled={!formValido() || salvando}
                >
                  {salvando ? "Salvando…" : projetoSalvo ? "Salvar novamente" : "Salvar contexto"}
                </button>

                {projetoSalvo && (
                  <button
                    className="wlc-btn-regen wlc-btn-regen-outline"
                    onClick={handleBaixarConfig}
                  >
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2v8M4 8l4 4 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><path d="M2 14h12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>
                    Baixar configuracoes_scan.json
                  </button>
                )}
              </div>

              {/* ── Scan via GitHub ─────────────────────────────────────────── */}
              <div className="nexus-gh-secao">
                <h3 className="nexus-gh-titulo">
                  <svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
                  Analisar via GitHub
                </h3>
                <p className="nexus-hint">
                  Use um token fine-grained com permissão de leitura. O Core clona
                  o repositório e inicia a análise automaticamente.
                </p>

                <div className="nexus-campo">
                  <label className="nexus-label">URL do repositório</label>
                  <input
                    className="nexus-input"
                    type="url"
                    value={ghUrl}
                    onChange={e => setGhUrl(e.target.value)}
                    placeholder="https://github.com/org/repositorio"
                  />
                </div>

                <div className="nexus-campo">
                  <label className="nexus-label">Token de acesso GitHub</label>
                  <input
                    className="nexus-input"
                    type="text"
                    autoComplete="off"
                    value={ghToken}
                    onChange={e => setGhToken(e.target.value)}
                    placeholder="ghp_ ou github_pat_..."
                  />
                </div>

                {erroScan && <p className="nexus-erro">{erroScan}</p>}

                {scanIniciado ? (
                  <div className="nexus-salvo">
                    ✓ Scan iniciado! Acompanhe o progresso no Dashboard.
                  </div>
                ) : (
                  <button
                    className="wlc-acessar-btn"
                    onClick={handleScanGithub}
                    disabled={scanando}
                    style={{ marginTop: "8px" }}
                  >
                    {scanando ? "Iniciando…" : "Iniciar análise"}
                  </button>
                )}

                {scanIniciado && (
                  <button
                    className="wlc-acessar-btn"
                    onClick={onAcessarDashboard}
                    style={{ marginTop: "8px" }}
                  >
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2 8h9M8 5l4 3-4 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
                    Ir para o Dashboard
                  </button>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════════════════════
            PASSOS 1–3 — FLUXO ORIGINAL
        ════════════════════════════════════════════════════════════════════ */}
        {passo !== 4 && (
          <>
            <div className="wlc-corpo">
              {/* Coluna esquerda */}
              <div className="wlc-esquerda">
                <p className="wlc-bem-vindo-label">Bem-vindo ao</p>
                <h1 className="wlc-hero-titulo">PhantomFix!</h1>
                <p className="wlc-hero-desc">
                  Sua conta foi criada com sucesso. Antes de iniciar sua primeira análise,
                  vincule o{" "}
                  <span className="wlc-destaque">PhantomFix Client</span> à sua conta
                  usando seu token único.
                </p>
                <div className="wlc-seguranca-card">
                  <div className="wlc-seguranca-icon">
                    <svg width="22" height="22" viewBox="0 0 22 22" fill="none"><path d="M11 2L4 5v6c0 4.4 3 8.2 7 9 4-0.8 7-4.6 7-9V5l-7-3z" stroke="var(--violet)" strokeWidth="1.5" strokeLinejoin="round"/><path d="M8 11l2 2 4-4" stroke="var(--violet)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  </div>
                  <div>
                    <p className="wlc-seguranca-titulo">Segurança em primeiro lugar</p>
                    <p className="wlc-seguranca-desc">
                      Seu token é único e intransferível, garantindo que apenas você
                      possa vincular o cliente desktop à sua conta.
                    </p>
                  </div>
                </div>
              </div>

              {/* Coluna direita — passos */}
              <div className="wlc-direita">
                {/* Passo 1 */}
                <div className="wlc-passo">
                  <div className="wlc-passo-num">1</div>
                  <div className="wlc-passo-corpo">
                    <h3 className="wlc-passo-titulo">Baixe o Cliente Oficial</h3>
                    <p className="wlc-passo-desc">
                      Clique no botão abaixo para baixar o PhantomFix Client para Windows.
                    </p>
                    <a href={EXE_URL} className="wlc-download-btn" download>
                      <svg width="20" height="20" viewBox="0 0 20 20" fill="none"><rect x="2" y="2" width="7" height="5" rx="1" fill="white" opacity=".9"/><rect x="11" y="2" width="7" height="5" rx="1" fill="white" opacity=".6"/><rect x="2" y="9" width="7" height="5" rx="1" fill="white" opacity=".6"/><rect x="11" y="9" width="7" height="5" rx="1" fill="white" opacity=".3"/></svg>
                      Download PhantomFix Client
                      <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><path d="M9 3v9M5 9l4 4 4-4" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><path d="M3 15h12" stroke="white" strokeWidth="1.5" strokeLinecap="round"/></svg>
                    </a>
                    <p className="wlc-download-meta">Windows (.exe) • Versão 1.0.0</p>
                  </div>
                </div>

                <div className="wlc-separador" />

                {/* Passo 2 */}
                <div className="wlc-passo">
                  <div className="wlc-passo-num">2</div>
                  <div className="wlc-passo-corpo">
                    <h3 className="wlc-passo-titulo">Vincule o Cliente</h3>
                    <p className="wlc-passo-desc">
                      No PhantomFix Client, ao abrir o aplicativo, cole seu token único
                      no campo indicado.
                    </p>
                    <div
                      className="wlc-token-preview"
                      onClick={() => setPopupAberto(true)}
                      title="Ver token completo"
                    >
                      <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2 8h2M12 8h2M5 5l-2 3 2 3M11 5l2 3-2 3" stroke="var(--violet)" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/></svg>
                      <span>Seu token exclusivo</span>
                      <span className="wlc-token-hint">clique para ver</span>
                    </div>
                    <button
                      className="wlc-btn-regen wlc-btn-regen-outline"
                      onClick={handleRegen}
                      disabled={regenando}
                    >
                      <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2 8a6 6 0 1 0 1.5-3.9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/><path d="M2 4v4h4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
                      {regenando ? "Gerando..." : "Gerar novo Token"}
                    </button>
                  </div>
                </div>

                <div className="wlc-separador" />

                {/* Passo 3 */}
                <div className="wlc-passo">
                  <div className="wlc-passo-num">3</div>
                  <div className="wlc-passo-corpo">
                    <h3 className="wlc-passo-titulo">Acesse o Dashboard</h3>
                    <p className="wlc-passo-desc">
                      Após vincular o cliente com sucesso, clique no botão abaixo
                      para acessar o dashboard e começar a realizar suas análises.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="wlc-footer">
              <div className="wlc-footer-aviso">
                <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><circle cx="9" cy="9" r="7.5" stroke="var(--ink-dim)" strokeWidth="1.3"/><path d="M9 5v4" stroke="var(--ink-dim)" strokeWidth="1.3" strokeLinecap="round"/><circle cx="9" cy="12.5" r=".7" fill="var(--ink-dim)"/></svg>
                <div>
                  <p className="wlc-footer-titulo">Ainda não vinculou o cliente?</p>
                  <p className="wlc-footer-desc">
                    Você ainda poderá gerar um novo token a qualquer momento nas
                    configurações da sua conta.
                  </p>
                </div>
              </div>
              <div className="wlc-footer-direita">
                {/* Botão Configurar projeto */}
                <button
                  className="wlc-btn-regen wlc-btn-regen-outline"
                  onClick={() => setPasso(4)}
                  style={{ marginRight: "8px" }}
                >
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2a6 6 0 1 0 0 12A6 6 0 0 0 8 2zm0 1.5a4.5 4.5 0 1 1 0 9 4.5 4.5 0 0 1 0-9zM7.25 5v3.44l2.15 2.15.9-.9-1.8-1.79V5h-1.25z" fill="currentColor"/></svg>
                  Configurar projeto
                </button>

                {erroLink && <p className="wlc-footer-erro">{erroLink}</p>}
                <button
                  className="wlc-acessar-btn"
                  onClick={handleAcessar}
                  disabled={verificando}
                >
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2 8h9M8 5l4 3-4 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><path d="M6 2a6 6 0 1 0 6 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>
                  {verificando ? "Verificando..." : "Token vinculado - Acessar Dashboard"}
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      {/* CSS adicional (Nexus) — idealmente mova para o .css global */}
      <style>{`
        .wlc-topbar-steps { display: flex; gap: 4px; flex: 1; justify-content: center; }
        .wlc-step-tab { background: none; border: 1px solid transparent; border-radius: 8px;
          padding: 6px 14px; font: inherit; font-size: 14px; cursor: pointer;
          color: var(--ink-dim, #9ca3af); transition: .15s; }
        .wlc-step-tab:hover { color: var(--violet, #a78bfa); }
        .wlc-step-tab.ativo { background: var(--surface2, rgba(255,255,255,.06));
          border-color: var(--violet, #a78bfa); color: var(--violet, #a78bfa); font-weight: 500; }
        .wlc-corpo-unica { display: block; padding: 32px clamp(16px,5vw,60px); }
        .nexus-form-wrap { max-width: 580px; margin: 0 auto; }
        .nexus-form-titulo { font-size: 22px; font-weight: 700; margin: 0 0 6px; }
        .nexus-form-sub { color: var(--ink-dim, #9ca3af); font-size: 14px; margin: 0 0 24px; }
        .nexus-campo { margin-bottom: 18px; }
        .nexus-label { display: block; font-size: 14px; font-weight: 500; margin-bottom: 6px; }
        .nexus-label-opt { font-weight: 400; color: var(--ink-dim, #9ca3af); }
        .nexus-hint { color: var(--ink-dim, #9ca3af); font-size: 13px; margin: 0 0 8px; }
        .nexus-input, .nexus-textarea, .nexus-select {
          width: 100%; padding: 10px 12px; border-radius: 8px; font: inherit; font-size: 14px;
          background: var(--surface, rgba(255,255,255,.04));
          border: 1px solid var(--border, rgba(255,255,255,.1));
          color: inherit; }
        .nexus-textarea { resize: vertical; }
        .nexus-chips { display: flex; flex-wrap: wrap; gap: 8px; }
        .nexus-chip { padding: 6px 14px; border-radius: 999px; font: inherit; font-size: 13px;
          cursor: pointer; background: var(--surface, rgba(255,255,255,.04));
          border: 1px solid var(--border, rgba(255,255,255,.1)); color: inherit; transition: .15s; }
        .nexus-chip-ativo { background: rgba(124,58,237,.15); border-color: var(--violet, #a78bfa);
          color: var(--violet, #a78bfa); font-weight: 500; }
        .nexus-acoes { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 8px; margin-bottom: 32px; }
        .nexus-salvo { padding: 10px 14px; border-radius: 8px; font-size: 14px; margin: 8px 0;
          background: rgba(16,185,129,.1); color: #34d399; border: 1px solid rgba(52,211,153,.2); }
        .nexus-erro { color: #f87171; font-size: 14px; margin: 6px 0; }
        .nexus-gh-secao { border-top: 1px solid var(--border, rgba(255,255,255,.1));
          padding-top: 24px; margin-top: 8px; }
        .nexus-gh-titulo { display: flex; align-items: center; gap: 8px;
          font-size: 16px; font-weight: 600; margin: 0 0 6px; }
      `}</style>
    </>
  );
}
