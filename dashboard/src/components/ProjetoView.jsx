{/*# PhantomFix — Copyright (C) 2025–2026 Rafael Pedro, Bernardo Coroa,
   # Giovanna Esmelardi, Gustavo Enrique
   # SPDX-License-Identifier: GPL-3.0-or-later
   # Licenciado sob a GNU GPL v3. Veja LICENSE.md na raiz do repositório.*/}

import { useEffect, useState } from "react";
import { buscarProjeto, salvarProjeto, scanGithub } from "../api";
import Topbar from "./Topbar";

const OPT = {
  stack:  ["JavaScript/TS", "Python", "Java", "Go", "Docker", "Terraform", "Kubernetes", "API REST/GraphQL"],
  sens:   ["Dados pessoais", "Credenciais", "Pagamento", "Saúde"],
  comp:   ["LGPD", "ISO 27001", "NIST CSF", "PCI DSS"],
  env:    ["Internet pública", "Rede interna", "Somente local"],
  stage:  ["Protótipo", "MVP", "Produção"],
};

function Chips({ campo, valores, onChange }) {
  return (
    <div className="nexus-chips">
      {OPT[campo].map((v) => (
        <button
          key={v}
          type="button"
          className={`nexus-chip${valores.includes(v) ? " nexus-chip-ativo" : ""}`}
          onClick={() =>
            onChange(campo, valores.includes(v) ? valores.filter((x) => x !== v) : [...valores, v])
          }
        >
          {v}
        </button>
      ))}
    </div>
  );
}

function Select({ campo, valor, onChange }) {
  return (
    <select
      className="nexus-select"
      value={valor}
      onChange={(e) => onChange(campo, e.target.value)}
    >
      <option value="">Selecione…</option>
      {OPT[campo].map((v) => (
        <option key={v} value={v}>{v}</option>
      ))}
    </select>
  );
}

const FORM_VAZIO = {
  nome: "", stack: [], env: "", url: "", stage: "", sens: [], comp: [], objetivo: "",
};

export default function ProjetoView({
  scanState,
  spiritAberto,
  onToggleSpirit,
  onVerHistorico,
  onAbrirPipeline,
  onSair,
  onVoltar,
}) {
  const [carregando, setCarregando] = useState(true);
  const [temProjeto, setTemProjeto] = useState(false);
  const [form, setForm] = useState(FORM_VAZIO);

  const [salvando, setSalvando] = useState(false);
  const [salvo,    setSalvo]    = useState(false);
  const [erro,     setErro]     = useState("");

  const [ghUrl,    setGhUrl]    = useState("");
  const [ghToken,  setGhToken]  = useState("");
  const [scanando, setScanando] = useState(false);
  const [erroScan, setErroScan] = useState("");

  useEffect(() => {
    buscarProjeto()
      .then((p) => {
        if (p) {
          setTemProjeto(true);
          setForm({
            nome:    p.nome    || "",
            stack:   p.stack   ? p.stack.split(",").map((s) => s.trim()).filter(Boolean) : [],
            env:     p.ambiente || "",
            url:     p.zap_url  || "",
            stage:   p.estagio  || "",
            sens:    p.dados_sensiveis ? p.dados_sensiveis.split(",").map((s) => s.trim()).filter(Boolean) : [],
            comp:    p.compliance      ? p.compliance.split(",").map((s) => s.trim()).filter(Boolean) : [],
            objetivo: p.objetivo || "",
          });
        }
      })
      .catch(() => {})
      .finally(() => setCarregando(false));
  }, []);

  function handleChange(campo, valor) {
    setSalvo(false);
    setForm((f) => ({ ...f, [campo]: valor }));
  }

  async function handleSalvar() {
    setErro("");
    if (!form.nome.trim()) { setErro("Nome do projeto é obrigatório."); return; }
    setSalvando(true);
    try {
      await salvarProjeto({
        nome:            form.nome.trim(),
        stack:           form.stack.join(", ")  || null,
        ambiente:        form.env               || null,
        dados_sensiveis: form.sens.join(", ")   || null,
        compliance:      form.comp.join(", ")   || null,
        estagio:         form.stage             || null,
        objetivo:        form.objetivo.trim()   || null,
        zap_url:         form.url.trim()        || null,
      });
      setTemProjeto(true);
      setSalvo(true);
      setTimeout(() => { onVoltar?.(); }, 1000);
    } catch (e) {
      setErro(e.message || "Erro ao salvar. Tente novamente.");
    } finally {
      setSalvando(false);
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
      const clientToken = localStorage.getItem("user_token") || "";
      const data = await scanGithub({ githubToken: ghToken.trim(), repositorio: ghUrl.trim(), clientToken });
      onAbrirPipeline?.(data?.protocolo);
    } catch (e) {
      setErroScan(e.message || "Erro ao iniciar scan.");
    } finally {
      setScanando(false);
    }
  }

  return (
    <>
      <style>{`
        .projeto-page { flex: 1; min-width: 0; display: flex; flex-direction: column; min-height: 100vh; }
        .projeto-main { padding: 28px 40px 60px; max-width: 640px; display: flex; flex-direction: column; gap: 0; }
        .projeto-header { margin-bottom: 6px; }
        .projeto-titulo { font-size: 22px; font-weight: 700; margin: 0 0 4px; }
        .projeto-sub { color: var(--ink-dim, #9ca3af); font-size: 14px; margin: 0 0 28px; }
        .projeto-secao-titulo { font-size: 16px; font-weight: 600; margin: 32px 0 16px;
          padding-top: 24px; border-top: 1px solid var(--border, rgba(255,255,255,.1)); display: flex; align-items: center; gap: 8px; }
        .projeto-acoes { display: flex; gap: 10px; align-items: center; margin-top: 8px; }
        .nexus-form-wrap { width: 100%; }
        .nexus-campo { margin-bottom: 18px; }
        .nexus-label { display: block; font-size: 14px; font-weight: 500; margin-bottom: 6px; }
        .nexus-label-opt { font-weight: 400; color: var(--ink-dim, #9ca3af); }
        .nexus-hint { color: var(--ink-dim, #9ca3af); font-size: 13px; margin: 0 0 8px; }
        .nexus-input, .nexus-textarea, .nexus-select {
          width: 100%; padding: 10px 12px; border-radius: 8px; font: inherit; font-size: 14px;
          background: var(--surface, rgba(255,255,255,.04));
          border: 1px solid var(--border, rgba(255,255,255,.1)); color: inherit; box-sizing: border-box; }
        .nexus-textarea { resize: vertical; }
        .nexus-chips { display: flex; flex-wrap: wrap; gap: 8px; }
        .nexus-chip { padding: 6px 14px; border-radius: 999px; font: inherit; font-size: 13px;
          cursor: pointer; background: var(--surface, rgba(255,255,255,.04));
          border: 1px solid var(--border, rgba(255,255,255,.1)); color: inherit; transition: .15s; }
        .nexus-chip-ativo { background: rgba(124,58,237,.15); border-color: var(--violet, #a78bfa);
          color: var(--violet, #a78bfa); font-weight: 500; }
        .nexus-salvo { padding: 10px 14px; border-radius: 8px; font-size: 14px; margin: 0;
          background: rgba(16,185,129,.1); color: #34d399; border: 1px solid rgba(52,211,153,.2); }
        .nexus-erro { color: #f87171; font-size: 14px; margin: 6px 0; }
      `}</style>

      <div className="projeto-page">
        <Topbar
          repositorio={null}
          processadoEm={null}
          scanState={scanState}
          spiritAberto={spiritAberto}
          onToggleSpirit={onToggleSpirit}
          onVerHistorico={onVerHistorico}
          onAbrirPipeline={onAbrirPipeline}
          onSair={onSair}
        />

        <main className="projeto-main">
          {carregando ? (
            <p style={{ color: "var(--ink-dim, #9ca3af)", marginTop: 40 }}>Carregando…</p>
          ) : (
            <>
              <div className="projeto-header">
                <h1 className="projeto-titulo">
                  {temProjeto ? "Meu projeto" : "Criar projeto"}
                </h1>
                <p className="projeto-sub">
                  {temProjeto
                    ? "Atualize o contexto do seu projeto. O pipeline usa essas informações para priorizar as vulnerabilidades."
                    : "Preencha o contexto do seu projeto para que o pipeline saiba o que priorizar."}
                </p>
              </div>

              {/* ── Formulário ─────────────────────────────────────────── */}
              <div className="nexus-form-wrap">
                <div className="nexus-campo">
                  <label className="nexus-label">Nome do projeto</label>
                  <input
                    className="nexus-input"
                    type="text"
                    value={form.nome}
                    onChange={(e) => handleChange("nome", e.target.value)}
                    placeholder="Ex.: Portal de pedidos"
                    autoFocus
                  />
                </div>

                <div className="nexus-campo">
                  <label className="nexus-label">Stack</label>
                  <p className="nexus-hint">Marque tudo o que o projeto usa.</p>
                  <Chips campo="stack" valores={form.stack} onChange={handleChange} />
                </div>

                <div className="nexus-campo">
                  <label className="nexus-label">Ambiente</label>
                  <Select campo="env" valor={form.env} onChange={handleChange} />
                </div>

                {form.env === "Internet pública" && (
                  <div className="nexus-campo">
                    <label className="nexus-label">
                      URL para scan DAST{" "}
                      <span className="nexus-label-opt">(opcional)</span>
                    </label>
                    <input
                      className="nexus-input"
                      type="url"
                      value={form.url}
                      onChange={(e) => handleChange("url", e.target.value)}
                      placeholder="https://meuapp.com"
                    />
                    <p className="nexus-hint">Deixe em branco para pular o scan DAST.</p>
                  </div>
                )}

                <div className="nexus-campo">
                  <label className="nexus-label">Estágio</label>
                  <Select campo="stage" valor={form.stage} onChange={handleChange} />
                </div>

                <div className="nexus-campo">
                  <label className="nexus-label">Dados sensíveis</label>
                  <p className="nexus-hint">O que o sistema guarda ou processa?</p>
                  <Chips campo="sens" valores={form.sens} onChange={handleChange} />
                </div>

                <div className="nexus-campo">
                  <label className="nexus-label">Conformidade exigida</label>
                  <Chips campo="comp" valores={form.comp} onChange={handleChange} />
                </div>

                <div className="nexus-campo">
                  <label className="nexus-label">
                    Objetivo da análise{" "}
                    <span className="nexus-label-opt">(opcional)</span>
                  </label>
                  <textarea
                    className="nexus-textarea"
                    rows={3}
                    value={form.objetivo}
                    onChange={(e) => handleChange("objetivo", e.target.value)}
                    placeholder="Ex.: Validar conformidade com a LGPD antes do lançamento."
                  />
                </div>

                {erro && <p className="nexus-erro">{erro}</p>}

                <div className="projeto-acoes">
                  <button className="wlc-acessar-btn" onClick={handleSalvar} disabled={salvando}>
                    {salvando ? "Salvando…" : temProjeto ? "Salvar alterações" : "Criar projeto"}
                  </button>
                  <button
                    type="button"
                    className="topbar-chip topbar-chip-btn"
                    onClick={onVoltar}
                    style={{ padding: "10px 18px" }}
                  >
                    Cancelar
                  </button>
                  {salvo && <span className="nexus-salvo">✓ Salvo!</span>}
                </div>
              </div>

              {/* ── Análise via GitHub ──────────────────────────────────── */}
              <h2 className="projeto-secao-titulo">
                <svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/>
                </svg>
                Analisar via GitHub
              </h2>

              <p className="nexus-hint" style={{ marginBottom: 16 }}>
                Use um token fine-grained com permissão de leitura. O Core clona o repositório
                e inicia a análise automaticamente com o contexto do projeto acima.
              </p>

              <div className="nexus-campo">
                <label className="nexus-label">URL do repositório</label>
                <input
                  className="nexus-input"
                  type="url"
                  value={ghUrl}
                  onChange={(e) => setGhUrl(e.target.value)}
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
                  onChange={(e) => setGhToken(e.target.value)}
                  placeholder="ghp_ ou github_pat_..."
                />
              </div>

              {erroScan && <p className="nexus-erro">{erroScan}</p>}

              <button
                className="wlc-acessar-btn"
                onClick={handleScanGithub}
                disabled={scanando}
                style={{ marginTop: 4 }}
              >
                {scanando ? "Iniciando…" : "Iniciar análise"}
              </button>
            </>
          )}
        </main>
      </div>
    </>
  );
}
