import { useState, useRef, useEffect } from "react";
import logoImg from "../assets/logo.png";
import { regenToken, scanGithub } from "../api";
// --- [MODIFICAÇÃO]: Importado hook do tema ---
import { useTheme } from "../App";

function formatarData(iso) {
  if (!iso) return null;
  return new Date(iso).toLocaleString("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
    timeZone: "America/Sao_Paulo",
  });
}

function TokenPopup({ token, onFechar }) {
  const [copiado, setCopiado] = useState(false);

  async function copiar() {
    await navigator.clipboard.writeText(`pf_${token}`);
    setCopiado(true);
    setTimeout(() => setCopiado(false), 2000);
  }

  return (
    <div className="wlc-overlay" onClick={onFechar}>
      <div className="wlc-popup" onClick={(e) => e.stopPropagation()}>
        <button className="wlc-popup-close" onClick={onFechar}>✕</button>

        <div className="wlc-popup-avatar">
          <img src={logoImg} alt="PhantomFix" />
          <span className="wlc-popup-star">✦</span>
        </div>

        <h2 className="wlc-popup-titulo">Seu novo token</h2>
        <p className="wlc-popup-sub">
          Este token substitui o anterior.<br />
          Guarde-o e vincule no Client.
        </p>

        <div className="wlc-token-row">
          <code className="wlc-token-code">pf_{token}</code>
          <button className="wlc-token-copy" onClick={copiar} title="Copiar">
            {copiado ? (
              <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><path d="M3 9l4 4 8-8" stroke="var(--ecto)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
            ) : (
              <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><rect x="6" y="6" width="9" height="9" rx="2" stroke="currentColor" strokeWidth="1.5"/><path d="M3 12V3h9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>
            )}
          </button>
        </div>

        <div className="wlc-aviso-box">
          <span className="wlc-aviso-icon">⚠</span>
          <div>
            <p className="wlc-aviso-titulo">Token anterior foi invalidado.</p>
            <p className="wlc-aviso-desc">Vincule este novo token no Client para continuar enviando análises.</p>
          </div>
        </div>

        <button className="wlc-btn-regen" onClick={onFechar}>
          Entendido
        </button>
      </div>
    </div>
  );
}

function GitCloneModal({ onFechar, onScanIniciado }) {
  const [ghUrl,    setGhUrl]    = useState("");
  const [ghToken,  setGhToken]  = useState("");
  const [scanando, setScanando] = useState(false);
  const [erro,     setErro]     = useState("");

  async function handleSubmit() {
    setErro("");
    if (!ghUrl.trim() || !ghToken.trim()) {
      setErro("Preencha a URL do repositório e o token GitHub.");
      return;
    }
    setScanando(true);
    try {
      const clientToken = localStorage.getItem("user_token") || "";
      const data = await scanGithub({
        githubToken: ghToken.trim(),
        repositorio: ghUrl.trim(),
        clientToken,
      });
      onScanIniciado?.(data?.protocolo);
      onFechar();
    } catch (e) {
      setErro(e.message || "Erro ao iniciar scan. Tente novamente.");
    } finally {
      setScanando(false);
    }
  }

  return (
    <div className="wlc-overlay" onClick={onFechar}>
      <div className="wlc-popup" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 420 }}>
        <button className="wlc-popup-close" onClick={onFechar}>✕</button>

        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
          <svg width="22" height="22" viewBox="0 0 16 16" fill="currentColor" style={{ color: "var(--ecto)" }}>
            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/>
          </svg>
          <h2 className="wlc-popup-titulo" style={{ margin: 0 }}>Nova análise via GitHub</h2>
        </div>
        <p className="wlc-popup-sub" style={{ marginBottom: 20 }}>
          Use um token fine-grained com permissão de leitura.<br />
          O Core clona o repositório e inicia a análise automaticamente.
        </p>

        <div className="nexus-campo" style={{ marginBottom: 12 }}>
          <label className="nexus-label">URL do repositório</label>
          <input
            className="nexus-input"
            type="url"
            value={ghUrl}
            onChange={(e) => setGhUrl(e.target.value)}
            placeholder="https://github.com/org/repositorio"
            autoFocus
          />
        </div>

        <div className="nexus-campo" style={{ marginBottom: 16 }}>
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

        {erro && <p className="nexus-erro" style={{ marginBottom: 12 }}>{erro}</p>}

        <button
          className="wlc-acessar-btn"
          onClick={handleSubmit}
          disabled={scanando}
          style={{ width: "100%" }}
        >
          {scanando ? "Iniciando…" : "Iniciar análise"}
        </button>
      </div>
    </div>
  );
}

export default function Topbar({
  repositorio,
  processadoEm,
  scanState,
  spiritAberto,
  onToggleSpirit,
  onVerHistorico,
  onAbrirPipeline,
  onSair,
}) {
  const rodando = scanState?.tipo === "rodando";
  const relatorioExecutivoNaoLido = scanState?.relatorioExecutivoNaoLido ?? false;
  const [dropdownAberto, setDropdownAberto] = useState(false);
  const [gitCloneAberto, setGitCloneAberto] = useState(false);
  const [novoToken, setNovoToken] = useState(null);
  const [regenando, setRegenando] = useState(false);
  const dropdownRef = useRef(null);

  // --- [MODIFICAÇÃO]: Uso do hook de tema ---
  const { tema, toggleTema } = useTheme();

  const TEMA_LABEL = {
  neon:  "◈ Neon",
  dark:  "◉ Dark",
  light: "○ Light",
  };

  // Fecha dropdown ao clicar fora
  useEffect(() => {
    function handleClick(e) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setDropdownAberto(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  async function handleRegenToken() {
    setDropdownAberto(false);
    setRegenando(true);
    try {
      const dados = await regenToken();
      localStorage.setItem("user_token", dados.token);
      localStorage.setItem("client_linked", "false");
      setNovoToken(dados.token);
    } catch {
      alert("Erro ao gerar novo token. Tente novamente.");
    } finally {
      setRegenando(false);
    }
  }

  return (
    <>
      {novoToken && (
        <TokenPopup token={novoToken} onFechar={() => setNovoToken(null)} />
      )}

      {gitCloneAberto && (
        <GitCloneModal
          onFechar={() => setGitCloneAberto(false)}
          onScanIniciado={(protocolo) => {
            if (protocolo && onAbrirPipeline) onAbrirPipeline(protocolo);
          }}
        />
      )}

      <header className="topbar">
        <div className="topbar-logo">
          <img src={logoImg} alt="PhantomFix" />
          <span className="topbar-logo-name">PhantomFix</span>
        </div>

        <div className="topbar-info">
          {repositorio && (
            <div className="topbar-chip">
              <span className="topbar-chip-icon">⌗</span>
              <span>repo: <strong>{repositorio}</strong></span>
            </div>
          )}
          {processadoEm && (
            <div className="topbar-chip">
              <span className="topbar-chip-icon">📅</span>
              <span>{formatarData(processadoEm)}</span>
            </div>
          )}

          <button
            type="button"
            className={`topbar-chip topbar-chip-btn topbar-scan-status ${
              rodando ? "scan-rodando" : relatorioExecutivoNaoLido ? "scan-novo-relatorio" : "scan-concluido"
            }`}
            onClick={() => {
              if (rodando && onAbrirPipeline) onAbrirPipeline(scanState.protocolo);
            }}
            title={
              rodando
                ? "Abrir Pipeline View"
                : relatorioExecutivoNaoLido
                ? "Novo relatório executivo disponível"
                : "Nenhum scan em andamento"
            }
          >
            <span className={`scan-dot ${rodando ? "pulse" : relatorioExecutivoNaoLido ? "pulse" : ""}`} />
            {rodando
              ? "Rodando novo scan"
              : relatorioExecutivoNaoLido
              ? "Novo relatório disponível"
              : "Scan concluído"}
          </button>

          {onVerHistorico && (
            <button
              type="button"
              className="topbar-chip topbar-chip-btn"
              onClick={onVerHistorico}
            >
              Ver histórico de scans
            </button>
          )}

          <button
            type="button"
            className="topbar-chip topbar-chip-btn"
            onClick={() => setGitCloneAberto(true)}
            title="Analisar novo repositório via GitHub"
            disabled={rodando}
          >
            <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor" style={{ flexShrink: 0 }}>
              <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/>
            </svg>
            Nova análise
          </button>
        </div>

        <div className="topbar-actions">
          {/* Dropdown de perfil */}
          <div className="topbar-perfil" ref={dropdownRef}>
            <button
              type="button"
              className="topbar-user"
              onClick={() => setDropdownAberto((v) => !v)}
            >
              {localStorage.getItem("user_nome") || "Usuário"} ▾
            </button>

            {dropdownAberto && (
              <div className="topbar-dropdown">
                {/* --- [MODIFICAÇÃO]: Botão para alternar tema --- */}
                <button
                  className="topbar-dropdown-item"
                  onClick={() => { setDropdownAberto(false); toggleTema(); }}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
                  {tema === "dark" ? "Modo Claro" : "Modo Escuro"}
                </button>
                <div className="topbar-dropdown-sep" />
                <button
                  className="topbar-dropdown-item"
                  onClick={handleRegenToken}
                  disabled={regenando}
                >
                  <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M2 8a6 6 0 1 0 1.5-3.9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/><path d="M2 4v4h4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  {regenando ? "Gerando..." : "Gerar novo token"}
                </button>
                <div className="topbar-dropdown-sep" />
                <button
                  className="topbar-dropdown-item topbar-dropdown-sair"
                  onClick={() => { setDropdownAberto(false); onSair?.(); }}
                >
                  <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M6 2H3a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/><path d="M10 11l3-3-3-3M13 8H6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  Sair
                </button>
              </div>
            )}
          </div>

          <button
            type="button"
            className={`btn-spirit-toggle ${spiritAberto ? "ativo" : ""}`}
            onClick={onToggleSpirit}
          >
            ✦ SPIRIT AI
            <span className={`spirit-dot ${spiritAberto ? "on" : ""}`} />
          </button>
        </div>
      </header>
    </>
  );
}
