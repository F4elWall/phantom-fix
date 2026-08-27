import { useState, useRef, useEffect } from "react";
import logoImg from "../assets/logo.png";
import { regenToken } from "../api";

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
  const [novoToken, setNovoToken] = useState(null);
  const [regenando, setRegenando] = useState(false);
  const dropdownRef = useRef(null);

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
