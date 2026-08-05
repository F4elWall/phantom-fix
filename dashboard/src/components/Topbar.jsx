import logoImg from "../assets/logo.png";

function formatarData(iso) {
  if (!iso) return null;
  return new Date(iso).toLocaleString("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
    timeZone: "America/Sao_Paulo",
  });
}

/**
 * scanState: null | { tipo: "concluido" } | { tipo: "rodando", protocolo, repositorio? }
 */
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

  return (
    <header className="topbar">
      <div className="topbar-logo">
        <img src={logoImg} alt="PhantomFix" />
        <span className="topbar-logo-name">PhantomFix</span>
      </div>

      <div className="topbar-info">
        {repositorio && (
          <div className="topbar-chip">
            <span className="topbar-chip-icon">⌗</span>
            <span>
              repo: <strong>{repositorio}</strong>
            </span>
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
            rodando ? "scan-rodando" : "scan-concluido"
          }`}
          onClick={() => {
            if (rodando && onAbrirPipeline) onAbrirPipeline(scanState.protocolo);
          }}
          title={rodando ? "Abrir Pipeline View" : "Nenhum scan em andamento"}
        >
          <span className={`scan-dot ${rodando ? "pulse" : ""}`} />
          {rodando ? "Rodando novo scan" : "Scan concluído"}
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
        <div className="topbar-user">{localStorage.getItem("user_nome") || "Usuário"} ▾</div>
        <button
          type="button"
          className={`btn-spirit-toggle ${spiritAberto ? "ativo" : ""}`}
          onClick={onToggleSpirit}
        >
          ✦ SPIRIT AI
          <span className={`spirit-dot ${spiritAberto ? "on" : ""}`} />
        </button>
        {onSair && (
          <button type="button" className="btn-sair" onClick={onSair}>
            Sair
          </button>
        )}
      </div>
    </header>
  );
}
