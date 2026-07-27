import VulnCard from "./VulnCard";
import logoImg from "../assets/logo.png";

const QUANTIDADE_PRIORITARIA = 3;

function calcularRiscoMedio(vulns) {
  if (!vulns.length) return 0;
  const soma = vulns.reduce((acc, v) => acc + (Number(v.score) || 0), 0);
  return (soma / vulns.length).toFixed(1);
}

function calcularTempoTotal(vulns) {
  // 15min por vuln prioritária aprox
  const mins = Math.min(vulns.length, QUANTIDADE_PRIORITARIA) * 15;
  return `~${mins} min`;
}

function nivelRisco(score) {
  if (score >= 8) return { label: "ALTO", classe: "badge-alert" };
  if (score >= 5) return { label: "MÉDIO", classe: "badge-aviso" };
  return { label: "BAIXO", classe: "badge-ecto" };
}

export default function ResultsView({ relatorio }) {
  const vulns = relatorio.vulnerabilidades || [];
  const ordenadas = [...vulns].sort(
    (a, b) => (Number(b.score) || 0) - (Number(a.score) || 0)
  );
  const prioritarias = ordenadas.slice(0, QUANTIDADE_PRIORITARIA);
  const restantes = ordenadas.slice(QUANTIDADE_PRIORITARIA);

  const total = relatorio.total_encontrado ?? vulns.length;
  const riscoMedio = calcularRiscoMedio(vulns);
  const risco = nivelRisco(Number(riscoMedio));
  const tempoTotal = calcularTempoTotal(prioritarias);

  const medium = restantes.filter(v => { const s = Number(v.score)||0; return s >= 5 && s < 8; }).length;
  const low    = restantes.filter(v => (Number(v.score)||0) < 5).length;
  const info   = restantes.filter(v => !v.score).length;

  return (
    <>
      {/* ── Topbar ── */}
      <header className="topbar">
        <div className="topbar-logo">
          <img src={logoImg} alt="PhantomFix" />
        </div>

        <div className="topbar-metricas">
          <div className="metrica-card">
            <div className="metrica-valor">{total}</div>
            <div className="metrica-rotulo">encontradas</div>
          </div>

          <div className="metrica-card destaque-alert">
            <div className="metrica-valor">
              {prioritarias.length}
              <span className="badge-alert">⚠</span>
            </div>
            <div className="metrica-rotulo">prioritárias</div>
          </div>

          <div className="metrica-card destaque-aviso">
            <div className="metrica-valor">
              <span className={risco.classe}>{risco.label}</span>
              <span style={{ fontSize: 14, color: "var(--ink-dim)" }}>({riscoMedio})</span>
            </div>
            <div className="metrica-rotulo">risco médio</div>
          </div>

          <div className="metrica-card destaque-ecto">
            <div className="metrica-valor">
              <span className="badge-ecto">⏱</span>
              {tempoTotal}
            </div>
            <div className="metrica-rotulo">est. correção</div>
          </div>
        </div>
      </header>

      {/* ── Main content ── */}
      <main className="main-content">
        {relatorio.repositorio && (
          <div className="repo-bar">
            <span>Repositório: <strong>{relatorio.repositorio}</strong></span>
            {relatorio.protocolo && (
              <span>Protocolo: <strong>{relatorio.protocolo}</strong></span>
            )}
          </div>
        )}

        <div className="prioridade-hero">
          <span className="prioridade-label">Sua prioridade agora.</span>
          <h2 className="prioridade-titulo">
            Corrija apenas estas {prioritarias.length} vulnerabilidades
          </h2>
        </div>

        <div className="lista-prioritarias">
          {prioritarias.map((v, i) => (
            <VulnCard key={v.id || i} vuln={v} posicao={i + 1} />
          ))}
        </div>

        {restantes.length > 0 && (
          <details className="lista-restantes">
            <summary className="lista-restantes-summary">
              ▶ Outras {restantes.length} não são prioridade agora
              <div className="lista-restantes-badges">
                {medium > 0 && <span className="badge-nivel medium">medium: {medium}</span>}
                {low    > 0 && <span className="badge-nivel low">low: {low}</span>}
                {info   > 0 && <span className="badge-nivel info">info: {info}</span>}
              </div>
            </summary>
            <div className="lista-restantes-corpo">
              {restantes.map((v, i) => (
                <VulnCard
                  key={v.id || i}
                  vuln={v}
                  posicao={QUANTIDADE_PRIORITARIA + i + 1}
                  compacto
                />
              ))}
            </div>
          </details>
        )}
      </main>
    </>
  );
}
