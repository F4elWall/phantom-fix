import { useState } from "react";
import VulnCard from "./VulnCard";
import logoImg from "../assets/logo.png";

const QUANTIDADE_PRIORITARIA = 4;
const VULNS_POR_PAGINA = 6;

// ── Severidade ────────────────────────────────────────────────────────────────
function severidade(score) {
  const s = Number(score) || 0;
  if (s >= 9)   return { label: "Crítica", classe: "critica" };
  if (s >= 7)   return { label: "Alta",    classe: "alta"    };
  if (s >= 4)   return { label: "Média",   classe: "media"   };
  return              { label: "Baixa",   classe: "baixa"   };
}

function calcularScoreMedio(vulns) {
  if (!vulns.length) return 0;
  const soma = vulns.reduce((acc, v) => acc + (Number(v.score) || 0), 0);
  return (soma / vulns.length).toFixed(1);
}

function labelScore(score) {
  const s = Number(score);
  if (s >= 8) return "Muito arriscado";
  if (s >= 6) return "Arriscado";
  if (s >= 4) return "Moderado";
  return "Sob controle";
}

function formatarData(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
    timeZone: "America/Sao_Paulo"
  });
}

// ── Linha da lista ─────────────────────────────────────────────────────────────
function VulnLinha({ vuln }) {
  const [aberto, setAberto] = useState(false);
  const sev = severidade(vuln.score);
  const arquivo = vuln.arquivo || "—";
  const arquivoDisplay = arquivo.length > 32 ? "…" + arquivo.slice(-29) : arquivo;
  const tipo = (vuln.tipo || "desconhecido").replace(/^CWE-\d+\s*/i, "");
  const temCorrecao = Boolean(vuln.correcao) &&
    vuln.correcao !== "Ghost não disponível" &&
    vuln.correcao !== "Correção indisponível";

  return (
    <>


<div className={`vuln-linha ${aberto ? "aberta" : ""}`} onClick={() => setAberto(!aberto)}>
  <span className={`vuln-linha-sev sev-${sev.classe}`}>
    <span className={`vuln-linha-dot sev-${sev.classe}`} />
    {sev.label}
  </span>
  <span className="vuln-linha-tipo">{tipo}</span>
  <span className="vuln-linha-arquivo">{arquivoDisplay}</span>
  {vuln.linha && <span className="vuln-linha-linha">L{vuln.linha}</span>}
  <span className={`vuln-linha-chevron ${aberto ? "aberto" : ""}`}>›</span>
</div>


      {aberto && (
        <div className="vuln-linha-detalhe">
          {vuln.justificativa && (
            <div className="vuln-detalhe-secao">
              <h4>Por que isso importa?</h4>
              <p>{vuln.justificativa}</p>
            </div>
          )}
          {temCorrecao ? (
            <div className="vuln-detalhe-secao">
              <h4>Correção sugerida (Ghost)</h4>
              <pre className="vuln-detalhe-codigo">{vuln.correcao}</pre>
            </div>
          ) : (
            <div className="vuln-detalhe-secao">
              <h4>Correção sugerida</h4>
              <p className="vuln-detalhe-sem-correcao">Ghost não gerou correção para esta vulnerabilidade.</p>
            </div>
          )}
        </div>
      )}
    </>
  );
}

// ── ResultsView ────────────────────────────────────────────────────────────────
export default function ResultsView({ relatorio, onVerHistorico, onSair }) {
  const [tabAtiva, setTabAtiva] = useState("todas");
  const [pagina, setPagina] = useState(1);

  const vulns = relatorio.vulnerabilidades || [];
  const ordenadas = [...vulns].sort(
    (a, b) => (Number(b.score) || 0) - (Number(a.score) || 0)
  );
  const prioritarias = ordenadas.slice(0, QUANTIDADE_PRIORITARIA);

  const scoreMedio = calcularScoreMedio(vulns);
  const total = relatorio.total_encontrado ?? vulns.length;

  const criticas = ordenadas.filter(v => Number(v.score) >= 9);
  const altas    = ordenadas.filter(v => { const s = Number(v.score); return s >= 7 && s < 9; });
  const medias   = ordenadas.filter(v => { const s = Number(v.score); return s >= 4 && s < 7; });
  const baixas   = ordenadas.filter(v => Number(v.score) < 4);

  const mapaTab = {
    todas:    ordenadas,
    criticas,
    altas,
    medias,
    baixas,
  };

  const vulnsFiltradas = mapaTab[tabAtiva] || ordenadas;
  const totalPaginas   = Math.ceil(vulnsFiltradas.length / VULNS_POR_PAGINA);
  const vulnsPagina    = vulnsFiltradas.slice(
    (pagina - 1) * VULNS_POR_PAGINA,
    pagina * VULNS_POR_PAGINA
  );

  function mudarTab(tab) {
    setTabAtiva(tab);
    setPagina(1);
  }

  // Paginação: mostra no máx 7 botões com "..."
  function paginacaoBotoes() {
    if (totalPaginas <= 7) return Array.from({ length: totalPaginas }, (_, i) => i + 1);
    const btns = [];
    btns.push(1);
    if (pagina > 3) btns.push("...");
    for (let i = Math.max(2, pagina - 1); i <= Math.min(totalPaginas - 1, pagina + 1); i++) {
      btns.push(i);
    }
    if (pagina < totalPaginas - 2) btns.push("...");
    btns.push(totalPaginas);
    return btns;
  }

  return (
    <>
      {/* ── Topbar ── */}
      <header className="topbar">
        <div className="topbar-logo">
          <img src={logoImg} alt="PhantomFix" />
          <span className="topbar-logo-name">PhantomFix</span>
        </div>

        <div className="topbar-info">
          {relatorio.repositorio && (
            <div className="topbar-chip">
              <span className="topbar-chip-icon">⌗</span>
              <span>repo: <strong>{relatorio.repositorio}</strong></span>
            </div>
          )}
          {relatorio.processado_em && (
            <div className="topbar-chip">
              <span className="topbar-chip-icon">📅</span>
              <span>{formatarData(relatorio.processado_em)}</span>
            </div>
          )}
          {onVerHistorico && (
            <button className="topbar-chip topbar-chip-btn" onClick={onVerHistorico}>
              Ver outros scans ⌄
            </button>
          )}
        </div>

        <div className="topbar-actions">
          {onSair && (
            <button className="btn-sair" onClick={onSair}>Sair</button>
          )}
        </div>
      </header>

      {/* ── Main ── */}
      <main className="main-content">

        {/* ── 2 cards de métricas ── */}
        <div className="metricas-grid">
          <div className="metrica-grande">
            <div className="metrica-grande-header">
              <span className="metrica-grande-icone">🛡️</span>
              <span className="metrica-grande-titulo">Score de Segurança</span>
            </div>
            <div className="metrica-grande-valor">
              {scoreMedio}
              <span className="metrica-grande-max"> / 10</span>
            </div>
            <div className="metrica-grande-barra">
              <div
                className="metrica-grande-barra-fill"
                style={{ width: `${(scoreMedio / 10) * 100}%` }}
              />
            </div>
            <div className="metrica-grande-label">{labelScore(scoreMedio)}</div>
          </div>

          <div className="metrica-grande">
            <div className="metrica-grande-header">
              <span className="metrica-grande-icone">⚠️</span>
              <span className="metrica-grande-titulo">Vulnerabilidades</span>
            </div>
            <div className="metrica-grande-valor">{total}</div>
            <div className="metrica-grande-label">Encontradas neste scan</div>
            <div className="metrica-dist">
              {criticas.length > 0 && <span className="dist-chip critica">{criticas.length} críticas</span>}
              {altas.length    > 0 && <span className="dist-chip alta">{altas.length} altas</span>}
              {medias.length   > 0 && <span className="dist-chip media">{medias.length} médias</span>}
              {baixas.length   > 0 && <span className="dist-chip baixa">{baixas.length} baixas</span>}
            </div>
          </div>
        </div>

        {/* ── Prioritárias ── */}
        <div className="prioridade-hero">
          <span className="prioridade-label">⭐ Sua prioridade agora</span>
          <h2 className="prioridade-titulo">
            Corrija estas {prioritarias.length} vulnerabilidades primeiro
          </h2>
        </div>

        <div className="lista-prioritarias">
          {prioritarias.map((v, i) => (
            <VulnCard key={v.id || i} vuln={v} posicao={i + 1} />
          ))}
        </div>

        {/* ── Lista completa ── */}
        <div className="lista-completa">
          <div className="lista-tabs">
            {[
              { key: "todas",    label: `Todas (${ordenadas.length})` },
              { key: "criticas", label: `Críticas (${criticas.length})` },
              { key: "altas",    label: `Altas (${altas.length})` },
              { key: "medias",   label: `Médias (${medias.length})` },
              { key: "baixas",   label: `Baixas (${baixas.length})` },
            ].map(t => (
              <button
                key={t.key}
                className={`lista-tab ${tabAtiva === t.key ? "ativa" : ""} tab-${t.key}`}
                onClick={() => mudarTab(t.key)}
              >
                {t.label}
              </button>
            ))}
            <span className="lista-mostrando">
              Mostrando {(pagina - 1) * VULNS_POR_PAGINA + 1}–{Math.min(pagina * VULNS_POR_PAGINA, vulnsFiltradas.length)} de {vulnsFiltradas.length} vulnerabilidades
            </span>
          </div>

          <div className="lista-header-linha">
            <span>Severidade</span>
            <span>Vulnerabilidade</span>
            <span>Arquivo</span>
            <span>Linha</span>
            <span />
          </div>

          <div className="lista-corpo">
            {vulnsPagina.length === 0 && (
              <p className="lista-vazia">Nenhuma vulnerabilidade nesta categoria.</p>
            )}
            {vulnsPagina.map((v, i) => (
              <VulnLinha key={v.id || i} vuln={v} />
            ))}
          </div>

          {totalPaginas > 1 && (
            <div className="paginacao">
              <button
                className="paginacao-btn"
                onClick={() => setPagina(p => Math.max(1, p - 1))}
                disabled={pagina === 1}
              >‹</button>

              {paginacaoBotoes().map((b, i) =>
                b === "..." ? (
                  <span key={i} className="paginacao-dots">…</span>
                ) : (
                  <button
                    key={i}
                    className={`paginacao-btn ${pagina === b ? "ativa" : ""}`}
                    onClick={() => setPagina(b)}
                  >{b}</button>
                )
              )}

              <button
                className="paginacao-btn"
                onClick={() => setPagina(p => Math.min(totalPaginas, p + 1))}
                disabled={pagina === totalPaginas}
              >›</button>
            </div>
          )}
        </div>
      </main>
    </>
  );
}
