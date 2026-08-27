import { useState } from "react";
import logo from "../assets/logo.png";
import { marcarRelatorioLido } from "../api";

function formatarData(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("pt-BR", {
    dateStyle: "long",
    timeStyle: "short",
    timeZone: "America/Sao_Paulo",
  });
}

function gerarPDF(relatorio) {
  const conteudo = `RELATÓRIO EXECUTIVO — PhantomFix
===============================
Repositório: ${relatorio.repositorio || "—"}
Gerado em: ${formatarData(relatorio.gerado_em)}

${relatorio.texto || "Conteúdo não disponível."}
`;

  const blob = new Blob([conteudo], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `relatorio-executivo-${relatorio.protocolo || "phantomfix"}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function RelatorioExecutivoView({ relatorio, onAcessarDashboard }) {
  const [baixando, setBaixando] = useState(false);
  const [acessando, setAcessando] = useState(false);

  async function handleBaixar() {
    setBaixando(true);
    try {
      gerarPDF(relatorio);
    } finally {
      setBaixando(false);
    }
  }

  async function handleAcessar() {
    setAcessando(true);
    try {
      await marcarRelatorioLido(relatorio.protocolo);
    } catch {
      /* se falhar, segue mesmo assim */
    } finally {
      setAcessando(false);
      onAcessarDashboard?.();
    }
  }

  const secoes = parsearSecoes(relatorio.texto || "");

  return (
    <div className="exec-page">
      {/* ── Topbar mínima ── */}
      <header className="exec-topbar">
        <div className="exec-topbar-logo">
          <img src={logo} alt="PhantomFix" />
          <span className="exec-topbar-name">PhantomFix</span>
        </div>
        <div className="exec-topbar-badge">
          <span className="exec-badge-dot" />
          Relatório Executivo
        </div>
      </header>

      <main className="exec-main">
        {/* ── Hero ── */}
        <div className="exec-hero">
          <div className="exec-hero-icon">📋</div>
          <div className="exec-hero-texto">
            <h1 className="exec-titulo">Relatório Executivo</h1>
            <p className="exec-subtitulo">
              Análise consolidada de segurança para{" "}
              <strong>{relatorio.repositorio || "seu repositório"}</strong>
            </p>
            <p className="exec-data">Gerado em {formatarData(relatorio.gerado_em)}</p>
          </div>
        </div>

        {/* ── Métricas resumidas ── */}
        {relatorio.resumo && (
          <div className="exec-metricas">
            {relatorio.resumo.total != null && (
              <div className="exec-metrica">
                <span className="exec-metrica-valor">{relatorio.resumo.total}</span>
                <span className="exec-metrica-label">Vulnerabilidades</span>
              </div>
            )}
            {relatorio.resumo.criticas != null && (
              <div className="exec-metrica exec-metrica-critica">
                <span className="exec-metrica-valor">{relatorio.resumo.criticas}</span>
                <span className="exec-metrica-label">Críticas</span>
              </div>
            )}
            {relatorio.resumo.score != null && (
              <div className="exec-metrica">
                <span className="exec-metrica-valor">{relatorio.resumo.score}</span>
                <span className="exec-metrica-label">Score médio</span>
              </div>
            )}
            {relatorio.resumo.compliance && (
              <div className="exec-metrica">
                <span className="exec-metrica-valor">{relatorio.resumo.compliance}</span>
                <span className="exec-metrica-label">Conformidade</span>
              </div>
            )}
          </div>
        )}

        {/* ── Corpo do relatório ── */}
        <div className="exec-corpo">
          {secoes.length > 0 ? (
            secoes.map((secao, i) => (
              <section key={i} className="exec-secao">
                {secao.titulo && <h2 className="exec-secao-titulo">{secao.titulo}</h2>}
                <div className="exec-secao-conteudo">
                  {secao.paragrafos.map((p, j) => (
                    <p key={j}>{p}</p>
                  ))}
                </div>
              </section>
            ))
          ) : (
            <section className="exec-secao">
              <div className="exec-secao-conteudo exec-texto-bruto">
                {(relatorio.texto || "Conteúdo não disponível.").split("\n").map((linha, i) =>
                  linha.trim() ? <p key={i}>{linha}</p> : <br key={i} />
                )}
              </div>
            </section>
          )}
        </div>

        {/* ── Ações ── */}
        <div className="exec-acoes">
          <button
            className="exec-btn-download"
            onClick={handleBaixar}
            disabled={baixando}
          >
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
              <path d="M9 3v9M5 9l4 4 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M3 15h12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
            </svg>
            {baixando ? "Gerando..." : "Baixar relatório (.txt)"}
          </button>

          <button
            className="exec-btn-dashboard"
            onClick={handleAcessar}
            disabled={acessando}
          >
            {acessando ? "Carregando..." : "Acessar Dashboard completo"}
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </button>
        </div>
      </main>
    </div>
  );
}

/**
 * Divide o texto do relatório em seções com título e parágrafos.
 * Aceita títulos precedidos por ##, **, números ou maiúsculas.
 */
function parsearSecoes(texto) {
  if (!texto) return [];
  const linhas = texto.split("\n");
  const secoes = [];
  let secaoAtual = null;

  for (const linha of linhas) {
    const trimada = linha.trim();
    if (!trimada) {
      if (secaoAtual) secaoAtual.paragrafos.push("");
      continue;
    }

    const ehTitulo =
      /^#{1,3}\s/.test(trimada) ||
      /^\*{2}.+\*{2}$/.test(trimada) ||
      /^\d+\.\s[A-Z]/.test(trimada) ||
      (trimada.length < 60 && trimada === trimada.toUpperCase() && trimada.length > 4);

    if (ehTitulo) {
      if (secaoAtual) secoes.push(secaoAtual);
      secaoAtual = {
        titulo: trimada.replace(/^#{1,3}\s/, "").replace(/\*{2}/g, ""),
        paragrafos: [],
      };
    } else {
      if (!secaoAtual) secaoAtual = { titulo: null, paragrafos: [] };
      // agrupa linhas consecutivas não-vazias num mesmo parágrafo
      const ultimo = secaoAtual.paragrafos[secaoAtual.paragrafos.length - 1];
      if (ultimo && ultimo !== "") {
        secaoAtual.paragrafos[secaoAtual.paragrafos.length - 1] = ultimo + " " + trimada;
      } else {
        secaoAtual.paragrafos.push(trimada);
      }
    }
  }

  if (secaoAtual) secoes.push(secaoAtual);
  return secoes.filter((s) => s.paragrafos.some((p) => p.trim()));
}
