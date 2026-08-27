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

// FIX: gera um PDF real via API nativa de impressão do browser.
// Antes usava Blob com text/plain, que baixava um .txt sem formatação.
// Agora abre uma janela com HTML estilizado e dispara window.print(),
// onde o usuário escolhe "Salvar como PDF" — zero dependências extras.
function gerarPDF(relatorio) {
  const textoHtml = (relatorio.texto || "Conteúdo não disponível.")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    // markdown bold
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    // markdown headers
    .replace(/^### (.+)$/gm, "<h3>$1</h3>")
    .replace(/^## (.+)$/gm, "<h2>$1</h2>")
    .replace(/^# (.+)$/gm, "<h1>$1</h1>")
    // separadores
    .replace(/^---+$/gm, "<hr>")
    // quebras de linha
    .replace(/\n\n/g, "</p><p>")
    .replace(/\n/g, "<br>");

  const janelaImpressao = window.open("", "_blank");
  if (!janelaImpressao) {
    alert("Permita pop-ups para gerar o PDF.");
    return;
  }

  janelaImpressao.document.write(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Relatório Executivo — PhantomFix</title>
      <style>
        @media print {
          body { margin: 0; }
          .no-print { display: none; }
        }
        body {
          font-family: 'Segoe UI', Arial, sans-serif;
          max-width: 800px;
          margin: 40px auto;
          color: #111827;
          line-height: 1.7;
          font-size: 14px;
        }
        .header {
          display: flex;
          align-items: center;
          gap: 12px;
          border-bottom: 2px solid #6366F1;
          padding-bottom: 16px;
          margin-bottom: 24px;
        }
        .header-titulo { font-size: 22px; font-weight: 700; color: #6366F1; margin: 0; }
        .header-sub { font-size: 12px; color: #6B7280; margin: 2px 0 0; }
        .meta {
          background: #F9FAFB;
          border: 1px solid #E5E7EB;
          border-radius: 8px;
          padding: 12px 16px;
          margin-bottom: 28px;
          font-size: 13px;
          color: #374151;
        }
        h1, h2, h3 { color: #374151; margin: 24px 0 8px; }
        h2 { font-size: 15px; border-bottom: 1px solid #E5E7EB; padding-bottom: 4px; }
        h3 { font-size: 14px; color: #6366F1; }
        p { margin: 0 0 10px; }
        hr { border: none; border-top: 1px solid #E5E7EB; margin: 20px 0; }
        strong { color: #111827; }
        .footer {
          margin-top: 40px;
          padding-top: 12px;
          border-top: 1px solid #E5E7EB;
          font-size: 11px;
          color: #9CA3AF;
          text-align: center;
        }
        .btn-imprimir {
          display: block;
          margin: 0 auto 24px;
          padding: 10px 28px;
          background: #6366F1;
          color: #fff;
          border: none;
          border-radius: 8px;
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
        }
      </style>
    </head>
    <body>
      <button class="btn-imprimir no-print" onclick="window.print()">
        Salvar como PDF
      </button>

      <div class="header">
        <div>
          <p class="header-titulo">👻 PhantomFix — Relatório Executivo</p>
          <p class="header-sub">Gerado automaticamente ao final da análise de segurança</p>
        </div>
      </div>

      <div class="meta">
        <strong>Repositório:</strong> ${relatorio.repositorio || "—"}&nbsp;&nbsp;·&nbsp;&nbsp;
        <strong>Gerado em:</strong> ${formatarData(relatorio.gerado_em)}&nbsp;&nbsp;·&nbsp;&nbsp;
        <strong>Protocolo:</strong> ${relatorio.protocolo || "—"}
      </div>

      <div><p>${textoHtml}</p></div>

      <div class="footer">
        PhantomFix · Relatório gerado automaticamente · Não substitui auditoria de segurança profissional.
      </div>
    </body>
    </html>
  `);

  janelaImpressao.document.close();

  // Aguarda o render antes de abrir o diálogo de impressão
  janelaImpressao.onload = () => janelaImpressao.print();
  setTimeout(() => {
    try { janelaImpressao.print(); } catch { /* já foi chamado pelo onload */ }
  }, 800);
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

  // FIX: marcarRelatorioLido usava query param (?protocolo=X) mas o Core
  // espera path param (/relatorio-executivo/{protocolo}/lido).
  // A correção está no api.js — aqui o handler não muda.
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
            {baixando ? "Gerando..." : "Baixar relatório (PDF)"}
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
