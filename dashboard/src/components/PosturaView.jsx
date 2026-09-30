/**
 * PosturaView.jsx — substitui Home.jsx
 * Autora e revisão: Giovana Esmelardi / Rafael Pedro
 *
 * Exibe a postura histórica de segurança:
 *   • PhantomScore do último scan + delta vs. anterior
 *   • Mini-gráfico de tendência (sparkbar)
 *   • Recorrentes detectados por fingerprint ou tipo+arquivo+linha
 *   • Recomendação proativa do Spirit (chamada única ao montar)
 *   • Lista de scans clicáveis → chama onRelatorioCarregado
 *   • Banner de pipeline ativo (polling herdado do Home)
 */

import { useEffect, useRef, useState } from "react";
import logo from "../assets/logo.png";
import { buscarPostura, buscarRelatorio, detectarScanAtivo, perguntarSpirit } from "../api";

const ETAPAS = {
  recebido:             { label: "Repositório recebido",          pct: 10 },
  extraindo:            { label: "Extraindo arquivos…",           pct: 20 },
  processando_contexto: { label: "Processando contexto…",         pct: 30 },
  escaneando:           { label: "Escaneando vulnerabilidades…",  pct: 40 },
  analisando:           { label: "Analisando com IA…",            pct: 65 },
  priorizado:           { label: "Priorizando resultados…",       pct: 75 },
  corrigindo:           { label: "Gerando correções (Ghost)…",    pct: 88 },
  gerando_relatorio:    { label: "Gerando relatório executivo…",  pct: 93 },
  gerando_vault:        { label: "Gerando Vault Obsidian…",       pct: 97 },
  concluido:            { label: "Análise concluída!",            pct: 100 },
  erro:                 { label: "Erro na análise",               pct: 100 },
};

function formatarData(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
    timeZone: "America/Sao_Paulo",
  });
}

/** Fingerprint canônico: usa o campo do analyser se disponível, senão monta chave. */
function fp(vuln) {
  return vuln.fingerprint || `${vuln.tipo || ""}|${vuln.arquivo || ""}|${vuln.linha || ""}`;
}

/** Retorna vulns do scan mais recente que também existem no anterior. */
function calcularRecorrentes(entradaAnterior, entradaAtual) {
  if (!entradaAnterior || !entradaAtual) return [];
  const setAnt = new Set((entradaAnterior.vulnerabilidades || []).map(fp));
  return (entradaAtual.vulnerabilidades || []).filter((v) => setAnt.has(fp(v)));
}

function labelScore(score) {
  if (score >= 8) return "Muito arriscado";
  if (score >= 6) return "Arriscado";
  if (score >= 4) return "Moderado";
  return "Sob controle";
}

function classeScore(score) {
  if (score >= 8) return "critica";
  if (score >= 6) return "alta";
  if (score >= 4) return "media";
  return "baixa";
}

export default function PosturaView({ onRelatorioCarregado, onAbrirPipeline, onSair }) {
  const [posturaData, setPosturaData]           = useState([]);
  const [carregando, setCarregando]             = useState(true);
  const [pipeline, setPipeline]                 = useState(null);
  const [abrindo, setAbrindo]                   = useState(null);
  const [spiritMsg, setSpiritMsg]               = useState(null);
  const [spiritCarregando, setSpiritCarregando] = useState(false);
  const spiritChamado                           = useRef(false);

  // ── Carrega postura ────────────────────────────────────────────────────────
  useEffect(() => {
    let ok = true;
    (async () => {
      try {
        const dados = await buscarPostura();
        if (ok) setPosturaData(dados);
      } catch { /* ignore */ } finally {
        if (ok) setCarregando(false);
      }
    })();
    return () => { ok = false; };
  }, []);

  // ── Polling de scan ativo (idêntico ao Home) ───────────────────────────────
  useEffect(() => {
    let cancelado = false;
    const id = setInterval(async () => {
      try {
        const ativo = await detectarScanAtivo();
        if (cancelado) return;
        if (ativo?.protocolo) {
          setPipeline(ativo);
          if (ativo.status === "concluido") {
            clearInterval(id);
            const rel = await buscarRelatorio();
            if (rel && !cancelado) onRelatorioCarregado(rel);
          }
        } else {
          setPipeline(null);
        }
      } catch { /* ignore */ }
    }, 3000);
    return () => { cancelado = true; clearInterval(id); };
  }, [onRelatorioCarregado]);

  // ── Recomendação do Spirit — disparada uma única vez quando os dados chegam ─
  useEffect(() => {
    if (spiritChamado.current || posturaData.length === 0 || spiritCarregando) return;
    spiritChamado.current = true;

    const ultimo = posturaData[0];
    if (!ultimo) return;

    const top3 = [...(ultimo.vulnerabilidades || [])]
      .sort((a, b) => (Number(b.score) || 0) - (Number(a.score) || 0))
      .slice(0, 3)
      .map((v) => `- ${(v.tipo || "desconhecido").replace(/^CWE-\d+\s*/i, "")} (score ${v.score ?? 0}) em ${v.arquivo || "?"}`)
      .join("\n");

    const prompt =
      `Com base na postura de segurança atual do projeto "${ultimo.repositorio || "projeto"}":\n` +
      `- PhantomScore: ${ultimo.score ?? "—"}/10 (${labelScore(ultimo.score ?? 0)})\n` +
      `- Total: ${ultimo.total ?? 0} vulnerabilidades ` +
      `(${ultimo.criticas} críticas, ${ultimo.altas} altas, ${ultimo.medias} médias, ${ultimo.baixas} baixas)\n` +
      `- Top 3 mais críticos:\n${top3 || "- Nenhum"}\n\n` +
      `Em até 3 frases objetivas, diga o que a equipe deve priorizar agora.`;

    setSpiritCarregando(true);
    perguntarSpirit(prompt, {
      repositorio: ultimo.repositorio,
      vulnerabilidades: (ultimo.vulnerabilidades || []).slice(0, 5),
    })
      .then((resp) => { if (resp?.resposta) setSpiritMsg(resp.resposta); })
      .catch(() => { /* Spirit pode estar offline */ })
      .finally(() => setSpiritCarregando(false));
  }, [posturaData]);

  // ── Derivações ─────────────────────────────────────────────────────────────
  const semDados    = !carregando && posturaData.length === 0;
  const ultimo      = posturaData[0] ?? null;
  const penultimo   = posturaData[1] ?? null;
  const delta =
    ultimo !== null && penultimo !== null &&
    ultimo.score !== null && penultimo.score !== null
      ? parseFloat((ultimo.score - penultimo.score).toFixed(1))
      : null;
  const recorrentes = calcularRecorrentes(penultimo, ultimo);

  const etapa    = pipeline ? (ETAPAS[pipeline.status] ?? null) : null;
  const rodando  = pipeline && pipeline.status &&
    !["concluido", "erro"].includes(pipeline.status);

  async function abrirRelatorio(protocolo) {
    if (abrindo) return;
    setAbrindo(protocolo);
    try {
      const rel = await buscarRelatorio(protocolo);
      if (rel) onRelatorioCarregado(rel);
    } catch { /* ignore */ } finally {
      setAbrindo(null);
    }
  }

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="postura-shell">
      {/* Topbar mínima */}
      <div className="postura-topbar">
        <img src={logo} alt="PhantomFix" className="postura-topbar-logo" />
        <span className="postura-topbar-titulo">Postura de Segurança</span>
        {onSair && (
          <button className="postura-btn-sair" onClick={onSair}>Sair</button>
        )}
      </div>

      <main className="postura-main">

        {/* ── Banner de pipeline ativo ──────────────────────────────────── */}
        {pipeline && etapa && (
          <div className="postura-pipeline-banner">
            <div className="postura-pipeline-info">
              {rodando && <span className="postura-pipeline-pulse" />}
              <span className="postura-pipeline-repo">
                {pipeline.repositorio || "Repositório"}
              </span>
              <span className="postura-pipeline-etapa">{etapa.label}</span>
            </div>
            <div className="postura-pipeline-barra-bg">
              <div
                className={`postura-pipeline-barra${pipeline.status === "erro" ? " barra-erro" : ""}`}
                style={{ width: `${etapa.pct}%` }}
              />
            </div>
            {rodando && onAbrirPipeline && (
              <button
                className="postura-pipeline-btn"
                onClick={() => onAbrirPipeline(pipeline.protocolo)}
              >
                Ver Pipeline →
              </button>
            )}
          </div>
        )}

        {/* ── Sem dados ────────────────────────────────────────────────── */}
        {semDados && !pipeline && (
          <div className="postura-vazio">
            <img src={logo} alt="PhantomFix" className="postura-vazio-logo" />
            <h2>Nenhuma análise ainda</h2>
            <p className="postura-vazio-desc">
              Envie um repositório pelo Client desktop e sua postura de segurança
              aparecerá aqui automaticamente.
            </p>
          </div>
        )}

        {/* ── Carregando ───────────────────────────────────────────────── */}
        {carregando && (
          <div className="postura-carregando">
            <div className="postura-spinner" />
            <p>Carregando postura…</p>
          </div>
        )}

        {/* ── Conteúdo principal ───────────────────────────────────────── */}
        {!carregando && posturaData.length > 0 && (
          <>

            {/* ── Cards de métricas ──────────────────────────────────── */}
            <div className="postura-metricas">

              {/* PhantomScore */}
              <div className={`postura-metric-card postura-phantom-score sev-card-${classeScore(ultimo?.score ?? 0)}`}>
                <div className="postura-metric-label">PhantomScore</div>
                <div className="postura-metric-valor">
                  {ultimo?.score ?? "—"}
                  <span className="postura-metric-max">/10</span>
                </div>
                <div className="postura-metric-sub">{labelScore(ultimo?.score ?? 0)}</div>
                {delta !== null && (
                  <div className={`postura-delta ${delta < 0 ? "delta-melhorou" : delta > 0 ? "delta-piorou" : "delta-igual"}`}>
                    {delta > 0 ? `▲ +${delta}` : delta < 0 ? `▼ ${delta}` : "= estável"}
                    <span className="postura-delta-sub"> vs scan anterior</span>
                  </div>
                )}
              </div>

              {/* Último scan */}
              <div className="postura-metric-card">
                <div className="postura-metric-label">Último scan</div>
                <div className="postura-metric-valor postura-metric-total">
                  {ultimo?.total ?? "—"}
                  <span className="postura-metric-max"> vulns</span>
                </div>
                <div className="postura-dist">
                  {(ultimo?.criticas ?? 0) > 0 && (
                    <span className="dist-chip critica">{ultimo.criticas} crítica{ultimo.criticas !== 1 ? "s" : ""}</span>
                  )}
                  {(ultimo?.altas ?? 0) > 0 && (
                    <span className="dist-chip alta">{ultimo.altas} alta{ultimo.altas !== 1 ? "s" : ""}</span>
                  )}
                  {(ultimo?.medias ?? 0) > 0 && (
                    <span className="dist-chip media">{ultimo.medias} média{ultimo.medias !== 1 ? "s" : ""}</span>
                  )}
                  {(ultimo?.baixas ?? 0) > 0 && (
                    <span className="dist-chip baixa">{ultimo.baixas} baixa{ultimo.baixas !== 1 ? "s" : ""}</span>
                  )}
                </div>
              </div>

              {/* Histórico */}
              <div className="postura-metric-card">
                <div className="postura-metric-label">Scans registrados</div>
                <div className="postura-metric-valor postura-metric-total">{posturaData.length}</div>
                <div className="postura-metric-sub">nos últimos registros</div>
              </div>

              {/* Recorrentes */}
              {recorrentes.length > 0 && (
                <div className="postura-metric-card postura-metric-recorrentes">
                  <div className="postura-metric-label">Recorrentes</div>
                  <div className="postura-metric-valor postura-metric-total">{recorrentes.length}</div>
                  <div className="postura-metric-sub">nos últimos 2 scans</div>
                </div>
              )}
            </div>

            {/* ── Tendência (sparkbar) ────────────────────────────────── */}
            {posturaData.length >= 2 && (
              <div className="postura-tendencia">
                <h3 className="postura-secao-titulo">Tendência de Score</h3>
                <div className="postura-spark">
                  {[...posturaData].reverse().map((entry, i, arr) => {
                    const pct = ((entry.score ?? 0) / 10) * 100;
                    const isAtual = i === arr.length - 1;
                    return (
                      <div key={entry.protocolo} className="postura-spark-col">
                        <div className="postura-spark-bar-wrap">
                          <div
                            className={`postura-spark-bar${isAtual ? " spark-atual" : ""}`}
                            style={{ height: `${Math.max(pct, 5)}%` }}
                            title={`${entry.repositorio} — Score ${entry.score ?? "—"}`}
                          />
                        </div>
                        <span className="postura-spark-val">{entry.score ?? "—"}</span>
                      </div>
                    );
                  })}
                </div>
                <div className="postura-spark-labels">
                  {[...posturaData].reverse().map((entry, i, arr) => (
                    <span key={entry.protocolo} className="postura-spark-label">
                      {i === arr.length - 1 ? "atual" : `-${arr.length - 1 - i}`}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* ── Recomendação do Spirit ──────────────────────────────── */}
            {(spiritCarregando || spiritMsg) && (
              <div className="postura-spirit-rec">
                <div className="postura-spirit-rec-header">
                  <span className="postura-spirit-rec-icon">👻</span>
                  <span className="postura-spirit-rec-titulo">Recomendação do Spirit</span>
                </div>
                {spiritCarregando ? (
                  <div className="postura-spirit-loading">
                    <span className="postura-spinner-sm" />
                    Consultando Spirit…
                  </div>
                ) : (
                  <p className="postura-spirit-rec-texto">{spiritMsg}</p>
                )}
              </div>
            )}

            {/* ── Vulnerabilidades recorrentes ────────────────────────── */}
            {recorrentes.length > 0 && (
              <div className="postura-recorrentes">
                <h3 className="postura-secao-titulo">
                  ⚠ Recorrentes
                  <span className="postura-secao-sub"> — presentes nos últimos 2 scans</span>
                </h3>
                <div className="postura-recorrentes-lista">
                  {recorrentes.slice(0, 6).map((v, i) => {
                    const s     = Number(v.score) || 0;
                    const cls   = s >= 9 ? "critica" : s >= 7 ? "alta" : s >= 4 ? "media" : "baixa";
                    const label = s >= 9 ? "Crítica" : s >= 7 ? "Alta"  : s >= 4 ? "Média" : "Baixa";
                    const tipo  = (v.tipo || "desconhecido").replace(/^CWE-\d+\s*/i, "");
                    const arq   = v.arquivo
                      ? v.arquivo.length > 38 ? "…" + v.arquivo.slice(-35) : v.arquivo
                      : "—";
                    return (
                      <div key={v.id || i} className="postura-recorrente-item">
                        <span className={`postura-rec-sev sev-${cls}`}>
                          <span className={`vuln-linha-dot sev-${cls}`} />
                          {label}
                        </span>
                        <span className="postura-rec-tipo">{tipo}</span>
                        <span className="postura-rec-arquivo">{arq}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* ── Lista de scans ──────────────────────────────────────── */}
            <div className="postura-historico">
              <h3 className="postura-secao-titulo">Histórico de scans</h3>
              <div className="postura-historico-lista">
                {posturaData.map((entry, i) => (
                  <button
                    key={entry.protocolo}
                    className={`postura-hist-linha${abrindo === entry.protocolo ? " abrindo" : ""}`}
                    onClick={() => abrirRelatorio(entry.protocolo)}
                    disabled={!!abrindo}
                  >
                    <div className="postura-hist-esquerda">
                      <span className="postura-hist-repo">{entry.repositorio}</span>
                      <span className="postura-hist-data">{formatarData(entry.processado_em)}</span>
                    </div>
                    <div className="postura-hist-direita">
                      <span className="postura-hist-score">
                        Score <strong>{entry.score ?? "—"}</strong>
                      </span>
                      <span className="postura-hist-total">{entry.total ?? "—"} vulns</span>
                      {i === 0 && <span className="postura-hist-badge-atual">mais recente</span>}
                    </div>
                    <span className="postura-hist-chevron">›</span>
                  </button>
                ))}
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
