{/*# PhantomFix — Copyright (C) 2025–2026 Rafael Pedro, Bernardo Coroa,
   # Giovanna Esmelardi, Gustavo Enrique
   # SPDX-License-Identifier: GPL-3.0-or-later
   # Licenciado sob a GNU GPL v3. Veja LICENSE.md na raiz do repositório.*/}

/**
 * ResultsView.jsx
 * Autora e revisão: Giovana Esmelardi / Rafael Pedro
 *
 * Adições v2:
 *  • Toggle Bruto / Aprimorado (sessionStorage)
 *  • Filtro por scanner (derivado de vuln.origem)
 *  • Filtro KEV
 *  • SLA badge nas VulnLinhas (calculado aqui, passado para VulnCard)
 *  • Checkbox Corrigido + botão FP (estado local por Set de IDs)
 *  • Modal de Falso Positivo com justificativa obrigatória
 */

import { useState, useMemo, useCallback } from "react";
import VulnCard from "./VulnCard";
import Topbar from "./Topbar";
import VaultDownload from "./VaultDownload";

const QUANTIDADE_PRIORITARIA = 4;
const VULNS_POR_PAGINA = 6;

// SLA em milissegundos por faixa de score
const SLA_MS = {
  critica: 24  * 60 * 60 * 1000,   // 24 h
  alta:    72  * 60 * 60 * 1000,   // 3 dias
  media:   120 * 60 * 60 * 1000,   // 5 dias
};

function severidade(score) {
  const s = Number(score) || 0;
  if (s >= 9) return { label: "Crítica", classe: "critica" };
  if (s >= 7) return { label: "Alta",    classe: "alta"    };
  if (s >= 4) return { label: "Média",   classe: "media"   };
  return           { label: "Baixa",   classe: "baixa"   };
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
    timeZone: "America/Sao_Paulo",
  });
}

/** true quando a vuln passou do prazo SLA relativo ao processado_em do relatório */
function isSlaVencido(vuln, processadoEm) {
  if (!processadoEm) return false;
  const s = Number(vuln.score) || 0;
  const limite =
    s >= 9 ? SLA_MS.critica :
    s >= 7 ? SLA_MS.alta :
    s >= 4 ? SLA_MS.media : null;
  if (!limite) return false;
  return Date.now() - new Date(processadoEm).getTime() > limite;
}

// ── Modal de Falso Positivo ───────────────────────────────────────────────────
function FPModal({ vuln, onConfirmar, onCancelar }) {
  const [justificativa, setJustificativa] = useState("");
  const [erro, setErro] = useState(false);

  function confirmar() {
    if (!justificativa.trim()) { setErro(true); return; }
    onConfirmar(vuln.id, justificativa.trim());
  }

  return (
    <div className="fp-modal-overlay" onClick={onCancelar}>
      <div className="fp-modal" onClick={(e) => e.stopPropagation()}>
        <h3 className="fp-modal-titulo">Marcar como Falso Positivo</h3>
        <p className="fp-modal-desc">
          <strong>{(vuln.tipo || "Vulnerabilidade").replace(/^CWE-\d+\s*/i, "")}</strong>
          {vuln.arquivo ? ` — ${vuln.arquivo}${vuln.linha ? `:${vuln.linha}` : ""}` : ""}
        </p>
        <label className="fp-modal-label">
          Justificativa <span className="fp-obrigatorio">*</span>
          <textarea
            className={`fp-modal-textarea${erro ? " fp-textarea-erro" : ""}`}
            placeholder="Por que esta vulnerabilidade é um falso positivo?"
            rows={4}
            value={justificativa}
            onChange={(e) => { setJustificativa(e.target.value); setErro(false); }}
          />
          {erro && <span className="fp-erro-msg">Justificativa obrigatória.</span>}
        </label>
        <div className="fp-modal-acoes">
          <button className="fp-btn-cancelar" onClick={onCancelar}>Cancelar</button>
          <button className="fp-btn-confirmar" onClick={confirmar}>Confirmar FP</button>
        </div>
      </div>
    </div>
  );
}

// ── VulnLinha (lista completa) ────────────────────────────────────────────────
function VulnLinha({ vuln, modoAprimorado, slaVencido, corrigido, onCorrigir, onFP }) {
  const [aberto, setAberto] = useState(false);
  const sev = severidade(vuln.score);
  const arquivo = vuln.arquivo || "—";
  const arquivoDisplay = arquivo.length > 32 ? "…" + arquivo.slice(-29) : arquivo;
  const tipo = (vuln.tipo || "desconhecido").replace(/^CWE-\d+\s*/i, "");
  const correcaoDisponivel =
    Boolean(vuln.correcao) &&
    vuln.correcao !== "Ghost não disponível" &&
    vuln.correcao !== "Correção indisponível";

  const origens = Array.isArray(vuln.origens_confirmadas) && vuln.origens_confirmadas.length
    ? vuln.origens_confirmadas
    : vuln.origem ? [vuln.origem] : [];

  return (
    <>
      <div
        className={`vuln-linha${aberto ? " aberta" : ""}${corrigido ? " vuln-linha-corrigida" : ""}`}
        onClick={() => setAberto(!aberto)}
      >
        <span className={`vuln-linha-sev sev-${sev.classe}`}>
          <span className={`vuln-linha-dot sev-${sev.classe}`} />
          {sev.label}
        </span>
        <span className="vuln-linha-tipo">{tipo}</span>
        <span className="vuln-linha-arquivo">{arquivoDisplay}</span>
        {vuln.linha && <span className="vuln-linha-linha">L{vuln.linha}</span>}

        {/* Tags inline */}
        <span className="vuln-linha-tags">
          {vuln.kev === true && <span className="kev-badge kev-badge-sm">KEV</span>}
          {slaVencido && !corrigido && <span className="sla-badge sla-badge-sm">SLA</span>}
          {origens.slice(0, 2).map((o) => (
            <span key={o} className={`vuln-origem-tag origem-${(o || "").toLowerCase()}`}>{o}</span>
          ))}
        </span>

        {/* Ações inline */}
        <span className="vuln-linha-acoes" onClick={(e) => e.stopPropagation()}>
          {onCorrigir && (
            <label className="vuln-check-inline">
              <input
                type="checkbox"
                checked={corrigido}
                onChange={(e) => onCorrigir(vuln.id, e.target.checked)}
              />
            </label>
          )}
          {onFP && !corrigido && (
            <button
              className="btn-fp btn-fp-sm"
              onClick={() => onFP(vuln)}
              title="Falso positivo"
            >FP</button>
          )}
        </span>

        <span className={`vuln-linha-chevron${aberto ? " aberto" : ""}`}>›</span>
      </div>

      {aberto && (
        <div className="vuln-linha-detalhe">
          {modoAprimorado && vuln.justificativa && (
            <div className="vuln-detalhe-secao">
              <h4>Por que isso importa?</h4>
              <p>{vuln.justificativa}</p>
            </div>
          )}
          {!modoAprimorado && vuln.descricao && (
            <div className="vuln-detalhe-secao">
              <h4>Descrição original</h4>
              <p>{vuln.descricao}</p>
            </div>
          )}
          {vuln.kev === true && (
            <div className="vuln-detalhe-secao vuln-kev-info">
              <h4>🔴 CISA Known Exploited Vulnerability</h4>
              <p>Esta CVE consta no catálogo CISA KEV — exploração ativa confirmada.
                {vuln.kev_data_adicao ? ` Adicionada em ${vuln.kev_data_adicao}.` : ""}
              </p>
            </div>
          )}
          {modoAprimorado && correcaoDisponivel ? (
            <div className="vuln-detalhe-secao">
              <h4>Correção sugerida (Ghost)</h4>
              <pre className="vuln-detalhe-codigo">{vuln.correcao}</pre>
            </div>
          ) : modoAprimorado ? (
            <div className="vuln-detalhe-secao">
              <h4>Correção sugerida</h4>
              <p className="vuln-detalhe-sem-correcao">Ghost não gerou correção para esta vulnerabilidade.</p>
            </div>
          ) : null}
        </div>
      )}
    </>
  );
}

// ── ResultsView ────────────────────────────────────────────────────────────────
export default function ResultsView({
  relatorio,
  scanState,
  spiritAberto,
  onToggleSpirit,
  onVerHistorico,
  onAbrirPipeline,
  onSair,
  onVerRelatorioExecutivo,
}) {
  // ── Modo Bruto / Aprimorado ─────────────────────────────────────────────────
  const [modoAprimorado, setModoAprimorado] = useState(() => {
    return sessionStorage.getItem("pf_modo_exibicao") !== "bruto";
  });

  function toggleModo() {
    const novo = !modoAprimorado;
    setModoAprimorado(novo);
    sessionStorage.setItem("pf_modo_exibicao", novo ? "aprimorado" : "bruto");
  }

  // ── Filtros ─────────────────────────────────────────────────────────────────
  const [filtroScanner, setFiltroScanner] = useState("todos");
  const [filtroKEV, setFiltroKEV]         = useState(false);
  const [tabAtiva, setTabAtiva]           = useState("todas");
  const [pagina, setPagina]               = useState(1);

  // ── Rastreabilidade local ────────────────────────────────────────────────────
  const [corrigidosSet, setCorrigidosSet] = useState(() => new Set());
  const [fpSet, setFpSet]                 = useState(() => new Set());
  const [fpModal, setFpModal]             = useState(null); // vuln | null

  function handleCorrigir(id, marcado) {
    setCorrigidosSet((prev) => {
      const next = new Set(prev);
      marcado ? next.add(id) : next.delete(id);
      return next;
    });
  }

  function handleFP(vuln) {
    setFpModal(vuln);
  }

  function confirmarFP(id, justificativa) {
    setFpSet((prev) => new Set([...prev, id]));
    setFpModal(null);
  }

  // ── Dados base ──────────────────────────────────────────────────────────────
  const vulnsRaw = relatorio.vulnerabilidades || [];
  const processadoEm = relatorio.processado_em || relatorio.analisado_em;

  const ordenadas = useMemo(() =>
    [...vulnsRaw]
      .filter((v) => !fpSet.has(v.id))
      .sort((a, b) =>
        modoAprimorado
          ? (Number(b.score) || 0) - (Number(a.score) || 0)
          : (a.origem || "").localeCompare(b.origem || "")
      ),
    [vulnsRaw, fpSet, modoAprimorado]
  );

  // Scanners disponíveis (para o filtro)
  const scannersDisponiveis = useMemo(() => {
    const set = new Set(ordenadas.map((v) => v.origem).filter(Boolean));
    return ["todos", ...Array.from(set).sort()];
  }, [ordenadas]);

  // Aplica filtros
  const filtradas = useMemo(() => {
    let lista = ordenadas;
    if (filtroScanner !== "todos") lista = lista.filter((v) => v.origem === filtroScanner);
    if (filtroKEV) lista = lista.filter((v) => v.kev === true);
    return lista;
  }, [ordenadas, filtroScanner, filtroKEV]);

  const criticas = filtradas.filter((v) => Number(v.score) >= 9);
  const altas    = filtradas.filter((v) => { const s = Number(v.score); return s >= 7 && s < 9; });
  const medias   = filtradas.filter((v) => { const s = Number(v.score); return s >= 4 && s < 7; });
  const baixas   = filtradas.filter((v) => Number(v.score) < 4);

  const mapaTab  = { todas: filtradas, criticas, altas, medias, baixas };
  const vulnsFiltradas = mapaTab[tabAtiva] || filtradas;
  const prioritarias   = filtradas.slice(0, QUANTIDADE_PRIORITARIA);

  const totalPaginas = Math.max(1, Math.ceil(vulnsFiltradas.length / VULNS_POR_PAGINA));
  const vulnsPagina  = vulnsFiltradas.slice(
    (pagina - 1) * VULNS_POR_PAGINA,
    pagina * VULNS_POR_PAGINA
  );

  const scoreMedio = calcularScoreMedio(filtradas);
  const total = relatorio.total_encontrado ?? vulnsRaw.length;

  function mudarTab(tab) { setTabAtiva(tab); setPagina(1); }
  function mudarFiltroScanner(v) { setFiltroScanner(v); setPagina(1); }

  function paginacaoBotoes() {
    if (totalPaginas <= 7) return Array.from({ length: totalPaginas }, (_, i) => i + 1);
    const btns = [1];
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
      <Topbar
        repositorio={relatorio.repositorio}
        processadoEm={processadoEm}
        scanState={scanState}
        spiritAberto={spiritAberto}
        onToggleSpirit={onToggleSpirit}
        onVerHistorico={onVerHistorico}
        onAbrirPipeline={onAbrirPipeline}
        onSair={onSair}
      />

      {/* ── Modal FP ── */}
      {fpModal && (
        <FPModal
          vuln={fpModal}
          onConfirmar={confirmarFP}
          onCancelar={() => setFpModal(null)}
        />
      )}

      <main className="main-content">

        {/* ── Vault ── */}
        {relatorio.protocolo && (
          <div className="vault-download-wrapper">
            <VaultDownload protocolo={relatorio.protocolo} />
          </div>
        )}

        {/* ── Toggle Bruto / Aprimorado ── */}
        <div className="modo-toggle-row">
          <span className="modo-toggle-label">Modo de exibição</span>
          <div className="modo-toggle">
            <button
              className={`modo-btn${!modoAprimorado ? " modo-btn-ativo" : ""}`}
              onClick={() => !modoAprimorado || toggleModo()}
            >
              Bruto
            </button>
            <button
              className={`modo-btn${modoAprimorado ? " modo-btn-ativo" : ""}`}
              onClick={() => modoAprimorado || toggleModo()}
            >
              Aprimorado ✦
            </button>
          </div>

          {/* Filtros de scanner e KEV */}
          <div className="filtros-row">
            <select
              className="filtro-scanner-select"
              value={filtroScanner}
              onChange={(e) => mudarFiltroScanner(e.target.value)}
            >
              {scannersDisponiveis.map((s) => (
                <option key={s} value={s}>
                  {s === "todos" ? "Todos os scanners" : s}
                </option>
              ))}
            </select>

            <label className="filtro-kev-label">
              <input
                type="checkbox"
                checked={filtroKEV}
                onChange={(e) => { setFiltroKEV(e.target.checked); setPagina(1); }}
              />
              Apenas KEV
            </label>

            {(corrigidosSet.size > 0 || fpSet.size > 0) && (
              <span className="filtros-resumo">
                {corrigidosSet.size > 0 && `${corrigidosSet.size} corrigida${corrigidosSet.size !== 1 ? "s" : ""}`}
                {corrigidosSet.size > 0 && fpSet.size > 0 && " · "}
                {fpSet.size > 0 && `${fpSet.size} FP`}
              </span>
            )}
          </div>
        </div>

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
            <div className="metrica-grande-label">
              Encontradas neste scan
              {filtroKEV && <span className="metrica-kev-filtro"> · filtro KEV ativo</span>}
            </div>
            <div className="metrica-dist">
              {criticas.length > 0 && <span className="dist-chip critica">{criticas.length} críticas</span>}
              {altas.length    > 0 && <span className="dist-chip alta">{altas.length} altas</span>}
              {medias.length   > 0 && <span className="dist-chip media">{medias.length} médias</span>}
              {baixas.length   > 0 && <span className="dist-chip baixa">{baixas.length} baixas</span>}
            </div>
          </div>
        </div>

        {/* ── Relatório Executivo ── */}
        {onVerRelatorioExecutivo && (
          <button
            type="button"
            className="btn-relatorio-executivo"
            onClick={onVerRelatorioExecutivo}
          >
            <span className="btn-relatorio-executivo-icone">📋</span>
            <span className="btn-relatorio-executivo-texto">
              <strong>Relatório Executivo</strong>
              <span>Visão CISO desta análise · gerado pelo Spirit</span>
            </span>
            <span className="btn-relatorio-executivo-seta">→</span>
          </button>
        )}

        {/* ── Prioritárias ── */}
        <div className="prioridade-hero">
          <span className="prioridade-label">⭐ Sua prioridade agora</span>
          <h2 className="prioridade-titulo">
            Corrija estas {prioritarias.length} vulnerabilidades primeiro
          </h2>
        </div>

        <div className="lista-prioritarias">
          {prioritarias.map((v, i) => (
            <VulnCard
              key={v.id || i}
              vuln={v}
              posicao={i + 1}
              slaVencido={isSlaVencido(v, processadoEm)}
              corrigido={corrigidosSet.has(v.id)}
              onCorrigir={handleCorrigir}
              onFP={handleFP}
            />
          ))}
        </div>

        {/* ── Lista completa ── */}
        <div className="lista-completa">
          <div className="lista-tabs">
            {[
              { key: "todas",    label: `Todas (${filtradas.length})` },
              { key: "criticas", label: `Críticas (${criticas.length})` },
              { key: "altas",    label: `Altas (${altas.length})` },
              { key: "medias",   label: `Médias (${medias.length})` },
              { key: "baixas",   label: `Baixas (${baixas.length})` },
            ].map((t) => (
              <button
                key={t.key}
                className={`lista-tab${tabAtiva === t.key ? " ativa" : ""} tab-${t.key}`}
                onClick={() => mudarTab(t.key)}
              >
                {t.label}
              </button>
            ))}
            <span className="lista-mostrando">
              Mostrando {vulnsFiltradas.length > 0 ? (pagina - 1) * VULNS_POR_PAGINA + 1 : 0}–
              {Math.min(pagina * VULNS_POR_PAGINA, vulnsFiltradas.length)} de {vulnsFiltradas.length}
            </span>
          </div>

          <div className="lista-header-linha">
            <span>Severidade</span>
            <span>Vulnerabilidade</span>
            <span>Arquivo</span>
            <span>Linha</span>
            <span>Tags</span>
            <span>Ações</span>
            <span />
          </div>

          <div className="lista-corpo">
            {vulnsPagina.length === 0 && (
              <p className="lista-vazia">Nenhuma vulnerabilidade nesta categoria.</p>
            )}
            {vulnsPagina.map((v, i) => (
              <VulnLinha
                key={v.id || i}
                vuln={v}
                modoAprimorado={modoAprimorado}
                slaVencido={isSlaVencido(v, processadoEm)}
                corrigido={corrigidosSet.has(v.id)}
                onCorrigir={handleCorrigir}
                onFP={handleFP}
              />
            ))}
          </div>

          {totalPaginas > 1 && (
            <div className="paginacao">
              <button
                className="paginacao-btn"
                onClick={() => setPagina((p) => Math.max(1, p - 1))}
                disabled={pagina === 1}
              >‹</button>

              {paginacaoBotoes().map((b, i) =>
                b === "..." ? (
                  <span key={i} className="paginacao-dots">…</span>
                ) : (
                  <button
                    key={i}
                    className={`paginacao-btn${pagina === b ? " ativa" : ""}`}
                    onClick={() => setPagina(b)}
                  >{b}</button>
                )
              )}

              <button
                className="paginacao-btn"
                onClick={() => setPagina((p) => Math.min(totalPaginas, p + 1))}
                disabled={pagina === totalPaginas}
              >›</button>
            </div>
          )}
        </div>
      </main>
    </>
  );
}
