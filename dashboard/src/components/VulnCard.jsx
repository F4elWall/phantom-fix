/**
 * VulnCard.jsx — Top-N prioritárias
 * Adições: tags de rastreabilidade (origens_confirmadas), badge KEV,
 *          SLA badge, checkbox Corrigido, botão FP via callbacks do pai.
 */

{/*# PhantomFix — Copyright (C) 2025–2026 Rafael Pedro, Bernardo Coroa,
   # Giovanna Esmelardi, Gustavo Enrique
   # SPDX-License-Identifier: GPL-3.0-or-later
   # Licenciado sob a GNU GPL v3. Veja LICENSE.md na raiz do repositório.*/}

import { useState } from "react";
import { temCorrecao } from "../utils";

function severidade(score) {
  const s = Number(score) || 0;
  if (s >= 9) return { label: "Crítica", classe: "critica" };
  if (s >= 7) return { label: "Alta",    classe: "alta"    };
  if (s >= 4) return { label: "Média",   classe: "media"   };
  return           { label: "Baixa",   classe: "baixa"   };
}

export default function VulnCard({
  vuln,
  posicao,
  slaVencido  = false,
  corrigido   = false,
  onCorrigir  = null,   // (id, bool) => void
  onFP        = null,   // (vuln) => void
}) {
  const [aberto, setAberto] = useState(false);
  const score  = Number(vuln.score) || 0;
  const sev    = severidade(score);
  const corr   = temCorrecao(vuln);

  const tipo = (vuln.tipo || "desconhecido").replace(/^CWE-\d+\s*/i, "");
  const arquivo = vuln.arquivo || "";
  const arquivoDisplay = arquivo.length > 28 ? "…" + arquivo.slice(-25) : arquivo;

  // Origens: usa campo do analyser ou fallback para origem simples
  const origens = Array.isArray(vuln.origens_confirmadas) && vuln.origens_confirmadas.length
    ? vuln.origens_confirmadas
    : vuln.origem ? [vuln.origem] : [];

  return (
    <div className={`vuln-card sev-card-${sev.classe}${corrigido ? " vuln-card-corrigida" : ""}`}>
      <div className="vuln-card-topo">
        <div className="vuln-card-num-sev">
          <div className="vuln-card-num">{posicao}</div>
          <div className={`vuln-card-sev-badge sev-${sev.classe}`}>
            <span className="dot" />
            {score.toFixed(1)} {sev.label}
          </div>
          {/* SLA vencido */}
          {slaVencido && !corrigido && (
            <span className="sla-badge">⏰ SLA vencido</span>
          )}
          {/* KEV */}
          {vuln.kev === true && (
            <span className="kev-badge">🔴 KEV</span>
          )}
        </div>

        <div className="vuln-card-tipo">{tipo}</div>

        {arquivo && (
          <div className="vuln-arquivo-linha">
            <span className="vuln-arquivo-texto">{arquivoDisplay}</span>
            {vuln.linha && <span className="vuln-arquivo-linha-num">L{vuln.linha}</span>}
          </div>
        )}

        {/* Tags de rastreabilidade */}
        {origens.length > 0 && (
          <div className="vuln-origens">
            {origens.map((o) => (
              <span key={o} className={`vuln-origem-tag origem-${(o || "").toLowerCase()}`}>
                {o}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="vuln-card-acoes">
        {/* Checkbox Corrigido */}
        {onCorrigir && (
          <label className="vuln-corrigido-label" onClick={(e) => e.stopPropagation()}>
            <input
              type="checkbox"
              className="vuln-corrigido-check"
              checked={corrigido}
              onChange={(e) => onCorrigir(vuln.id, e.target.checked)}
            />
            {corrigido ? "Corrigido ✓" : "Marcar corrigido"}
          </label>
        )}

        {/* Botão FP */}
        {onFP && !corrigido && (
          <button
            className="btn-fp"
            onClick={(e) => { e.stopPropagation(); onFP(vuln); }}
            title="Marcar como falso positivo"
          >
            FP
          </button>
        )}

        <button
          className={`btn-detalhes sev-btn-${sev.classe}`}
          onClick={() => setAberto(!aberto)}
        >
          {aberto ? "Ver menos ▲" : "Detalhes ▼"}
        </button>
      </div>

      {aberto && (
        <div className="vuln-card-corpo">
          {vuln.justificativa && (
            <div className="vuln-secao">
              <h4>Por que isso importa?</h4>
              <p>{vuln.justificativa}</p>
            </div>
          )}
          {vuln.recomendacao && (
            <div className="vuln-secao">
              <h4>Recomendação</h4>
              <p>{vuln.recomendacao}</p>
            </div>
          )}
          {vuln.kev === true && vuln.kev_data_adicao && (
            <div className="vuln-secao vuln-kev-info">
              <h4>🔴 CISA Known Exploited Vulnerability</h4>
              <p>Adicionado ao catálogo KEV em {vuln.kev_data_adicao}. Esta vulnerabilidade tem exploração ativa confirmada.</p>
            </div>
          )}
          <div className="vuln-secao">
            <h4>Correção sugerida</h4>
            {corr
              ? <pre className="vuln-detalhe-codigo">{vuln.correcao}</pre>
              : <p>Correção ainda não gerada pelo Ghost.</p>
            }
          </div>
        </div>
      )}
    </div>
  );
}
