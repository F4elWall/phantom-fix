import { useState } from "react";
import { temCorrecao } from "../utils";

function severidade(score) {
  const s = Number(score) || 0;
  if (s >= 9) return { label: "Crítica", classe: "critica" };
  if (s >= 7) return { label: "Alta",    classe: "alta"    };
  if (s >= 4) return { label: "Média",   classe: "media"   };
  return           { label: "Baixa",   classe: "baixa"   };
}

export default function VulnCard({ vuln, posicao }) {
  const [aberto, setAberto] = useState(false);
  const score  = Number(vuln.score) || 0;
  const sev    = severidade(score);
  const corr   = temCorrecao(vuln);

  const tipo = (vuln.tipo || "desconhecido").replace(/^CWE-\d+\s*/i, "");
  const arquivo = vuln.arquivo || "";
  const arquivoDisplay = arquivo.length > 28 ? "…" + arquivo.slice(-25) : arquivo;

  return (
    <div className={`vuln-card sev-card-${sev.classe}`}>
      <div className="vuln-card-topo">
        <div className="vuln-card-num-sev">
          <div className="vuln-card-num">{posicao}</div>
          <div className={`vuln-card-sev-badge sev-${sev.classe}`}>
            <span className="dot" />
            {score.toFixed(1)} {sev.label}
          </div>
        </div>

        <div className="vuln-card-tipo">{tipo}</div>

        {arquivo && (
          <div className="vuln-arquivo-linha">
            <span className="vuln-arquivo-texto">{arquivoDisplay}</span>
            {vuln.linha && <span className="vuln-arquivo-linha-num">L{vuln.linha}</span>}
          </div>
        )}
      </div>

      <div className="vuln-card-acoes">
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
