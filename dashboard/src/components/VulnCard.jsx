import { useState } from "react";
import {
  classeImpacto,
  estimarTempo,
  mapearImpacto,
  temCorrecao,
} from "../utils";

export default function VulnCard({ vuln, posicao, compacto }) {
  const [aberto, setAberto] = useState(false);
  const score = Number(vuln.score) || 0;
  const impacto = mapearImpacto(score);
  const classeImp = classeImpacto(score);
  const tempo = estimarTempo(vuln);
  const correcao = temCorrecao(vuln);

  const tipoParts = (vuln.tipo || "desconhecido").split(" ");
  const cweId = tipoParts[0]?.startsWith("CWE") ? tipoParts[0] : null;
  const tipoNome = cweId ? tipoParts.slice(1).join(" ") : vuln.tipo;

  const arquivo = vuln.arquivo || "";
  const arquivoDisplay = arquivo.length > 36 ? "…" + arquivo.slice(-33) : arquivo;

  return (
    <div className={`vuln-card impacto-${classeImp}`}>
      <div className="vuln-card-topo">
        <div className="vuln-card-header">
          <div className="vuln-numero-score">
            <div className="vuln-numero">{posicao}</div>
            <div className={`vuln-score-badge ${classeImp}`}>
              <span className="dot" />
              {score.toFixed(1)} {impacto}
            </div>
          </div>
          {correcao && !compacto && (
            <span className="vuln-badge-autofix">⚡ Auto-fix</span>
          )}
        </div>

        {vuln.biblioteca && (
          <div className="vuln-lib">
            lib: <strong>{vuln.biblioteca}</strong>
          </div>
        )}

        {arquivo && (
          <div className="vuln-arquivo-linha">
            <span className="vuln-arquivo-texto">{arquivoDisplay}</span>
          </div>
        )}

        {!compacto && (
          <div className="vuln-cwe">
            {cweId && <strong>tipo {cweId}</strong>}
            {tipoNome && <span className="vuln-cwe-tipo">{tipoNome}</span>}
          </div>
        )}
      </div>

      <div className="vuln-card-acoes">
        {!compacto && (
          <button className="btn-criar-pr" disabled title="Em breve">
            Criar PR de Correção (Em Breve)
          </button>
        )}
        <button
          className="btn-detalhes"
          onClick={() => setAberto(!aberto)}
        >
          {aberto ? "Ver menos ▲" : "Ver Detalhes ▼"}
        </button>
      </div>

      {aberto && (
        <div className="vuln-card-corpo">
          <div className="vuln-secao">
            <h4>Por que isso importa?</h4>
            <p>{vuln.justificativa || vuln.descricao || "Sem justificativa."}</p>
          </div>
          <div className="vuln-secao">
            <h4>Correção sugerida</h4>
            <p>
              {correcao
                ? vuln.correcao
                : "Correção ainda não gerada pelo Ghost."}
            </p>
          </div>
          <div className="vuln-secao">
            <h4>Tempo estimado</h4>
            <p>{tempo}</p>
          </div>
        </div>
      )}
    </div>
  );
}