import { useState } from "react";
import {
  classeImpacto,
  estimarTempo,
  mapearImpacto,
  temCorrecao,
} from "../utils";

export default function VulnCard({ vuln, posicao }) {
  const [aberto, setAberto] = useState(false);
  const score = Number(vuln.score) || 0;
  const impacto = mapearImpacto(score);
  const tempo = estimarTempo(vuln);

  return (
    <div className={`vuln-card impacto-${classeImpacto(score)}`}>
      <div className="vuln-card-topo">
        <span className="vuln-posicao">{posicao}</span>
        <div className="vuln-titulo-bloco">
          <span className="vuln-tipo">{vuln.tipo || "desconhecido"}</span>
          <span className="vuln-arquivo">{vuln.arquivo || ""}</span>
        </div>
        <div className="vuln-meta">
          <span className="vuln-score">{score.toFixed(1)}</span>
          <span className="vuln-impacto">{impacto}</span>
        </div>
      </div>

      <div className="vuln-card-resumo">
        <span>Tempo estimado: {tempo}</span>
        {temCorrecao(vuln) && (
          <span className="badge-correcao">Correção disponível</span>
        )}
      </div>

      <button className="vuln-card-toggle" onClick={() => setAberto(!aberto)}>
        {aberto ? "Ver menos ▲" : "Ver detalhes ▼"}
      </button>

      {aberto && (
        <div className="vuln-card-corpo">
          <div className="vuln-secao">
            <h4>Por que isso importa?</h4>
            <p>{vuln.justificativa || vuln.descricao || "Sem justificativa."}</p>
          </div>
          <div className="vuln-secao">
            <h4>Correção sugerida</h4>
            <p>
              {temCorrecao(vuln)
                ? vuln.correcao
                : "Correção ainda não gerada pelo Ghost."}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}