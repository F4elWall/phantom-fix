import VulnCard from "./VulnCard";

const QUANTIDADE_PRIORITARIA = 3;

export default function ResultsView({ relatorio }) {
  const vulns = relatorio.vulnerabilidades || [];
  const ordenadas = [...vulns].sort(
    (a, b) => (Number(b.score) || 0) - (Number(a.score) || 0)
  );
  const prioritarias = ordenadas.slice(0, QUANTIDADE_PRIORITARIA);
  const restantes = ordenadas.slice(QUANTIDADE_PRIORITARIA);

  return (
    <div className="tela-resultados">
      <div className="resumo-analise">
        <span className="resumo-check">Análise concluída ✓</span>
        <span className="resumo-total">
          {relatorio.total_encontrado ?? vulns.length} vulnerabilidades
        </span>
      </div>

      {relatorio.repositorio && (
        <p className="repo-info">
          Repositório: <strong>{relatorio.repositorio}</strong>
          {relatorio.protocolo && ` · Protocolo: ${relatorio.protocolo}`}
        </p>
      )}

      <div className="prioridade-hero">
        <span className="prioridade-label">Sua prioridade agora</span>
        <h2>
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
          <summary>
            Outras {restantes.length} vulnerabilidades foram analisadas, mas não
            exigem atenção imediata.
          </summary>
          <div className="lista-restantes-corpo">
            {restantes.map((v, i) => (
              <VulnCard
                key={v.id || i}
                vuln={v}
                posicao={QUANTIDADE_PRIORITARIA + i + 1}
              />
            ))}
          </div>
        </details>
      )}
    </div>
  );
}