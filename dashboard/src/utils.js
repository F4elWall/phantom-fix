export function mapearImpacto(score) {
  if (score >= 8) return "Alto";
  if (score >= 5) return "Médio";
  return "Baixo";
}

export function classeImpacto(score) {
  if (score >= 8) return "alto";
  if (score >= 5) return "medio";
  return "baixo";
}

export function estimarTempo(vuln) {
  return "15 minutos";
}

export function temCorrecao(vuln) {
  return (
    Boolean(vuln.correcao) &&
    vuln.correcao !== "Ghost não disponível" &&
    vuln.correcao !== "Correção indisponível"
  );
}