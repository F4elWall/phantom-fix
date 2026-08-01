const CORE_URL = import.meta.env.VITE_CORE_URL || "http://localhost:8000";
const SPIRIT_URL = import.meta.env.VITE_SPIRIT_URL || "http://localhost:8001";

const CORE_HEADERS = {
  "ngrok-skip-browser-warning": "true",
};

export async function buscarRelatorio(protocolo) {
  const url = protocolo
    ? `${CORE_URL}/relatorio?protocolo=${encodeURIComponent(protocolo)}`
    : `${CORE_URL}/relatorio`;
  const resp = await fetch(url, { headers: CORE_HEADERS });
  if (!resp.ok) {
    if (resp.status === 404) return null;
    throw new Error("Core não respondeu");
  }
  return resp.json();
}

export async function listarResultados() {
  const resp = await fetch(`${CORE_URL}/resultados`, { headers: CORE_HEADERS });
  if (!resp.ok) throw new Error("Core não respondeu");
  return resp.json();
}

/** Lista histórico enriquecido (repo, data, total vulns). */
export async function listarHistorico() {
  const data = await listarResultados();
  const lista = data.resultados || [];
  const ricos = await Promise.all(
    lista.map(async (item) => {
      if (!item.relatorio) {
        return {
          protocolo: item.protocolo,
          repositorio: "—",
          processado_em: null,
          total: null,
          completo: false,
        };
      }
      try {
        const rel = await buscarRelatorio(item.protocolo);
        return {
          protocolo: item.protocolo,
          repositorio: rel?.repositorio || "—",
          processado_em: rel?.processado_em || rel?.analisado_em || null,
          total: rel?.total_encontrado ?? rel?.vulnerabilidades?.length ?? 0,
          completo: true,
        };
      } catch {
        return {
          protocolo: item.protocolo,
          repositorio: "—",
          processado_em: null,
          total: null,
          completo: false,
        };
      }
    })
  );
  return ricos.sort((a, b) => {
    const da = a.processado_em ? new Date(a.processado_em).getTime() : 0;
    const db = b.processado_em ? new Date(b.processado_em).getTime() : 0;
    return db - da;
  });
}

export async function statusScan(protocolo) {
  const resp = await fetch(`${CORE_URL}/scan/${encodeURIComponent(protocolo)}/status`, {
    headers: CORE_HEADERS,
  });
  if (!resp.ok) {
    if (resp.status === 404) return null;
    throw new Error("Core não respondeu");
  }
  return resp.json();
}

export async function statusCore() {
  const resp = await fetch(`${CORE_URL}/status`, { headers: CORE_HEADERS });
  if (!resp.ok) throw new Error("Core não respondeu");
  return resp.json();
}

/** Descobre se há job em andamento. */
export async function detectarScanAtivo() {
  try {
    const data = await listarResultados();
    const lista = data.resultados || [];
    for (const item of [...lista].reverse()) {
      const job = await statusScan(item.protocolo);
      if (job && job.status && !["concluido", "erro"].includes(job.status)) {
        return { protocolo: item.protocolo, ...job };
      }
    }
  } catch {
    /* ignore */
  }
  return null;
}

export async function perguntarSpirit(pergunta) {
  const resp = await fetch(`${SPIRIT_URL}/perguntar`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pergunta }),
  });
  if (!resp.ok) throw new Error("Spirit não respondeu");
  return resp.json();
}
