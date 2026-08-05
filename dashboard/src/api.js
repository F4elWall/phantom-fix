const CORE_URL = import.meta.env.VITE_CORE_URL || "http://localhost:8000";
const SPIRIT_URL = import.meta.env.VITE_SPIRIT_URL || "http://localhost:8001";

const BASE_HEADERS = {
  "ngrok-skip-browser-warning": "true",
};

function authHeaders() {
  const token = localStorage.getItem("session_token");
  return {
    ...BASE_HEADERS,
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export async function signup({ nome, email, senha }) {
  const resp = await fetch(`${CORE_URL}/auth/signup`, {
    method: "POST",
    headers: { ...BASE_HEADERS, "Content-Type": "application/json" },
    body: JSON.stringify({ nome, email, senha }),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.detail || "Erro ao criar conta");
  return data;
}

export async function login({ email, senha }) {
  const resp = await fetch(`${CORE_URL}/auth/login`, {
    method: "POST",
    headers: { ...BASE_HEADERS, "Content-Type": "application/json" },
    body: JSON.stringify({ email, senha }),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.detail || "E-mail ou senha incorretos");
  return data;
}

export async function logout() {
  await fetch(`${CORE_URL}/auth/logout`, {
    method: "POST",
    headers: authHeaders(),
  });
  localStorage.removeItem("session_token");
}

export async function checkLink() {
  const resp = await fetch(`${CORE_URL}/auth/check-link`, {
    headers: authHeaders(),
  });
  if (!resp.ok) return { client_linked: false };
  return resp.json();
}

export async function regenToken() {
  const resp = await fetch(`${CORE_URL}/auth/regen-token`, {
    method: "POST",
    headers: authHeaders(),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.detail || "Erro ao gerar novo token");
  return data;
}

// ── Relatórios ────────────────────────────────────────────────────────────────

export async function buscarRelatorio(protocolo) {
  const url = protocolo
    ? `${CORE_URL}/relatorio?protocolo=${encodeURIComponent(protocolo)}`
    : `${CORE_URL}/relatorio`;
  const resp = await fetch(url, { headers: authHeaders() });
  if (!resp.ok) {
    if (resp.status === 404) return null;
    throw new Error("Core não respondeu");
  }
  return resp.json();
}

export async function listarResultados() {
  const resp = await fetch(`${CORE_URL}/resultados`, { headers: authHeaders() });
  if (!resp.ok) throw new Error("Core não respondeu");
  return resp.json();
}

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
  const resp = await fetch(
    `${CORE_URL}/scan/${encodeURIComponent(protocolo)}/status`,
    { headers: authHeaders() }
  );
  if (!resp.ok) {
    if (resp.status === 404) return null;
    throw new Error("Core não respondeu");
  }
  return resp.json();
}

export async function statusCore() {
  const resp = await fetch(`${CORE_URL}/status`, { headers: authHeaders() });
  if (!resp.ok) throw new Error("Core não respondeu");
  return resp.json();
}

export async function detectarScanAtivo() {
  try {
    const resp = await fetch(`${CORE_URL}/scan/ativo`, { headers: authHeaders() });
    if (!resp.ok) return null;
    const data = await resp.json();
    return data;
  } catch {
    return null;
  }
}

export async function perguntarSpirit(pergunta, relatorio = null) {
  const resp = await fetch(`${SPIRIT_URL}/perguntar`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pergunta, relatorio }),
  });
  if (!resp.ok) throw new Error("Spirit não respondeu");
  return resp.json();
}
