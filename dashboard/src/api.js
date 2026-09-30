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

export async function solicitarReset(email) {
  const resp = await fetch(`${CORE_URL}/auth/solicitar-reset`, {
    method: "POST",
    headers: { ...BASE_HEADERS, "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.detail || "Erro ao solicitar reset");
  return data;
}

export async function confirmarReset(token, nova_senha) {
  const resp = await fetch(`${CORE_URL}/auth/confirmar-reset`, {
    method: "POST",
    headers: { ...BASE_HEADERS, "Content-Type": "application/json" },
    body: JSON.stringify({ token, nova_senha }),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.detail || "Erro ao redefinir senha");
  return data;
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

export async function buscarRelatorioExecutivo(protocolo) {
  const url = protocolo
    ? `${CORE_URL}/relatorio-executivo?protocolo=${encodeURIComponent(protocolo)}`
    : `${CORE_URL}/relatorio-executivo`;
  const resp = await fetch(url, { headers: authHeaders() });
  if (!resp.ok) {
    if (resp.status === 404) return null;
    throw new Error("Core não respondeu");
  }
  return resp.json();
}

export async function marcarRelatorioLido(protocolo) {
  if (!protocolo) throw new Error("Protocolo obrigatório");
  const resp = await fetch(
    `${CORE_URL}/relatorio-executivo/${encodeURIComponent(protocolo)}/lido`,
    {
      method: "POST",
      headers: authHeaders(),
    }
  );
  if (!resp.ok) throw new Error("Não foi possível marcar como lido");
  return resp.json();
}

// ── Vault Obsidian ────────────────────────────────────────────────────────────

export async function statusVault(protocolo) {
  const resp = await fetch(
    `${CORE_URL}/vault/${encodeURIComponent(protocolo)}/status`,
    { headers: authHeaders() }
  );
  if (!resp.ok) return { vault_pronto: false };
  return resp.json();
}

export function urlDownloadVault(protocolo) {
  const token = localStorage.getItem("session_token");
  return `${CORE_URL}/vault/${encodeURIComponent(protocolo)}/download?token=${token}`;
}

export async function baixarVault(protocolo) {
  const resp = await fetch(
    `${CORE_URL}/vault/${encodeURIComponent(protocolo)}/download`,
    { headers: authHeaders() }
  );
  if (!resp.ok) throw new Error("Vault não disponível");
  const blob = await resp.blob();
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `vault-${protocolo}.zip`;
  a.click();
  URL.revokeObjectURL(url);
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

// ── Postura ───────────────────────────────────────────────────────────────────

/**
 * Busca as últimas 10 entradas do histórico e retorna métricas calculadas
 * por scan: score médio (PhantomScore), totais por severidade e referência
 * às vulnerabilidades brutas (para cálculo de recorrentes).
 * Não depende de nenhum endpoint novo — tudo derivado de listarHistorico +
 * buscarRelatorio existentes.
 */
export async function buscarPostura() {
  const historico = await listarHistorico();
  const ultimas = historico.filter((e) => e.completo).slice(0, 10);

  const entradas = await Promise.all(
    ultimas.map(async (item) => {
      try {
        const rel = await buscarRelatorio(item.protocolo);
        const vulns = rel?.vulnerabilidades || [];
        const score =
          vulns.length
            ? vulns.reduce((acc, v) => acc + (Number(v.score) || 0), 0) / vulns.length
            : 0;
        return {
          protocolo:    item.protocolo,
          repositorio:  rel?.repositorio || item.repositorio || "—",
          processado_em: rel?.processado_em || rel?.analisado_em || item.processado_em,
          score:        parseFloat(score.toFixed(1)),
          total:        vulns.length,
          criticas:     vulns.filter((v) => Number(v.score) >= 9).length,
          altas:        vulns.filter((v) => { const s = Number(v.score); return s >= 7 && s < 9; }).length,
          medias:       vulns.filter((v) => { const s = Number(v.score); return s >= 4 && s < 7; }).length,
          baixas:       vulns.filter((v) => Number(v.score) < 4).length,
          vulnerabilidades: vulns,
        };
      } catch {
        return null;
      }
    })
  );

  return entradas.filter(Boolean);
}

// ── Projeto (Nexus) ───────────────────────────────────────────────────────────
// Adicione estas funções ao final do api.js existente.

export async function buscarProjeto() {
  const resp = await fetch(`${CORE_URL}/projeto`, {
    headers: authHeaders(),
  });
  if (resp.status === 404) return null;
  if (!resp.ok) throw new Error("Core não respondeu");
  return resp.json();
}

export async function salvarProjeto(dados) {
  const resp = await fetch(`${CORE_URL}/projeto`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(dados),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.detail || "Erro ao salvar projeto");
  return data;
}

export async function baixarConfiguracoes() {
  const resp = await fetch(`${CORE_URL}/projeto/configuracoes.json`, {
    headers: authHeaders(),
  });
  if (!resp.ok) throw new Error("Projeto não encontrado");
  const data = await resp.json();
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "configuracoes_scan.json";
  a.click();
  URL.revokeObjectURL(a.href);
  return data;
}

export async function scanGithub({ githubToken, repositorio, clientToken }) {
  const resp = await fetch(`${CORE_URL}/scan/github`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({
      token: githubToken,
      repositorio,
      client_token: clientToken,
    }),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.detail || "Erro ao iniciar scan GitHub");
  return data;
}
