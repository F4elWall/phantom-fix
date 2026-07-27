const CORE_URL   = import.meta.env.VITE_CORE_URL   || "http://localhost:8000";
const SPIRIT_URL = import.meta.env.VITE_SPIRIT_URL || "http://localhost:8001";

const NGROK_HEADERS = {
  "ngrok-skip-browser-warning": "true",
};

export async function buscarRelatorio() {
  const resp = await fetch(`${CORE_URL}/relatorio`, {
    headers: NGROK_HEADERS,
  });
  if (!resp.ok) {
    if (resp.status === 404) return null;
    throw new Error("Core não respondeu");
  }
  return resp.json();
}

export async function listarResultados() {
  const resp = await fetch(`${CORE_URL}/resultados`, {
    headers: NGROK_HEADERS,
  });
  if (!resp.ok) throw new Error("Core não respondeu");
  return resp.json();
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
