import { useCallback, useEffect, useState } from "react";
import Landing from "./components/Landing";
import Login from "./components/Login";
import SignUp from "./components/SignUp";
import Welcome from "./components/Welcome";
import Home from "./components/Home";
import ResultsView from "./components/ResultsView";
import SpiritChat from "./components/SpiritChat";
import PipelineView from "./components/PipelineView";
import HistoricoView from "./components/HistoricoView";
import { detectarScanAtivo } from "./api";
import "./App.css";

/**
 * Telas possíveis:
 *  auth     → login ou signup (não autenticado)
 *  signup   → formulário de criar conta
 *  welcome  → pós-signup: exibe token + instrução de vínculo
 *  home     → carregando último relatório ou tela vazia
 *  pipeline → acompanhar scan em andamento
 *  results  → relatório de vulnerabilidades
 *  historico→ lista de scans anteriores
 */

function sessaoSalva() {
  return !!localStorage.getItem("session_token");
}

export default function App() {
  // Se já havia sessão salva, pula direto pro dashboard
const dadosSalvos = sessaoSalva() ? {
  token: localStorage.getItem("user_token"),
  nome: localStorage.getItem("user_nome"),
  client_linked: localStorage.getItem("client_linked") === "true",
} : null;

const [tela, setTela] = useState(
  !dadosSalvos ? "landing" :
  !dadosSalvos.client_linked ? "welcome" : "home"
);
const [usuarioAuth, setUsuarioAuth] = useState(dadosSalvos);
  const [relatorio, setRelatorio] = useState(null);
  const [protocoloPipeline, setProtocoloPipeline] = useState(null);
  const [scanState, setScanState] = useState({ tipo: "concluido" });
  const [spiritAberto, setSpiritAberto] = useState(true);

  // ── Polling de scan ativo (só quando no dashboard) ──────────────────────
  const logado = !["auth", "signup", "welcome"].includes(tela);

  useEffect(() => {
    if (!logado) return;
    let cancel = false;

    async function tick() {
      try {
        const ativo = await detectarScanAtivo();
        if (cancel) return;
        if (ativo) {
          setScanState({ tipo: "rodando", protocolo: ativo.protocolo, repositorio: ativo.repositorio });
        } else {
          setScanState({ tipo: "concluido" });
        }
      } catch { /* ignore */ }
    }

    tick();
    const id = setInterval(tick, 4000);
    return () => { cancel = true; clearInterval(id); };
  }, [logado]);

  // ── Handlers ─────────────────────────────────────────────────────────────

  function sair() {
    localStorage.removeItem("session_token");
    localStorage.removeItem("user_nome");
    localStorage.removeItem("user_token");
    setRelatorio(null);
    setProtocoloPipeline(null);
    setUsuarioAuth(null);
    setTela("landing");
  }

function onLogin(dados) {
  setUsuarioAuth(dados);
  localStorage.setItem("client_linked", dados.client_linked ? "true" : "false");
  setTela(dados.client_linked ? "home" : "welcome");
}

function onCriouConta(dados) {
  setUsuarioAuth(dados);
  localStorage.setItem("client_linked", "false");
  setTela("welcome");
}

  function onAcessarDashboard() {
    setTela("home");
  }

  function onRelatorioCarregado(dados) {
    setRelatorio(dados);
    setTela("results");
  }

  const abrirPipeline = useCallback((protocolo) => {
    if (!protocolo) return;
    setProtocoloPipeline(protocolo);
    setTela("pipeline");
  }, []);

  function onConcluidoPipeline(rel) {
    setRelatorio(rel);
    setTela("results");
    setScanState({ tipo: "concluido" });
  }

  // ── Roteamento ────────────────────────────────────────────────────────────

  if (tela === "landing") {
    return (
      <Landing
        onEntrar={() => setTela("auth")}
        onCriarConta={() => setTela("signup")}
      />
    );
  }

  if (tela === "auth") {
    return (
      <Login
        onLogin={onLogin}
        onIrParaSignup={() => setTela("signup")}
        onVoltar={() => setTela("landing")}
      />
    );
  }

  if (tela === "signup") {
    return (
      <SignUp
        onCriouConta={onCriouConta}
        onIrParaLogin={() => setTela("auth")}
        onVoltar={() => setTela("landing")}
      />
    );
  }

  if (tela === "welcome") {
    // usuarioAuth pode ser null após F5 — monta um objeto mínimo do localStorage
    const usuarioWelcome = usuarioAuth || {
      token: localStorage.getItem("user_token") || "",
      nome:  localStorage.getItem("user_nome")  || "Usuário",
      client_linked: false,
    };
    return (
      <Welcome
        usuario={usuarioWelcome}
        onAcessarDashboard={onAcessarDashboard}
        onSair={sair}
      />
    );
  }

  const dashboardClass = `dashboard ${spiritAberto ? "" : "spirit-recolhido"}`;

  if (tela === "pipeline" && protocoloPipeline) {
    return (
      <div className={dashboardClass}>
        <PipelineView
          protocolo={protocoloPipeline}
          scanState={scanState}
          spiritAberto={spiritAberto}
          onToggleSpirit={() => setSpiritAberto((v) => !v)}
          onVerHistorico={() => setTela("historico")}
          onConcluido={onConcluidoPipeline}
          onSair={sair}
          onAbrirPipeline={abrirPipeline}
        />
        {spiritAberto && <SpiritChat />}
      </div>
    );
  }

  if (tela === "historico") {
    return (
      <div className={dashboardClass}>
        <HistoricoView
          scanState={scanState}
          spiritAberto={spiritAberto}
          onToggleSpirit={() => setSpiritAberto((v) => !v)}
          onAbrirPipeline={abrirPipeline}
          onSelecionar={(rel) => { setRelatorio(rel); setTela("results"); }}
          onVoltar={() => setTela(relatorio ? "results" : "home")}
          onSair={sair}
        />
        {spiritAberto && <SpiritChat />}
      </div>
    );
  }

  if (!relatorio || tela === "home") {
    return (
      <div className="app-shell">
        <Home onRelatorioCarregado={onRelatorioCarregado} />
      </div>
    );
  }

  return (
    <div className={dashboardClass}>
      <ResultsView
        relatorio={relatorio}
        scanState={scanState}
        spiritAberto={spiritAberto}
        onToggleSpirit={() => setSpiritAberto((v) => !v)}
        onVerHistorico={() => setTela("historico")}
        onAbrirPipeline={abrirPipeline}
        onSair={sair}
      />
      {spiritAberto && <SpiritChat />}
    </div>
  );
}
