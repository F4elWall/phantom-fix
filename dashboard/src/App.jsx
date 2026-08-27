//Autora e revisão: Giovana Esmelardi

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
import RelatorioExecutivoView from "./components/RelatorioExecutivoView";
import "./App.css";
import { detectarScanAtivo, buscarRelatorio, buscarRelatorioExecutivo } from "./api";

/**
 * Telas possíveis:
 *  landing          → página inicial
 *  auth             → login
 *  signup           → criar conta
 *  welcome          → pós-signup: exibe token + instrução de vínculo
 *  home             → carregando último relatório ou tela vazia
 *  pipeline         → acompanhar scan em andamento
 *  relatorio_executivo → relatório executivo gerado pelo Spirit
 *  results          → relatório de vulnerabilidades (dashboard completo)
 *  historico        → lista de scans anteriores
 */

function sessaoSalva() {
  return !!localStorage.getItem("session_token");
}

export default function App() {
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
  const [relatorioExecutivo, setRelatorioExecutivo] = useState(null);
  const [protocoloPipeline, setProtocoloPipeline] = useState(null);
  const [scanState, setScanState] = useState({ tipo: "concluido" });
  const [relatorioExecutivoNaoLido, setRelatorioExecutivoNaoLido] = useState(false);
  const [spiritAberto, setSpiritAberto] = useState(true);

  // ── Polling de scan ativo ─────────────────────────────────────────────────
  const logado = !["auth", "signup", "welcome", "landing"].includes(tela);

  useEffect(() => {
    if (!logado) return;
    let cancel = false;

    async function tick() {
      try {
        const ativo = await detectarScanAtivo();
        if (cancel) return;

        if (ativo) {
          setScanState({ tipo: "rodando", protocolo: ativo.protocolo, repositorio: ativo.repositorio });

          // FIX: só redireciona para o executivo se ainda não estamos nessa tela
          if (ativo.relatorio_executivo_pronto && tela !== "relatorio_executivo") {
            const exec = await buscarRelatorioExecutivo(ativo.protocolo);
            if (exec && !cancel) {
              setRelatorioExecutivo(exec);
              setRelatorioExecutivoNaoLido(true);
              setTela("relatorio_executivo");
            }
          }
        } else {
          setScanState({ tipo: "concluido" });
        }
      } catch { /* ignore */ }
    }

    tick();
    const id = setInterval(tick, 4000);
    return () => { cancel = true; clearInterval(id); };
  }, [logado, tela]);

  // ── Recarrega relatório quando scan conclui ───────────────────────────────
  useEffect(() => {
    if (scanState.tipo === "concluido" && tela === "results") {
      buscarRelatorio().then((rel) => {
        if (rel) setRelatorio(rel);
      }).catch(() => {});
    }
  }, [scanState.tipo]);

  // ── Handlers ──────────────────────────────────────────────────────────────

  function sair() {
    localStorage.removeItem("session_token");
    localStorage.removeItem("user_nome");
    localStorage.removeItem("user_token");
    localStorage.removeItem("client_linked");
    setRelatorio(null);
    setRelatorioExecutivo(null);
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

  // FIX — busca o relatório executivo no momento em que o pipeline conclui,
  // antes de decidir para qual tela ir. Antes, relatorioExecutivo era sempre
  // null aqui porque o polling ainda não havia rodado após a conclusão.
  async function onConcluidoPipeline(rel) {
    setRelatorio(rel);
    setScanState({ tipo: "concluido" });

    try {
      const exec = await buscarRelatorioExecutivo(rel?.protocolo);
      if (exec) {
        setRelatorioExecutivo(exec);
        setRelatorioExecutivoNaoLido(true);
        setTela("relatorio_executivo");
        return;
      }
    } catch { /* se Spirit falhou, segue para results normalmente */ }

    setTela("results");
  }

  function onAcessarDashboardCompleto() {
    setRelatorioExecutivoNaoLido(false);
    setTela(relatorio ? "results" : "home");
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
  const scanStateComExecutivo = { ...scanState, relatorioExecutivoNaoLido };

  if (tela === "relatorio_executivo" && relatorioExecutivo) {
    return (
      <RelatorioExecutivoView
        relatorio={relatorioExecutivo}
        onAcessarDashboard={onAcessarDashboardCompleto}
      />
    );
  }

  if (tela === "pipeline" && protocoloPipeline) {
    return (
      <div className={dashboardClass}>
        <PipelineView
          protocolo={protocoloPipeline}
          scanState={scanStateComExecutivo}
          spiritAberto={spiritAberto}
          onToggleSpirit={() => setSpiritAberto((v) => !v)}
          onVerHistorico={() => setTela("historico")}
          onConcluido={onConcluidoPipeline}
          onSair={sair}
          onAbrirPipeline={abrirPipeline}
        />
        {spiritAberto && <SpiritChat relatorio={relatorio} />}
      </div>
    );
  }

  if (tela === "historico") {
    return (
      <div className={dashboardClass}>
        <HistoricoView
          scanState={scanStateComExecutivo}
          spiritAberto={spiritAberto}
          onToggleSpirit={() => setSpiritAberto((v) => !v)}
          onAbrirPipeline={abrirPipeline}
          onSelecionar={(rel) => { setRelatorio(rel); setTela("results"); }}
          onVoltar={() => setTela(relatorio ? "results" : "home")}
          onSair={sair}
        />
        {spiritAberto && <SpiritChat relatorio={relatorio} />}
      </div>
    );
  }

  if (!relatorio || tela === "home") {
    return (
      <div className="app-shell">
        <Home
          onRelatorioCarregado={onRelatorioCarregado}
          onAbrirPipeline={abrirPipeline}
          onSair={sair}
        />
      </div>
    );
  }

  return (
    <div className={dashboardClass}>
      <ResultsView
        relatorio={relatorio}
        scanState={scanStateComExecutivo}
        spiritAberto={spiritAberto}
        onToggleSpirit={() => setSpiritAberto((v) => !v)}
        onVerHistorico={() => setTela("historico")}
        onAbrirPipeline={abrirPipeline}
        onSair={sair}
        onVerRelatorioExecutivo={relatorioExecutivo ? () => setTela("relatorio_executivo") : null}
      />
      {spiritAberto && <SpiritChat relatorio={relatorio} />}
    </div>
  );
}
