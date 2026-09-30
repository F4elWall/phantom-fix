//Autora e revisão: Giovana Esmelardi

import { useCallback, useEffect, useState, createContext, useContext } from "react";
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

// --- [MODIFICAÇÃO]: Criado ThemeContext para gerenciamento de tema ---
const ThemeContext = createContext();
export const useTheme = () => useContext(ThemeContext);

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
  // --- [MODIFICAÇÃO]: Estado para o tema ---

  const [tema, setTema] = useState(localStorage.getItem("theme") || "neon");

  const toggleTema = () => {
    setTema((prev) => {
      if (prev === "neon")  return "dark";
      if (prev === "dark")  return "light";
      return "neon";
    });
  };

  // --- [MODIFICAÇÃO]: Sincronizar tema com o atributo 'data-theme' no documento ---
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", tema);
    localStorage.setItem("theme", tema);
  }, [tema]);

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

  // --- [MODIFICAÇÃO]: Envolver tudo no ThemeContext.Provider ---
  return (
    <ThemeContext.Provider value={{ tema, toggleTema }}>
      {tela === "landing" && (
        <Landing
          onEntrar={() => setTela("auth")}
          onCriarConta={() => setTela("signup")}
        />
      )}

      {tela === "auth" && (
        <Login
          onLogin={onLogin}
          onIrParaSignup={() => setTela("signup")}
          onVoltar={() => setTela("landing")}
        />
      )}

      {tela === "signup" && (
        <SignUp
          onCriouConta={onCriouConta}
          onIrParaLogin={() => setTela("auth")}
          onVoltar={() => setTela("landing")}
        />
      )}

      {tela === "welcome" && (
        <Welcome
          usuario={usuarioAuth || {
            token: localStorage.getItem("user_token") || "",
            nome:  localStorage.getItem("user_nome")  || "Usuário",
            client_linked: false,
          }}
          onAcessarDashboard={onAcessarDashboard}
          onSair={sair}
        />
      )}

      {tela === "relatorio_executivo" && relatorioExecutivo && (
        <RelatorioExecutivoView
          relatorio={relatorioExecutivo}
          onAcessarDashboard={onAcessarDashboardCompleto}
        />
      )}

      {tela === "pipeline" && protocoloPipeline && (
        <div className={`dashboard ${spiritAberto ? "" : "spirit-recolhido"}`}>
          <PipelineView
            protocolo={protocoloPipeline}
            scanState={{ ...scanState, relatorioExecutivoNaoLido }}
            spiritAberto={spiritAberto}
            onToggleSpirit={() => setSpiritAberto((v) => !v)}
            onVerHistorico={() => setTela("historico")}
            onConcluido={onConcluidoPipeline}
            onSair={sair}
            onAbrirPipeline={abrirPipeline}
          />
          {spiritAberto && <SpiritChat relatorio={relatorio} />}
        </div>
      )}

      {tela === "historico" && (
        <div className={`dashboard ${spiritAberto ? "" : "spirit-recolhido"}`}>
          <HistoricoView
            scanState={{ ...scanState, relatorioExecutivoNaoLido }}
            spiritAberto={spiritAberto}
            onToggleSpirit={() => setSpiritAberto((v) => !v)}
            onAbrirPipeline={abrirPipeline}
            onSelecionar={(rel) => { setRelatorio(rel); setTela("results"); }}
            onVoltar={() => setTela(relatorio ? "results" : "home")}
            onSair={sair}
          />
          {spiritAberto && <SpiritChat relatorio={relatorio} />}
        </div>
      )}

      {(!relatorio || tela === "home") && tela !== "landing" && tela !== "auth" && tela !== "signup" && tela !== "welcome" && tela !== "relatorio_executivo" && tela !== "pipeline" && tela !== "historico" && (
        <div className="app-shell">
          <Home
            onRelatorioCarregado={onRelatorioCarregado}
            onAbrirPipeline={abrirPipeline}
            onSair={sair}
          />
        </div>
      )}

      {tela === "results" && (
        <div className={`dashboard ${spiritAberto ? "" : "spirit-recolhido"}`}>
          <ResultsView
            relatorio={relatorio}
            scanState={{ ...scanState, relatorioExecutivoNaoLido }}
            spiritAberto={spiritAberto}
            onToggleSpirit={() => setSpiritAberto((v) => !v)}
            onVerHistorico={() => setTela("historico")}
            onAbrirPipeline={abrirPipeline}
            onSair={sair}
            onVerRelatorioExecutivo={relatorioExecutivo ? () => setTela("relatorio_executivo") : null}
          />
          {spiritAberto && <SpiritChat relatorio={relatorio} />}
        </div>
      )}
    </ThemeContext.Provider>
  );
}
