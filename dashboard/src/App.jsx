{/*# PhantomFix — Copyright (C) 2025–2026 Rafael Pedro, Bernardo Coroa,
   # Giovanna Esmelardi, Gustavo Enrique
   # SPDX-License-Identifier: GPL-3.0-or-later
   # Licenciado sob a GNU GPL v3. Veja LICENSE.md na raiz do repositório.*/}

//Autora e revisão: Giovana Esmelardi

import { useCallback, useEffect, useState, createContext, useContext } from "react";
import Landing from "./components/Landing";
import Login from "./components/Login";
import SignUp from "./components/SignUp";
import Welcome from "./components/Welcome";
import Onboarding from "./components/Onboarding";
import PosturaView from "./components/PosturaView";
import ResultsView from "./components/ResultsView";
import SpiritChat from "./components/SpiritChat";
import PipelineView from "./components/PipelineView";
import HistoricoView from "./components/HistoricoView";
import RelatorioExecutivoView from "./components/RelatorioExecutivoView";
import RecuperarSenha from "./components/RecuperarSenha";
import ProjetoView from "./components/ProjetoView";
import "./App.css";
import { detectarScanAtivo, buscarRelatorio, buscarRelatorioExecutivo, buscarProjeto } from "./api";

// --- ThemeContext ---
const ThemeContext = createContext();
export const useTheme = () => useContext(ThemeContext);

// --- NavContext: permite que Topbar navegue sem prop drilling ---
const NavContext = createContext();
export const useNav = () => useContext(NavContext);

/**
 * Telas possíveis:
 *  landing          → página inicial
 *  auth             → login
 *  signup           → criar conta
 *  onboarding       → pós-signup: criar o 1º projeto (GitHub) ou, se quiser, baixar o instalável
 *  welcome          → instalável (opcional): token + instrução de vínculo do Client
 *  home             → PosturaView (postura histórica de segurança)
 *  pipeline         → acompanhar scan em andamento
 *  relatorio_executivo → relatório executivo gerado pelo Spirit
 *  results          → relatório de vulnerabilidades (dashboard completo)
 *  historico        → lista de scans anteriores
 *  projeto          → criar / editar projeto (Nexus)
 */

function sessaoSalva() {
  return !!localStorage.getItem("session_token");
}

// Boas-vindas: aparece até o usuário criar o 1º projeto, abrir o dashboard ou vincular o Client.
function onboardingPendente() {
  return localStorage.getItem("onboarding_done") !== "true";
}

function concluirOnboarding() {
  localStorage.setItem("onboarding_done", "true");
}

function lerResetToken() {
  const params = new URLSearchParams(window.location.search);
  return params.get("reset_token") || null;
}

export default function App() {
  const [resetToken] = useState(lerResetToken);
  const [tema, setTema] = useState(localStorage.getItem("theme") || "neon");

  const toggleTema = () => {
    setTema((prev) => {
      if (prev === "neon")  return "dark";
      if (prev === "dark")  return "light";
      return "neon";
    });
  };

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
    resetToken ? "recuperar_senha" :
    !dadosSalvos ? "landing" :
    (dadosSalvos.client_linked || !onboardingPendente()) ? "home" : "onboarding"
  );
  const [usuarioAuth, setUsuarioAuth] = useState(dadosSalvos);
  const [relatorio, setRelatorio] = useState(null);
  const [relatorioExecutivo, setRelatorioExecutivo] = useState(null);
  const [protocoloPipeline, setProtocoloPipeline] = useState(null);
  const [scanState, setScanState] = useState({ tipo: "concluido" });
  const [relatorioExecutivoNaoLido, setRelatorioExecutivoNaoLido] = useState(false);
  const [spiritAberto, setSpiritAberto] = useState(true);
  // Tela anterior para voltar após editar projeto
  const [telaAntesDoProjeto, setTelaAntesDoProjeto] = useState(null);

  // ── Polling de scan ativo ─────────────────────────────────────────────────
  const logado = !["auth", "signup", "onboarding", "welcome", "landing"].includes(tela);

  useEffect(() => {
    if (!logado) return;
    let cancel = false;

    async function tick() {
      try {
        const ativo = await detectarScanAtivo();
        if (cancel) return;

        if (ativo) {
          setScanState({ tipo: "rodando", protocolo: ativo.protocolo, repositorio: ativo.repositorio });

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
    localStorage.removeItem("onboarding_done");
    setRelatorio(null);
    setRelatorioExecutivo(null);
    setProtocoloPipeline(null);
    setUsuarioAuth(null);
    setTela("landing");
  }

  // Quem já vinculou o Client ou já tem projeto vai direto ao dashboard;
  // quem ainda não tem nada vê as boas-vindas (e não fica preso a elas).
  async function onLogin(dados) {
    setUsuarioAuth(dados);
    localStorage.setItem("client_linked", dados.client_linked ? "true" : "false");

    let temProjeto = false;
    if (!dados.client_linked) {
      try { temProjeto = !!(await buscarProjeto()); } catch { /* segue para o onboarding */ }
    }

    if (dados.client_linked || temProjeto) {
      concluirOnboarding();
      setTela("home");
    } else {
      localStorage.removeItem("onboarding_done");
      setTela("onboarding");
    }
  }

  function onCriouConta(dados) {
    setUsuarioAuth(dados);
    localStorage.setItem("client_linked", "false");
    localStorage.removeItem("onboarding_done");
    setTela("onboarding");
  }

  function onAcessarDashboard() {
    concluirOnboarding();
    setTela("home");
  }

  async function onRelatorioCarregado(dados) {
    setRelatorio(dados);
    try {
      const exec = await buscarRelatorioExecutivo(dados?.protocolo);
      if (exec) setRelatorioExecutivo(exec);
    } catch { /* Spirit pode não ter gerado */ }
    setTela("results");
  }

  const abrirPipeline = useCallback((protocolo) => {
    if (!protocolo) return;
    setProtocoloPipeline(protocolo);
    setTela("pipeline");
  }, []);

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

  function abrirProjeto() {
    setTelaAntesDoProjeto(tela);
    setTela("projeto");
  }

  function voltarDoProjeto() {
    setTela(telaAntesDoProjeto || "home");
    setTelaAntesDoProjeto(null);
  }

  // ── Roteamento ────────────────────────────────────────────────────────────
  const scanStateComExecutivo = { ...scanState, relatorioExecutivoNaoLido };
  const dashboardClass = `dashboard ${spiritAberto ? "" : "spirit-recolhido"}`;
  const naTelaInicial  = ["landing", "auth", "signup", "onboarding", "welcome"].includes(tela);

  const navValue = { irParaProjeto: abrirProjeto };

  return (
    <ThemeContext.Provider value={{ tema, toggleTema }}>
      <NavContext.Provider value={navValue}>
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
            onEsqueciSenha={() => setTela("recuperar_senha")}
          />
        )}

        {tela === "recuperar_senha" && (
          <RecuperarSenha
            resetToken={resetToken}
            onVoltar={() => setTela("auth")}
            onSucesso={() => setTela("auth")}
          />
        )}

        {tela === "signup" && (
          <SignUp
            onCriouConta={onCriouConta}
            onIrParaLogin={() => setTela("auth")}
            onVoltar={() => setTela("landing")}
          />
        )}

        {tela === "onboarding" && (
          <Onboarding
            nome={usuarioAuth?.nome || localStorage.getItem("user_nome") || ""}
            onCriarProjeto={abrirProjeto}
            onInstalavel={() => setTela("welcome")}
            onIrDashboard={onAcessarDashboard}
            onSair={sair}
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
            onVoltar={() => setTela("onboarding")}
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
        )}

        {tela === "historico" && (
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
        )}

        {tela === "projeto" && (
          <div className={dashboardClass}>
            <ProjetoView
              scanState={scanStateComExecutivo}
              spiritAberto={spiritAberto}
              onToggleSpirit={() => setSpiritAberto((v) => !v)}
              onVerHistorico={() => setTela("historico")}
              onAbrirPipeline={abrirPipeline}
              onSair={sair}
              onVoltar={voltarDoProjeto}
              onProjetoSalvo={concluirOnboarding}
            />
            {spiritAberto && <SpiritChat relatorio={relatorio} />}
          </div>
        )}

        {/* --- Home: PosturaView --- */}
        {(!relatorio || tela === "home") && !naTelaInicial &&
          tela !== "relatorio_executivo" && tela !== "pipeline" &&
          tela !== "historico" && tela !== "results" && tela !== "projeto" && (
          <div className="app-shell app-shell-resultados">
            <PosturaView
              onRelatorioCarregado={onRelatorioCarregado}
              onAbrirPipeline={abrirPipeline}
              onConfigurarProjeto={abrirProjeto}
              onSair={sair}
            />
          </div>
        )}

        {tela === "results" && relatorio && (
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
        )}
      </NavContext.Provider>
    </ThemeContext.Provider>
  );
}
