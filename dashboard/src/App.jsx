import { useCallback, useEffect, useState } from "react";
import Login from "./components/Login";
import Home from "./components/Home";
import ResultsView from "./components/ResultsView";
import SpiritChat from "./components/SpiritChat";
import PipelineView from "./components/PipelineView";
import HistoricoView from "./components/HistoricoView";
import { detectarScanAtivo } from "./api";
import "./App.css";

export default function App() {
  const [logado, setLogado] = useState(false);
  const [relatorio, setRelatorio] = useState(null);
  const [tela, setTela] = useState("home");
  const [protocoloPipeline, setProtocoloPipeline] = useState(null);
  const [scanState, setScanState] = useState({ tipo: "concluido" });
  const [spiritAberto, setSpiritAberto] = useState(true);

  function sair() {
    setLogado(false);
    setRelatorio(null);
    setTela("home");
    setProtocoloPipeline(null);
  }

  const abrirPipeline = useCallback((protocolo) => {
    if (!protocolo) return;
    setProtocoloPipeline(protocolo);
    setTela("pipeline");
  }, []);

  useEffect(() => {
    if (!logado) return;
    let cancel = false;

    async function tick() {
      try {
        const ativo = await detectarScanAtivo();
        if (cancel) return;
        if (ativo) {
          setScanState({
            tipo: "rodando",
            protocolo: ativo.protocolo,
            repositorio: ativo.repositorio,
          });
        } else {
          setScanState({ tipo: "concluido" });
        }
      } catch {
        /* ignore */
      }
    }

    tick();
    const id = setInterval(tick, 4000);
    return () => {
      cancel = true;
      clearInterval(id);
    };
  }, [logado]);

  function onRelatorioCarregado(dados) {
    setRelatorio(dados);
    setTela("results");
  }

  function onConcluidoPipeline(rel) {
    setRelatorio(rel);
    setTela("results");
    setScanState({ tipo: "concluido" });
  }

  if (!logado) {
    return <Login onLogin={() => setLogado(true)} />;
  }

  if (tela === "pipeline" && protocoloPipeline) {
    return (
      <div className={`dashboard ${spiritAberto ? "" : "spirit-recolhido"}`}>
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
      <div className={`dashboard ${spiritAberto ? "" : "spirit-recolhido"}`}>
        <HistoricoView
          scanState={scanState}
          spiritAberto={spiritAberto}
          onToggleSpirit={() => setSpiritAberto((v) => !v)}
          onAbrirPipeline={abrirPipeline}
          onSelecionar={(rel) => {
            setRelatorio(rel);
            setTela("results");
          }}
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
    <div className={`dashboard ${spiritAberto ? "" : "spirit-recolhido"}`}>
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
