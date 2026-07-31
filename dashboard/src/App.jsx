import { useState } from "react";
import Login from "./components/Login";
import Home from "./components/Home";
import ResultsView from "./components/ResultsView";
import SpiritChat from "./components/SpiritChat";
import "./App.css";

export default function App() {
  const [logado, setLogado] = useState(false);
  const [relatorio, setRelatorio] = useState(null);

  function sair() {
    setLogado(false);
    setRelatorio(null);
  }

  if (!logado) {
    return <Login onLogin={() => setLogado(true)} />;
  }

  if (!relatorio) {
    return (
      <div className="app-shell">
        <Home onRelatorioCarregado={setRelatorio} />
      </div>
    );
  }

  return (
    <div className="dashboard">
      <ResultsView
        relatorio={relatorio}
        onVerHistorico={() => setRelatorio(null)}
        onSair={sair}
      />
      <SpiritChat />
    </div>
  );
}
