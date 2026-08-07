import { useEffect, useState } from "react";
import logo from "../assets/logo.png";
import { buscarRelatorio, detectarScanAtivo } from "../api";

const ETAPAS = {
  recebido:  { label: "Repositório recebido",          pct: 10 },
  extraindo: { label: "Extraindo arquivos...",           pct: 20 },
  escaneando:{ label: "Escaneando vulnerabilidades...", pct: 40 },
  analisando:{ label: "Analisando com IA...",           pct: 65 },
  priorizado:{ label: "Priorizando resultados...",      pct: 75 },
  corrigindo:{ label: "Gerando correções (Ghost)...",   pct: 88 },
  concluido: { label: "Análise concluída!",             pct: 100 },
  erro:      { label: "Erro na análise",                pct: 100 },
};

export default function Home({ onRelatorioCarregado, onAbrirPipeline, onSair }) {
  const [status, setStatus]   = useState("carregando");
  const [pipeline, setPipeline] = useState(null);

  useEffect(() => {
    let cancelado = false;
    let intervalo = null;

    async function carregar() {
      try {
        const dados = await buscarRelatorio();
        if (cancelado) return;
        if (dados) { onRelatorioCarregado(dados); return; }
        setStatus("vazio");
        iniciarPolling();
      } catch {
        if (!cancelado) setStatus("erro");
      }
    }

    function iniciarPolling() {
      intervalo = setInterval(async () => {
        if (cancelado) return;
        try {
          const ativo = await detectarScanAtivo();
          if (ativo && ativo.protocolo) {
            setPipeline(ativo);
            if (ativo.status === "concluido") {
              clearInterval(intervalo);
              const rel = await buscarRelatorio();
              if (rel && !cancelado) onRelatorioCarregado(rel);
            }
          } else {
            setPipeline(null);
          }
        } catch { /* ignore */ }
      }, 3000);
    }

    carregar();
    return () => { cancelado = true; clearInterval(intervalo); };
  }, [onRelatorioCarregado]);

  const etapa = pipeline ? ETAPAS[pipeline.status] : null;
  const rodando = pipeline && pipeline.status && !["concluido", "erro"].includes(pipeline.status);

  return (
    <div className="tela-home">
      {/* Botão sair no canto */}
      {onSair && (
        <button className="home-btn-sair" onClick={onSair}>Sair</button>
      )}

      <img src={logo} alt="PhantomFix" className="home-logo-img" />
      <h2>PhantomFix Dashboard</h2>

      {!pipeline && status === "carregando" && (
        <p className="status-carregando">Buscando último relatório...</p>
      )}

      {!pipeline && status === "erro" && (
        <p className="status-erro">Não foi possível conectar ao Core. Ele está rodando?</p>
      )}

      {!pipeline && status === "vazio" && (
        <div className="home-aguardando">
          <div className="home-aguardando-dot" />
          <p className="home-aguardando-label">Aguardando primeira análise</p>
          <p className="dica">Envie um repositório pelo Client desktop e volte aqui.</p>
        </div>
      )}

      {pipeline && etapa && (
        <div className="home-pipeline">
          {rodando && (
            <div className="home-pipeline-badge">
              <span className="home-pipeline-pulse" />
              Análise em andamento
            </div>
          )}

          <p className="home-pipeline-repo">
            <span className="home-pipeline-icon">⌗</span>
            {pipeline.repositorio || "Repositório"}
          </p>

          <div className="home-pipeline-barra-bg">
            <div
              className={`home-pipeline-barra ${pipeline.status === "erro" ? "barra-erro" : ""}`}
              style={{ width: `${etapa.pct}%` }}
            />
          </div>

          <p className="home-pipeline-label">
            {pipeline.status === "erro" ? "❌" : "⏳"} {etapa.label}
          </p>

          {rodando && onAbrirPipeline && (
            <button
              className="home-pipeline-btn"
              onClick={() => onAbrirPipeline(pipeline.protocolo)}
            >
              Ver Pipeline View →
            </button>
          )}

          {!rodando && (
            <p className="home-pipeline-dica">
              Aguarde — o relatório aparecerá automaticamente quando a análise terminar.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
