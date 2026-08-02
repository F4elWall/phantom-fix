import { useEffect, useState } from "react";
import { buscarRelatorio, statusCore } from "../api";

const ETAPAS = {
  recebido:          { label: "Repositório recebido",       pct: 10 },
  extraindo:         { label: "Extraindo arquivos...",       pct: 20 },
  escaneando:        { label: "Escaneando vulnerabilidades...", pct: 40 },
  analisando:        { label: "Analisando com IA...",        pct: 65 },
  priorizado:        { label: "Priorizando resultados...",   pct: 75 },
  corrigindo:        { label: "Gerando correções (Ghost)...", pct: 88 },
  concluido:         { label: "Análise concluída!",          pct: 100 },
  erro:              { label: "Erro na análise",             pct: 100 },
};

export default function Home({ onRelatorioCarregado }) {
  const [status, setStatus]       = useState("carregando");
  const [mensagem, setMensagem]   = useState("Buscando último relatório...");
  const [pipeline, setPipeline]   = useState(null); // dados do scan ativo

  useEffect(() => {
    let cancelado = false;
    let intervalo = null;

    async function carregar() {
      try {
        const dados = await buscarRelatorio();
        if (cancelado) return;
        if (dados) {
          onRelatorioCarregado(dados);
          return;
        }
        // Sem relatório — verifica se tem scan rodando
        setStatus("vazio");
        setMensagem("Nenhum relatório disponível ainda.");
        iniciarPolling();
      } catch {
        if (!cancelado) {
          setStatus("erro");
          setMensagem("Não foi possível conectar ao Core. Ele está rodando?");
        }
      }
    }

    function iniciarPolling() {
      intervalo = setInterval(async () => {
        if (cancelado) return;
        try {
          const st = await statusCore();
          if (!st) return;

          if (st.status === "concluido") {
            clearInterval(intervalo);
            const rel = await buscarRelatorio();
            if (rel && !cancelado) onRelatorioCarregado(rel);
            return;
          }

          if (st.status && st.status !== "ocioso") {
            setPipeline(st);
          }
        } catch { /* ignore */ }
      }, 3000);
    }

    carregar();
    return () => { cancelado = true; clearInterval(intervalo); };
  }, [onRelatorioCarregado]);

  const etapa = pipeline ? ETAPAS[pipeline.status] : null;

  return (
    <div className="tela-home">
      <div className="home-logo">👻</div>
      <h2>PhantomFix Dashboard</h2>

      {!pipeline && (
        <>
          <p className={`status-${status}`}>{mensagem}</p>
          {status === "vazio" && (
            <p className="dica">Envie um repositório pelo Client desktop e volte aqui.</p>
          )}
        </>
      )}

      {pipeline && etapa && (
        <div className="home-pipeline">
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

          <p className="home-pipeline-dica">
            Aguarde — o relatório aparecerá automaticamente quando a análise terminar.
          </p>
        </div>
      )}
    </div>
  );
}
