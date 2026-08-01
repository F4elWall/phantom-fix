import { useEffect, useMemo, useRef, useState } from "react";
import { statusScan, buscarRelatorio } from "../api";
import Topbar from "./Topbar";

const ETAPAS = [
  { id: "upload", label: "Upload do Repositório", statuses: ["recebido"] },
  { id: "prep", label: "Preparação do Ambiente", statuses: ["extraindo"] },
  { id: "sast", label: "Análise Estática (SAST)", statuses: ["escaneando"] },
  { id: "dast", label: "Análise Dinâmica (DAST)", statuses: ["escaneando"] },
  {
    id: "relatorio",
    label: "Geração de Relatório",
    statuses: ["analisando", "priorizado", "corrigindo"],
  },
];

const ORDEM_STATUS = [
  "recebido",
  "extraindo",
  "escaneando",
  "analisando",
  "priorizado",
  "corrigindo",
  "concluido",
  "erro",
];

const LOGS_POR_STATUS = {
  recebido: "Repositório recebido com sucesso",
  extraindo: "Extraindo e preparando ambiente...",
  escaneando: "Executando análise estática (SAST) e dinâmica (DAST)...",
  analisando: "Correlacionando resultados com IA...",
  priorizado: "Priorizando vulnerabilidades por risco de negócio...",
  corrigindo: "Ghost gerando sugestões de correção...",
  concluido: "Relatório final gerado",
  erro: "Falha no pipeline",
};

function indiceStatus(status) {
  const i = ORDEM_STATUS.indexOf(status);
  return i === -1 ? 0 : i;
}

/** Estado visual de cada etapa do stepper */
function estadoEtapa(etapaId, statusCore) {
  if (statusCore === "erro") {
    // marca a etapa atual como falha de forma simples
    return "erro";
  }
  const idx = indiceStatus(statusCore);

  if (etapaId === "upload") {
    if (idx > 0) return "concluido";
    if (statusCore === "recebido") return "executando";
    return "aguardando";
  }
  if (etapaId === "prep") {
    if (idx > 1) return "concluido";
    if (statusCore === "extraindo") return "executando";
    if (idx < 1) return "aguardando";
    return "aguardando";
  }
  if (etapaId === "sast") {
    if (idx > 2) return "concluido";
    if (statusCore === "escaneando") return "executando";
    if (idx < 2) return "aguardando";
    return "aguardando";
  }
  if (etapaId === "dast") {
    // mesmo status escaneando: fica executando junto com SAST (Core não separa)
    if (idx > 2) return "concluido";
    if (statusCore === "escaneando") return "executando";
    if (idx < 2) return "aguardando";
    return "aguardando";
  }
  if (etapaId === "relatorio") {
    if (statusCore === "concluido") return "concluido";
    if (["analisando", "priorizado", "corrigindo"].includes(statusCore))
      return "executando";
    if (idx < 3) return "aguardando";
    return "aguardando";
  }
  return "aguardando";
}

function estadoNoArquitetura(noId, statusCore) {
  const idx = indiceStatus(statusCore);
  if (statusCore === "erro") return "falhou";

  const map = {
    client: idx >= 0 ? "concluido" : "aguardando",
    core: idx >= 0 ? (idx < 6 ? "executando" : "concluido") : "aguardando",
    datacontrol: idx >= 1 ? (idx <= 2 ? "executando" : "concluido") : "aguardando",
    sast: idx > 2 ? "concluido" : statusCore === "escaneando" ? "executando" : "aguardando",
    dast: idx > 2 ? "concluido" : statusCore === "escaneando" ? "executando" : "aguardando",
    secrets: idx > 2 ? "concluido" : statusCore === "escaneando" ? "executando" : "aguardando",
    deps: idx > 2 ? "concluido" : statusCore === "escaneando" ? "executando" : "aguardando",
    ia:
      idx >= 6
        ? "concluido"
        : ["analisando", "priorizado"].includes(statusCore)
          ? "ia"
          : idx > 2
            ? "aguardando"
            : "aguardando",
    ghost:
      statusCore === "corrigindo"
        ? "ia"
        : statusCore === "concluido"
          ? "concluido"
          : "aguardando",
    relatorio: statusCore === "concluido" ? "concluido" : "aguardando",
  };
  return map[noId] || "aguardando";
}

function formatarDecorrido(segundos) {
  const m = Math.floor(segundos / 60)
    .toString()
    .padStart(2, "0");
  const s = (segundos % 60).toString().padStart(2, "0");
  return `${m}:${s}`;
}

export default function PipelineView({
  protocolo,
  scanState,
  spiritAberto,
  onToggleSpirit,
  onVerHistorico,
  onConcluido,
  onSair,
  onAbrirPipeline,
}) {
  const [statusCore, setStatusCore] = useState("recebido");
  const [repositorio, setRepositorio] = useState(
    scanState?.repositorio || ""
  );
  const [detalhe, setDetalhe] = useState("");
  const [logs, setLogs] = useState([]);
  const [segundos, setSegundos] = useState(0);
  const ultimoStatusRef = useRef(null);
  const inicioRef = useRef(Date.now());

  // cronômetro
  useEffect(() => {
    const t = setInterval(() => {
      setSegundos(Math.floor((Date.now() - inicioRef.current) / 1000));
    }, 1000);
    return () => clearInterval(t);
  }, []);

  // polling
  useEffect(() => {
    if (!protocolo) return;
    let cancelado = false;

    async function tick() {
      try {
        const job = await statusScan(protocolo);
        if (cancelado) return;
        if (!job) {
          // job sumiu da memória — tenta relatório pronto
          const rel = await buscarRelatorio(protocolo);
          if (rel) {
            setStatusCore("concluido");
            onConcluido?.(rel);
          }
          return;
        }
        const st = job.status || "recebido";
        setStatusCore(st);
        if (job.repositorio) setRepositorio(job.repositorio);
        if (job.detalhe) setDetalhe(job.detalhe);

        if (ultimoStatusRef.current !== st) {
          ultimoStatusRef.current = st;
          const agora = new Date().toLocaleTimeString("pt-BR", {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          });
          const texto =
            st === "erro"
              ? `${LOGS_POR_STATUS.erro}: ${job.detalhe || "erro desconhecido"}`
              : LOGS_POR_STATUS[st] || `Status: ${st}`;
          setLogs((prev) => [...prev, { hora: agora, texto, status: st }]);
        }

        if (st === "concluido") {
          const rel = await buscarRelatorio(protocolo);
          if (rel) onConcluido?.(rel);
        }
      } catch {
        /* rede */
      }
    }

    tick();
    const id = setInterval(tick, 2500);
    return () => {
      cancelado = true;
      clearInterval(id);
    };
  }, [protocolo, onConcluido]);

  const mensagemEtapa = useMemo(() => {
    if (statusCore === "erro") return detalhe || "Erro no pipeline";
    return LOGS_POR_STATUS[statusCore] || "Processando...";
  }, [statusCore, detalhe]);

  return (
    <div className="pipeline-page">
      <Topbar
        repositorio={repositorio}
        processadoEm={null}
        scanState={{ tipo: "rodando", protocolo, repositorio }}
        spiritAberto={spiritAberto}
        onToggleSpirit={onToggleSpirit}
        onVerHistorico={onVerHistorico}
        onAbrirPipeline={onAbrirPipeline}
        onSair={onSair}
      />

      <main className="pipeline-main">
        <div className="pipeline-header-block">
          <h1 className="pipeline-title">Pipeline view</h1>
          <p className="pipeline-subtitle">
            Acompanhe o progresso do scan em tempo real
          </p>
        </div>

        {/* Stepper */}
        <div className="pipeline-stepper">
          {ETAPAS.map((etapa, i) => {
            const est = estadoEtapa(etapa.id, statusCore);
            return (
              <div key={etapa.id} className="pipeline-step-wrap">
                {i > 0 && (
                  <div
                    className={`pipeline-connector ${
                      est === "concluido" || est === "executando"
                        ? "ativo"
                        : ""
                    }`}
                  />
                )}
                <div className={`pipeline-step estado-${est}`}>
                  <div className="pipeline-step-icon">
                    {est === "concluido" && <span className="check">✓</span>}
                    {est === "executando" && (
                      <span className="num">{i + 1}</span>
                    )}
                    {est === "aguardando" && (
                      <span className="num dim">{i + 1}</span>
                    )}
                    {est === "erro" && <span className="err">!</span>}
                  </div>
                  <div className="pipeline-step-label">{etapa.label}</div>
                  <div className={`pipeline-step-status st-${est}`}>
                    {est === "concluido" && "Concluído"}
                    {est === "executando" && "Executando"}
                    {est === "aguardando" && "Aguardando"}
                    {est === "erro" && "Falhou"}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        <div className="pipeline-meta-row">
          <p className="pipeline-msg">{mensagemEtapa}</p>
          <div className="pipeline-timer">
            <span className="timer-icon">⏱</span>
            Tempo decorrido
            <strong>{formatarDecorrido(segundos)}</strong>
          </div>
        </div>

        {/* Arquitetura */}
        <section className="pipeline-arch">
          <h2>Arquitetura do PhantomFix</h2>
          <div className="arch-flow">
            {[
              { id: "client", label: "Client" },
              { id: "core", label: "Core" },
              { id: "datacontrol", label: "Data Control" },
            ].map((n) => (
              <div
                key={n.id}
                className={`arch-node estado-${estadoNoArquitetura(n.id, statusCore)}`}
              >
                {n.label}
              </div>
            ))}
            <div className="arch-branch">
              {[
                { id: "sast", label: "SAST" },
                { id: "dast", label: "DAST" },
                { id: "secrets", label: "Secrets" },
                { id: "deps", label: "Dependencies" },
              ].map((n) => (
                <div
                  key={n.id}
                  className={`arch-node small estado-${estadoNoArquitetura(n.id, statusCore)}`}
                >
                  {n.label}
                </div>
              ))}
            </div>
            {[
              { id: "ia", label: "AI Correlation" },
              { id: "ghost", label: "Ghost" },
              { id: "relatorio", label: "Relatório Final" },
            ].map((n) => (
              <div
                key={n.id}
                className={`arch-node estado-${estadoNoArquitetura(n.id, statusCore)}`}
              >
                {n.label}
              </div>
            ))}
          </div>
          <div className="arch-legend">
            <span>
              <i className="lg-aguardo" /> Aguardando
            </span>
            <span>
              <i className="lg-exec" /> Executando
            </span>
            <span>
              <i className="lg-ok" /> Concluído
            </span>
            <span>
              <i className="lg-ia" /> IA processando
            </span>
            <span>
              <i className="lg-fail" /> Falhou
            </span>
          </div>
        </section>

        {/* Logs sintéticos */}
        <section className="pipeline-logs">
          <div className="pipeline-logs-header">
            <h2>Logs em tempo real</h2>
          </div>
          <div className="pipeline-logs-body">
            {logs.length === 0 && (
              <p className="log-line dim">Aguardando eventos do pipeline…</p>
            )}
            {logs.map((l, i) => (
              <p key={i} className={`log-line log-${l.status}`}>
                <span className="log-hora">{l.hora}</span>
                <span className="log-icon">
                  {l.status === "erro" ? "✗" : l.status === "concluido" ? "✓" : "●"}
                </span>
                {l.texto}
              </p>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}
