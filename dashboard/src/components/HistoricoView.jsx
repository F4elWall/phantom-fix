import { useEffect, useState } from "react";
import { listarHistorico, buscarRelatorio } from "../api";
import Topbar from "./Topbar";

const POR_PAGINA = 6;

function formatarData(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
    timeZone: "America/Sao_Paulo",
  });
}

export default function HistoricoView({
  scanState,
  spiritAberto,
  onToggleSpirit,
  onAbrirPipeline,
  onSelecionar,
  onVoltar,
  onSair,
}) {
  const [itens, setItens] = useState([]);
  const [pagina, setPagina] = useState(1);
  const [carregando, setCarregando] = useState(true);
  const [erro, setErro] = useState("");
  const [abrindo, setAbrindo] = useState(null);

  useEffect(() => {
    let ok = true;
    (async () => {
      try {
        const lista = await listarHistorico();
        if (ok) setItens(lista);
      } catch {
        if (ok) setErro("Não foi possível carregar o histórico.");
      } finally {
        if (ok) setCarregando(false);
      }
    })();
    return () => {
      ok = false;
    };
  }, []);

  const totalPaginas = Math.max(1, Math.ceil(itens.length / POR_PAGINA));
  const fatia = itens.slice((pagina - 1) * POR_PAGINA, pagina * POR_PAGINA);

  async function abrir(protocolo) {
    setAbrindo(protocolo);
    try {
      const rel = await buscarRelatorio(protocolo);
      if (rel) onSelecionar(rel);
      else setErro("Relatório ainda não disponível para este protocolo.");
    } catch {
      setErro("Falha ao abrir o relatório.");
    } finally {
      setAbrindo(null);
    }
  }

  return (
    <div className="historico-page">
      <Topbar
        repositorio={null}
        processadoEm={null}
        scanState={scanState}
        spiritAberto={spiritAberto}
        onToggleSpirit={onToggleSpirit}
        onVerHistorico={null}
        onAbrirPipeline={onAbrirPipeline}
        onSair={onSair}
      />

      <main className="historico-main">
        <div className="historico-header">
          <button type="button" className="btn-voltar" onClick={onVoltar}>
            ← Voltar
          </button>
          <h1>Histórico de scans</h1>
          <p className="historico-sub">
            Selecione uma análise anterior para abrir o relatório priorizado.
          </p>
        </div>

        {carregando && <p className="historico-msg">Carregando…</p>}
        {erro && <p className="historico-msg erro">{erro}</p>}

        {!carregando && !erro && itens.length === 0 && (
          <p className="historico-msg">Nenhum scan encontrado.</p>
        )}

        <div className="historico-lista">
          {fatia.map((item) => (
            <button
              key={item.protocolo}
              type="button"
              className="historico-linha"
              disabled={!item.completo || abrindo === item.protocolo}
              onClick={() => abrir(item.protocolo)}
            >
              <span className="hist-repo">{item.repositorio}</span>
              <span className="hist-data">{formatarData(item.processado_em)}</span>
              <span className="hist-total">
                {item.completo
                  ? `${item.total} vulnerabilidades`
                  : "Em andamento / incompleto"}
              </span>
              <span className="hist-proto">{item.protocolo}</span>
            </button>
          ))}
        </div>

        {totalPaginas > 1 && (
          <div className="paginacao">
            <button
              type="button"
              className="paginacao-btn"
              disabled={pagina === 1}
              onClick={() => setPagina((p) => p - 1)}
            >
              ‹
            </button>
            <span className="paginacao-info">
              {pagina} / {totalPaginas}
            </span>
            <button
              type="button"
              className="paginacao-btn"
              disabled={pagina === totalPaginas}
              onClick={() => setPagina((p) => p + 1)}
            >
              ›
            </button>
          </div>
        )}
      </main>
    </div>
  );
}
