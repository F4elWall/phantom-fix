import { useEffect, useState } from "react";
import { buscarRelatorio } from "../api";

export default function Home({ onRelatorioCarregado }) {
  const [status, setStatus] = useState("carregando");
  const [mensagem, setMensagem] = useState("Buscando último relatório...");

  useEffect(() => {
    async function carregar() {
      try {
        const dados = await buscarRelatorio();
        if (!dados) {
          setStatus("vazio");
          setMensagem(
            "Nenhum relatório disponível ainda. Use o Client (app.py) para enviar um repositório."
          );
          return;
        }
        onRelatorioCarregado(dados);
      } catch (e) {
        setStatus("erro");
        setMensagem("Não foi possível conectar ao Core. Ele está rodando?");
      }
    }
    carregar();
  }, [onRelatorioCarregado]);

  return (
    <div className="tela-home">
      <h2>PhantomFix Dashboard</h2>
      <p className={`status-${status}`}>{mensagem}</p>
      {status === "vazio" && (
        <p className="dica">
          Envie um repositório pelo Client desktop e volte aqui.
        </p>
      )}
    </div>
  );
}