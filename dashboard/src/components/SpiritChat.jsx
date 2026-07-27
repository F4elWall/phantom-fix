import { useState } from "react";
import { perguntarSpirit } from "../api";

export default function SpiritChat() {
  const [mensagens, setMensagens] = useState([
    {
      autor: "spirit",
      texto:
        "Sou o Spirit. Pergunte sobre as vulnerabilidades, impacto legal ou compliance (LGPD, ISO 27001...).",
    },
  ]);
  const [pergunta, setPergunta] = useState("");
  const [carregando, setCarregando] = useState(false);

  async function enviar(e) {
    e.preventDefault();
    if (!pergunta.trim()) return;

    const perguntaAtual = pergunta;
    setMensagens((m) => [...m, { autor: "usuario", texto: perguntaAtual }]);
    setPergunta("");
    setCarregando(true);

    try {
      const resposta = await perguntarSpirit(perguntaAtual);
      setMensagens((m) => [
        ...m,
        { autor: "spirit", texto: resposta.resposta },
      ]);
    } catch {
      setMensagens((m) => [
        ...m,
        {
          autor: "spirit",
          texto: "Não consegui responder agora. O Spirit está no ar?",
        },
      ]);
    } finally {
      setCarregando(false);
    }
  }

  return (
    <div className="spirit-chat">
      <div className="spirit-header">Spirit</div>
      <div className="spirit-mensagens">
        {mensagens.map((m, i) => (
          <div key={i} className={`mensagem mensagem-${m.autor}`}>
            {m.texto}
          </div>
        ))}
        {carregando && (
          <div className="mensagem mensagem-spirit mensagem-carregando">
            digitando...
          </div>
        )}
      </div>
      <form onSubmit={enviar} className="spirit-form">
        <input
          value={pergunta}
          onChange={(e) => setPergunta(e.target.value)}
          placeholder="Pergunte ao Spirit..."
        />
        <button type="submit" disabled={carregando}>
          Enviar
        </button>
      </form>
    </div>
  );
}