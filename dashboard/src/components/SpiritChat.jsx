import { useState, useRef, useEffect } from "react";
import { perguntarSpirit } from "../api";

const SUGESTOES = [
  { icone: "💡", texto: "Por que estes 3 são prioritários?" },
  { icone: "🛡️", texto: "Como isso afeta o LGPD/ISO 27001?" },
  { icone: "🔧", texto: "Gerar patch de correção" },
];

export default function SpiritChat() {
  const [mensagens, setMensagens] = useState([
    {
      autor: "spirit",
      texto:
        "Sou o Spirit AI. Pergunte sobre o contexto técnico, o impacto regulatório (LGPD, ISO 27001) ou peça sugestões de patch para as vulnerabilidades prioritárias.",
    },
  ]);
  const [pergunta, setPergunta] = useState("");
  const [carregando, setCarregando] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [mensagens, carregando]);

  async function enviar(texto) {
    const q = texto || pergunta;
    if (!q.trim()) return;

    setMensagens((m) => [...m, { autor: "usuario", texto: q }]);
    setPergunta("");
    setCarregando(true);

    try {
      const resposta = await perguntarSpirit(q);
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

  function handleSubmit(e) {
    e.preventDefault();
    enviar();
  }

  return (
    <aside className="spirit-panel">
      <div className="spirit-header">
        <div className="spirit-titulo">
          <div className="spirit-icon">🤖</div>
          SPIRIT AI
        </div>
        <div className="spirit-status">
          <div className="spirit-status-dot" />
          Online
        </div>
      </div>

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
        <div ref={bottomRef} />
      </div>

      <div className="spirit-sugestoes">
        {SUGESTOES.map((s, i) => (
          <button
            key={i}
            className="spirit-sugestao-btn"
            onClick={() => enviar(s.texto)}
            disabled={carregando}
          >
            <span className="icone">{s.icone}</span>
            {s.texto}
          </button>
        ))}
      </div>

      <form onSubmit={handleSubmit} className="spirit-form">
        <input
          className="spirit-input"
          value={pergunta}
          onChange={(e) => setPergunta(e.target.value)}
          placeholder="Pergunte sobre..."
          disabled={carregando}
        />
        <button type="submit" className="spirit-send" disabled={carregando}>
          ➤
        </button>
      </form>
    </aside>
  );
}
