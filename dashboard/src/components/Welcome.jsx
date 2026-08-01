import { useState } from "react";
import logo from "../assets/logo.png";
import { regenToken, checkLink } from "../api";

const EXE_URL = "#"; // substitua pela URL real do executável

export default function Welcome({ usuario, onAcessarDashboard }) {
  const [token, setToken] = useState(usuario.token);
  const [copiado, setCopiado] = useState(false);
  const [regenando, setRegenando] = useState(false);
  const [verificando, setVerificando] = useState(false);
  const [erroLink, setErroLink] = useState("");

  async function copiarToken() {
    await navigator.clipboard.writeText(token);
    setCopiado(true);
    setTimeout(() => setCopiado(false), 2000);
  }

  async function handleRegen() {
    setRegenando(true);
    try {
      const dados = await regenToken();
      setToken(dados.token);
      localStorage.setItem("user_token", dados.token);
    } catch {
      /* ignore */
    } finally {
      setRegenando(false);
    }
  }

  async function handleAcessar() {
    setErroLink("");
    setVerificando(true);
    try {
      const dados = await checkLink();
      if (dados.client_linked) {
        onAcessarDashboard();
      } else {
        setErroLink("Client ainda não vinculado. Cole o token no executável e tente novamente.");
      }
    } catch {
      setErroLink("Não foi possível verificar. O Core está rodando?");
    } finally {
      setVerificando(false);
    }
  }

  return (
    <div className="tela-login">
      <div className="login-bg-grid" aria-hidden="true" />
      <div className="login-orb login-orb-1" aria-hidden="true" />
      <div className="login-orb login-orb-2" aria-hidden="true" />

      <div className="login-card welcome-card">
        <div className="login-card-borda" aria-hidden="true" />

        <div className="login-logo">
          <img src={logo} alt="PhantomFix" />
        </div>

        <h1 className="login-titulo">Bem-vindo, {usuario.nome}! 👻</h1>
        <p className="login-subtitulo">
          Sua conta foi criada. Configure o client para começar.
        </p>

        {/* Token */}
        <div className="welcome-token-bloco">
          <p className="welcome-label">Seu token único</p>
          <div className="welcome-token-row">
            <code className="welcome-token">{token}</code>
            <button
              type="button"
              className="welcome-btn-copy"
              onClick={copiarToken}
              title="Copiar token"
            >
              {copiado ? "✓ Copiado" : "Copiar"}
            </button>
          </div>
          <p className="welcome-aviso">
            ⚠ Guarde este token. Ele não será exibido novamente após você fechar esta página.
          </p>
          <button
            type="button"
            className="welcome-btn-regen"
            onClick={handleRegen}
            disabled={regenando}
          >
            {regenando ? "Gerando..." : "↺ Gerar novo token"}
          </button>
        </div>

        {/* Instruções */}
        <div className="welcome-instrucoes">
          <p className="welcome-label">Como configurar o client</p>
          <ol className="welcome-steps">
            <li>
              <a href={EXE_URL} className="welcome-link" download>
                Baixe o executável oficial do PhantomFix Client
              </a>
            </li>
            <li>
              Abra o executável e cole seu token no campo{" "}
              <strong>"Vincule o token único"</strong>
            </li>
            <li>
              Após vincular, clique em <strong>"Acessar Dashboard"</strong> abaixo
            </li>
          </ol>
        </div>

        {erroLink && <p className="login-erro">{erroLink}</p>}

        <button
          type="button"
          className="login-btn"
          onClick={handleAcessar}
          disabled={verificando}
        >
          <span>{verificando ? "Verificando..." : "Acessar Dashboard"}</span>
          {!verificando && (
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          )}
        </button>
      </div>
    </div>
  );
}
