import { useState } from "react";
import logo from "../assets/logo.png";

const USUARIO_VALIDO = "admin";
const SENHA_VALIDA = "admin";

export default function Login({ onLogin }) {
  const [usuario, setUsuario] = useState("");
  const [senha, setSenha] = useState("");
  const [erro, setErro] = useState("");

  function handleSubmit(e) {
    e.preventDefault();
    if (usuario === USUARIO_VALIDO && senha === SENHA_VALIDA) {
      setErro("");
      onLogin();
    } else {
      setErro("Usuário ou senha incorretos.");
    }
  }

  return (
    <div className="tela-login">
      <div className="login-bg-grid" aria-hidden="true" />
      <div className="login-orb login-orb-1" aria-hidden="true" />
      <div className="login-orb login-orb-2" aria-hidden="true" />

      <div className="login-card">
        <div className="login-card-borda" aria-hidden="true" />

    <div className="login-logo">
        <img src={logo} alt="PhantomFix" />
    </div>

        <h1 className="login-titulo">PhantomFix</h1>
        <p className="login-subtitulo">
          ASPM com IA · priorização e redução de alert fatigue
        </p>

        <form onSubmit={handleSubmit}>
          <label>
            Usuário
            <input
              value={usuario}
              onChange={(e) => setUsuario(e.target.value)}
              autoFocus
              autoComplete="username"
              placeholder="admin"
            />
          </label>
          <label>
            Senha
            <input
              type="password"
              value={senha}
              onChange={(e) => setSenha(e.target.value)}
              autoComplete="current-password"
              placeholder="••••••••"
            />
          </label>
          {erro && <p className="login-erro">{erro}</p>}
          <button type="submit" className="login-btn">
            <span>Entrar</span>
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </button>
        </form>
      </div>
    </div>
  );
}