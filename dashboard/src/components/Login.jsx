import { useState } from "react";

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
      <div className="login-card">
        <div className="login-glow" />
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
            />
          </label>
          <label>
            Senha
            <input
              type="password"
              value={senha}
              onChange={(e) => setSenha(e.target.value)}
            />
          </label>
          {erro && <p className="login-erro">{erro}</p>}
          <button type="submit">Entrar</button>
        </form>
      </div>
    </div>
  );
}