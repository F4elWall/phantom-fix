import { useState } from "react";
import logo from "../assets/logo.png";
import { signup } from "../api";

export default function SignUp({ onCriouConta, onIrParaLogin }) {
  const [nome, setNome] = useState("");
  const [email, setEmail] = useState("");
  const [senha, setSenha] = useState("");
  const [erro, setErro] = useState("");
  const [carregando, setCarregando] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setErro("");
    if (senha.length < 6) {
      setErro("A senha precisa ter pelo menos 6 caracteres");
      return;
    }
    setCarregando(true);
    try {
      const dados = await signup({ nome: nome.trim(), email: email.trim(), senha });
      localStorage.setItem("session_token", dados.session_token);
      localStorage.setItem("user_nome", dados.nome);
      localStorage.setItem("user_token", dados.token);
      onCriouConta(dados);
    } catch (err) {
      setErro(err.message || "Erro ao criar conta");
    } finally {
      setCarregando(false);
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

        <h1 className="login-titulo">Criar conta</h1>
        <p className="login-subtitulo">
          Bem-vindo ao PhantomFix · Análise de segurança com IA
        </p>

        <form onSubmit={handleSubmit}>
          <label>
            Nome
            <input
              type="text"
              value={nome}
              onChange={(e) => setNome(e.target.value)}
              autoFocus
              placeholder="Seu nome"
              required
            />
          </label>
          <label>
            E-mail
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              placeholder="seu@email.com"
              required
            />
          </label>
          <label>
            Senha
            <input
              type="password"
              value={senha}
              onChange={(e) => setSenha(e.target.value)}
              autoComplete="new-password"
              placeholder="mínimo 6 caracteres"
              required
            />
          </label>
          {erro && <p className="login-erro">{erro}</p>}
          <button type="submit" className="login-btn" disabled={carregando}>
            <span>{carregando ? "Criando conta..." : "Criar conta"}</span>
            {!carregando && (
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            )}
          </button>
        </form>

        <p className="login-link-alt">
          Já tem conta?{" "}
          <button type="button" className="login-link-btn" onClick={onIrParaLogin}>
            Entrar
          </button>
        </p>
      </div>
    </div>
  );
}
