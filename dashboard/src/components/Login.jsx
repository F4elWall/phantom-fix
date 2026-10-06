{/*# PhantomFix — Copyright (C) 2025–2026 Rafael Pedro, Bernardo Coroa,
   # Giovanna Esmelardi, Gustavo Enrique
   # SPDX-License-Identifier: GPL-3.0-or-later
   # Licenciado sob a GNU GPL v3. Veja LICENSE.md na raiz do repositório.*/}


import { useState } from "react";
import logo from "../assets/logo.png";
import { login } from "../api";

export default function Login({ onLogin, onIrParaSignup, onEsqueciSenha }) {
  const [email, setEmail] = useState("");
  const [senha, setSenha] = useState("");
  const [erro, setErro] = useState("");
  const [carregando, setCarregando] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setErro("");
    setCarregando(true);
    try {
      const dados = await login({ email: email.trim(), senha });
      localStorage.setItem("session_token", dados.session_token);
      localStorage.setItem("user_nome", dados.nome);
      localStorage.setItem("user_token", dados.token);
      onLogin(dados);
    } catch (err) {
      setErro(err.message || "Erro ao entrar");
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

        <h1 className="login-titulo">PhantomFix</h1>
        <p className="login-subtitulo">
          ASPM com IA · priorização e redução de alert fatigue
        </p>

        <form onSubmit={handleSubmit}>
          <label>
            E-mail
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoFocus
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
              autoComplete="current-password"
              placeholder="••••••••"
              required
            />
          </label>
          {onEsqueciSenha && (
            <p style={{ textAlign: "right", margin: "-8px 0 12px" }}>
              <button
                type="button"
                className="login-link-btn"
                style={{ fontSize: "13px" }}
                onClick={onEsqueciSenha}
              >
                Esqueci minha senha
              </button>
            </p>
          )}
          {erro && <p className="login-erro">{erro}</p>}
          <button type="submit" className="login-btn" disabled={carregando}>
            <span>{carregando ? "Entrando..." : "Entrar"}</span>
            {!carregando && (
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            )}
          </button>
        </form>

        <p className="login-link-alt">
          Não tem conta?{" "}
          <button type="button" className="login-link-btn" onClick={onIrParaSignup}>
            Criar conta
          </button>
        </p>
      </div>
    </div>
  );
}
