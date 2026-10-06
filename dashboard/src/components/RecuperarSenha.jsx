{/*# PhantomFix — Copyright (C) 2025–2026 Rafael Pedro, Bernardo Coroa,
   # Giovanna Esmelardi, Gustavo Enrique
   # SPDX-License-Identifier: GPL-3.0-or-later
   # Licenciado sob a GNU GPL v3. Veja LICENSE.md na raiz do repositório.*/}

import { useState } from "react";
import logo from "../assets/logo.png";
import { solicitarReset, confirmarReset } from "../api";

/**
 * RecuperarSenha.jsx
 *
 * Duas etapas:
 *  1. "solicitar"  — usuário digita o e-mail
 *  2. "redefinir"  — usuário digitou a nova senha (chegou pelo link com ?reset_token=...)
 *
 * Props:
 *  resetToken    — string | null  (preenchido quando a URL já traz o token)
 *  onVoltar      — () => void     (volta para o Login)
 *  onSucesso     — () => void     (senha redefinida → vai para o Login)
 */
export default function RecuperarSenha({ resetToken, onVoltar, onSucesso }) {
  const etapa = resetToken ? "redefinir" : "solicitar";

  // ── Etapa 1: solicitar ───────────────────────────────────────────────────
  const [email, setEmail]         = useState("");
  const [enviado, setEnviado]     = useState(false);

  // ── Etapa 2: redefinir ───────────────────────────────────────────────────
  const [novaSenha, setNovaSenha]         = useState("");
  const [confirmarSenha, setConfirmarSenha] = useState("");
  const [sucesso, setSucesso]             = useState(false);

  // ── Compartilhado ────────────────────────────────────────────────────────
  const [erro, setErro]           = useState("");
  const [carregando, setCarregando] = useState(false);

  // ── Handlers ─────────────────────────────────────────────────────────────

  async function handleSolicitar(e) {
    e.preventDefault();
    setErro("");
    setCarregando(true);
    try {
      await solicitarReset(email.trim());
      setEnviado(true);
    } catch (err) {
      setErro(err.message || "Erro ao enviar e-mail");
    } finally {
      setCarregando(false);
    }
  }

  async function handleRedefinir(e) {
    e.preventDefault();
    setErro("");
    if (novaSenha !== confirmarSenha) {
      setErro("As senhas não coincidem.");
      return;
    }
    if (novaSenha.length < 6) {
      setErro("A senha deve ter no mínimo 6 caracteres.");
      return;
    }
    setCarregando(true);
    try {
      await confirmarReset(resetToken, novaSenha);
      setSucesso(true);
    } catch (err) {
      setErro(err.message || "Erro ao redefinir senha");
    } finally {
      setCarregando(false);
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────

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

        {/* ── Etapa 1: solicitar ── */}
        {etapa === "solicitar" && !enviado && (
          <>
            <p className="login-subtitulo">Recuperação de senha</p>
            <form onSubmit={handleSolicitar}>
              <label>
                E-mail da conta
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoFocus
                  placeholder="seu@email.com"
                  required
                />
              </label>
              {erro && <p className="login-erro">{erro}</p>}
              <button type="submit" className="login-btn" disabled={carregando}>
                <span>{carregando ? "Enviando..." : "Enviar link de recuperação"}</span>
              </button>
            </form>
            <p className="login-link-alt">
              <button type="button" className="login-link-btn" onClick={onVoltar}>
                ← Voltar para o login
              </button>
            </p>
          </>
        )}

        {/* ── Etapa 1: confirmação de envio ── */}
        {etapa === "solicitar" && enviado && (
          <>
            <p className="login-subtitulo">Verifique seu e-mail</p>
            <p style={{ color: "var(--cor-texto-2, #9CA3AF)", fontSize: "14px", lineHeight: "1.6", marginBottom: "24px" }}>
              Se o e-mail <strong style={{ color: "var(--cor-texto, #F9FAFB)" }}>{email}</strong> estiver
              cadastrado, você receberá as instruções em instantes.
              O link é válido por <strong style={{ color: "var(--cor-texto, #F9FAFB)" }}>30 minutos</strong>.
            </p>
            <p className="login-link-alt">
              <button type="button" className="login-link-btn" onClick={onVoltar}>
                ← Voltar para o login
              </button>
            </p>
          </>
        )}

        {/* ── Etapa 2: redefinir ── */}
        {etapa === "redefinir" && !sucesso && (
          <>
            <p className="login-subtitulo">Criar nova senha</p>
            <form onSubmit={handleRedefinir}>
              <label>
                Nova senha
                <input
                  type="password"
                  value={novaSenha}
                  onChange={(e) => setNovaSenha(e.target.value)}
                  autoFocus
                  placeholder="••••••••"
                  required
                />
              </label>
              <label>
                Confirmar nova senha
                <input
                  type="password"
                  value={confirmarSenha}
                  onChange={(e) => setConfirmarSenha(e.target.value)}
                  placeholder="••••••••"
                  required
                />
              </label>
              {erro && <p className="login-erro">{erro}</p>}
              <button type="submit" className="login-btn" disabled={carregando}>
                <span>{carregando ? "Salvando..." : "Salvar nova senha"}</span>
              </button>
            </form>
          </>
        )}

        {/* ── Etapa 2: sucesso ── */}
        {etapa === "redefinir" && sucesso && (
          <>
            <p className="login-subtitulo">Senha redefinida!</p>
            <p style={{ color: "var(--cor-texto-2, #9CA3AF)", fontSize: "14px", lineHeight: "1.6", marginBottom: "24px" }}>
              Sua senha foi atualizada com sucesso. Faça login com a nova senha.
            </p>
            <button className="login-btn" onClick={onSucesso}>
              <span>Ir para o login</span>
            </button>
          </>
        )}
      </div>
    </div>
  );
}
