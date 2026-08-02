import { useState } from "react";
import logo from "../assets/logo.png";
import { regenToken, checkLink } from "../api";

const EXE_URL = "https://github.com/F4elWall/phantom-fix/releases/tag/phantom-fix.exe"; // substituir pela URL real do .exe

export default function Welcome({ usuario, onAcessarDashboard }) {
  const [token, setToken] = useState(usuario?.token || localStorage.getItem("user_token") || "");
  const [popupAberto, setPopupAberto] = useState(true);
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
      setPopupAberto(true); // reabre o popup com novo token
    } catch { /* ignore */ }
    finally { setRegenando(false); }
  }

  async function handleAcessar() {
    setErroLink("");
    setVerificando(true);
    try {
      const dados = await checkLink();
if (dados.client_linked) {
  localStorage.setItem("client_linked", "true");
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
    <>
      {/* ── Pop-up do token ─────────────────────────────────────────────── */}
      {popupAberto && (
        <div className="wlc-overlay" onClick={() => setPopupAberto(false)}>
          <div className="wlc-popup" onClick={(e) => e.stopPropagation()}>
            <button className="wlc-popup-close" onClick={() => setPopupAberto(false)}>✕</button>

            <div className="wlc-popup-avatar">
              <img src={logo} alt="PhantomFix" />
              <span className="wlc-popup-star">✦</span>
            </div>

            <h2 className="wlc-popup-titulo">Seu token exclusivo</h2>
            <p className="wlc-popup-sub">
              Este token é exibido apenas uma vez.<br />
              Guarde-o com segurança.
            </p>

            <div className="wlc-token-row">
              <code className="wlc-token-code">pf_{token}</code>
              <button className="wlc-token-copy" onClick={copiarToken} title="Copiar">
                {copiado ? (
                  <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><path d="M3 9l4 4 8-8" stroke="var(--ecto)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
                ) : (
                  <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><rect x="6" y="6" width="9" height="9" rx="2" stroke="currentColor" strokeWidth="1.5"/><path d="M3 12V3h9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>
                )}
              </button>
            </div>

            <div className="wlc-aviso-box">
              <span className="wlc-aviso-icon">⚠</span>
              <div>
                <p className="wlc-aviso-titulo">Importante: este token não poderá ser recuperado.</p>
                <p className="wlc-aviso-desc">Caso perca, gere um novo quando necessário.</p>
              </div>
            </div>

            <button className="wlc-btn-regen" onClick={handleRegen} disabled={regenando}>
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2 8a6 6 0 1 0 1.5-3.9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/><path d="M2 4v4h4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
              {regenando ? "Gerando..." : "Gerar novo Token"}
            </button>
          </div>
        </div>
      )}

      {/* ── Tela principal ──────────────────────────────────────────────── */}
      <div className="wlc-tela">
        {/* Topbar */}
        <div className="wlc-topbar">
          <div className="wlc-topbar-logo">
            <img src={logo} alt="" />
            <span>Phantom<strong>Fix</strong></span>
          </div>
          <button className="wlc-help-btn">
            <svg width="15" height="15" viewBox="0 0 15 15" fill="none"><circle cx="7.5" cy="7.5" r="6.5" stroke="currentColor" strokeWidth="1.3"/><path d="M7.5 5a1.5 1.5 0 0 1 .87 2.72C7.8 8.15 7.5 8.58 7.5 9.1" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/><circle cx="7.5" cy="11" r=".6" fill="currentColor"/></svg>
            Precisa de ajuda?
          </button>
        </div>

        {/* Corpo */}
        <div className="wlc-corpo">
          {/* Coluna esquerda */}
          <div className="wlc-esquerda">
            <p className="wlc-bem-vindo-label">Bem-vindo ao</p>
            <h1 className="wlc-hero-titulo">PhantomFix!</h1>
            <p className="wlc-hero-desc">
              Sua conta foi criada com sucesso. Antes de iniciar sua primeira análise, vincule o{" "}
              <span className="wlc-destaque">PhantomFix Client</span> à sua conta usando seu token único.
            </p>

            <div className="wlc-seguranca-card">
              <div className="wlc-seguranca-icon">
                <svg width="22" height="22" viewBox="0 0 22 22" fill="none"><path d="M11 2L4 5v6c0 4.4 3 8.2 7 9 4-0.8 7-4.6 7-9V5l-7-3z" stroke="var(--violet)" strokeWidth="1.5" strokeLinejoin="round"/><path d="M8 11l2 2 4-4" stroke="var(--violet)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
              </div>
              <div>
                <p className="wlc-seguranca-titulo">Segurança em primeiro lugar</p>
                <p className="wlc-seguranca-desc">
                  Seu token é único e intransferível, garantindo que apenas você possa vincular o cliente desktop à sua conta.
                </p>
              </div>
            </div>
          </div>

          {/* Coluna direita — passos */}
          <div className="wlc-direita">
            {/* Passo 1 */}
            <div className="wlc-passo">
              <div className="wlc-passo-num">1</div>
              <div className="wlc-passo-corpo">
                <h3 className="wlc-passo-titulo">Baixe o Cliente Oficial</h3>
                <p className="wlc-passo-desc">Clique no botão abaixo para baixar o PhantomFix Client para Windows.</p>
                <a href={EXE_URL} className="wlc-download-btn" download>
                  <svg width="20" height="20" viewBox="0 0 20 20" fill="none"><rect x="2" y="2" width="7" height="5" rx="1" fill="white" opacity=".9"/><rect x="11" y="2" width="7" height="5" rx="1" fill="white" opacity=".6"/><rect x="2" y="9" width="7" height="5" rx="1" fill="white" opacity=".6"/><rect x="11" y="9" width="7" height="5" rx="1" fill="white" opacity=".3"/></svg>
                  Download PhantomFix Client
                  <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><path d="M9 3v9M5 9l4 4 4-4" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><path d="M3 15h12" stroke="white" strokeWidth="1.5" strokeLinecap="round"/></svg>
                </a>
                <p className="wlc-download-meta">Windows (.exe) • Versão 1.0.0</p>
              </div>
            </div>

            <div className="wlc-separador" />

            {/* Passo 2 */}
            <div className="wlc-passo">
              <div className="wlc-passo-num">2</div>
              <div className="wlc-passo-corpo">
                <h3 className="wlc-passo-titulo">Vincule o Cliente</h3>
                <p className="wlc-passo-desc">No PhantomFix Client, ao abrir o aplicativo, cole seu token único no campo indicado.</p>

                <div className="wlc-token-preview" onClick={() => setPopupAberto(true)} title="Ver token completo">
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2 8h2M12 8h2M5 5l-2 3 2 3M11 5l2 3-2 3" stroke="var(--violet)" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  <span>Seu token exclusivo</span>
                  <span className="wlc-token-hint">clique para ver</span>
                </div>

                <button className="wlc-btn-regen wlc-btn-regen-outline" onClick={handleRegen} disabled={regenando}>
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2 8a6 6 0 1 0 1.5-3.9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/><path d="M2 4v4h4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  {regenando ? "Gerando..." : "Gerar novo Token"}
                </button>
              </div>
            </div>

            <div className="wlc-separador" />

            {/* Passo 3 */}
            <div className="wlc-passo">
              <div className="wlc-passo-num">3</div>
              <div className="wlc-passo-corpo">
                <h3 className="wlc-passo-titulo">Acesse o Dashboard</h3>
                <p className="wlc-passo-desc">Após vincular o cliente com sucesso, clique no botão abaixo para acessar o dashboard e começar a realizar suas análises.</p>
              </div>
            </div>
          </div>
        </div>

        {/* Footer fixo */}
        <div className="wlc-footer">
          <div className="wlc-footer-aviso">
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><circle cx="9" cy="9" r="7.5" stroke="var(--ink-dim)" strokeWidth="1.3"/><path d="M9 5v4" stroke="var(--ink-dim)" strokeWidth="1.3" strokeLinecap="round"/><circle cx="9" cy="12.5" r=".7" fill="var(--ink-dim)"/></svg>
            <div>
              <p className="wlc-footer-titulo">Ainda não vinculou o cliente?</p>
              <p className="wlc-footer-desc">Você ainda poderá gerar um novo token a qualquer momento nas configurações da sua conta.</p>
            </div>
          </div>
          <div className="wlc-footer-direita">
            {erroLink && <p className="wlc-footer-erro">{erroLink}</p>}
            <button className="wlc-acessar-btn" onClick={handleAcessar} disabled={verificando}>
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2 8h9M8 5l4 3-4 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><path d="M6 2a6 6 0 1 0 6 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>
              {verificando ? "Verificando..." : "Token vinculado - Acessar Dashboard"}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
