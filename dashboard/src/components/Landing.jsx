import logo from "../assets/logo.png";

const FEATURES = [
  {
    icon: "🛡️",
    titulo: "Segurança em primeiro lugar",
    desc: "Seu código é enviado de forma segura e mantido apenas o tempo necessário para a análise.",
  },
  {
    icon: "🤖",
    titulo: "Resultados enriquecidos com IA",
    desc: "Nossa inteligência correlaciona vulnerabilidades para fornecer contexto claro para você tomar as melhores decisões.",
  },
  {
    icon: "🔧",
    titulo: "Sugestões de correções automáticas",
    desc: "Receba recomendações práticas e objetivas para corrigir vulnerabilidades e acelerar seu desenvolvimento.",
  },
  {
    icon: "⚖️",
    titulo: "Comparação com leis e frameworks",
    desc: "Compare seus resultados com LGPD, ISO 27001, NIST, e outros frameworks de cibersegurança.",
  },
];

export default function Landing({ onEntrar, onCriarConta }) {
  return (
    <div className="landing">

      {/* ── Topbar ── */}
      <nav className="landing-nav">
        <div className="landing-nav-logo">
          <img src={logo} alt="PhantomFix" />
          <span>Phantom<strong>Fix</strong></span>
        </div>
        <div className="landing-nav-actions">
          <button className="landing-btn-ghost" onClick={onEntrar}>Entrar</button>
          <button className="landing-btn-primary" onClick={onCriarConta}>Criar conta</button>
        </div>
      </nav>

      {/* ── Hero ── */}
      <section className="landing-hero">
        <div className="landing-hero-content">
          <h1 className="landing-hero-titulo">
            Silêncio inteligente<br />
            para um código<br />
            <span className="landing-hero-destaque">verdadeiramente seguro.</span>
          </h1>
          <p className="landing-hero-desc">
            O PhantomFix encontra o que importa, prioriza o que é crítico
            e te ajuda a corrigir antes que os problemas apareçam.
          </p>
          <div className="landing-hero-btns">
            <button className="landing-btn-primary landing-btn-lg" onClick={onCriarConta}>
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="5" r="2.5" stroke="currentColor" strokeWidth="1.4"/><path d="M2 13c0-3 2.7-5 6-5s6 2 6 5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/></svg>
              Criar conta gratuitamente
            </button>
          </div>
          <div className="landing-hero-chips">
            <span>✓ Sem cartão de crédito</span>
            <span>✓ Configuração em minutos</span>
            <span>✓ Focado no que importa</span>
          </div>
        </div>

        <div className="landing-hero-orb">
          <img src={logo} alt="PhantomFix" className="landing-hero-img" />
        </div>
      </section>

      {/* ── Features ── */}
      <section className="landing-features">
        {FEATURES.map((f) => (
          <div className="landing-feature-card" key={f.titulo}>
            <span className="landing-feature-icon">{f.icon}</span>
            <h3 className="landing-feature-titulo">{f.titulo}</h3>
            <p className="landing-feature-desc">{f.desc}</p>
          </div>
        ))}
      </section>

      {/* ── Spirit banner ── */}
      <section className="landing-spirit">
        <div className="landing-spirit-esquerda">
          <p className="landing-spirit-label">SPIRIT AI ✦</p>
          <h2 className="landing-spirit-titulo">
            Seu assistente de IA para{" "}
            <span className="landing-hero-destaque">compliance.</span>
          </h2>
          <p className="landing-spirit-desc">
            Converse com o Spirit AI e entenda o impacto de dados críticos,
            orientações sobre os frameworks e tome decisões com confiança.
          </p>
          <button className="landing-btn-ghost landing-spirit-btn" onClick={onCriarConta}>
            Conhecer o Spirit AI ↗
          </button>
        </div>

        <div className="landing-spirit-chat">
          <div className="landing-chat-bubble landing-chat-user">
            Esse risco impacta a LGPD?
          </div>
          <div className="landing-chat-bubble landing-chat-spirit">
            <span className="landing-chat-tag">Spirit AI</span>
            Sim. Esse risco pode resultar em exposição de dados pessoais sem
            controle adequado, o que pode violar o artigo 46 da LGPD.
            <div className="landing-chat-rec">
              <p className="landing-chat-rec-titulo">Recomendações:</p>
              <p>✓ Revise o tratamento de dados pessoais neste fluxo</p>
              <p>✓ Implemente validação e sanitização das entradas</p>
              <p>✓ Aplique o princípio do menor privilégio.</p>
            </div>
          </div>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="landing-footer">
        <p>© 2025 PhantomFix. Todos os direitos reservados.</p>
        <div className="landing-footer-links">
          <a href="#">Termos de Uso</a>
          <a href="#">Privacidade</a>
          <a href="#">Contato</a>
        </div>
      </footer>

    </div>
  );
}
