/**
 * PhantomFix — VaultDownload
 * Botão de download do Vault Obsidian com verificação de status.
 *
 * Props:
 *   protocolo  — string  — ID do scan atual
 *   className  — string  — classe CSS extra (opcional)
 */

import { useState, useEffect } from "react";
import { statusVault, baixarVault } from "../api";

export default function VaultDownload({ protocolo, className = "" }) {
  const [pronto,       setPronto]       = useState(false);
  const [verificando,  setVerificando]  = useState(true);
  const [baixando,     setBaixando]     = useState(false);
  const [erro,         setErro]         = useState(null);

  // Verifica se o vault está pronto para download
  useEffect(() => {
    if (!protocolo) return;

    let cancelado = false;
    let tentativas = 0;
    const MAX_TENTATIVAS = 20;   // até ~60s de polling

    async function verificar() {
      try {
        const data = await statusVault(protocolo);
        if (cancelado) return;

        if (data.vault_pronto) {
          setPronto(true);
          setVerificando(false);
          return;
        }

        tentativas++;
        if (tentativas < MAX_TENTATIVAS) {
          setTimeout(verificar, 3000);
        } else {
          setVerificando(false);   // desiste silenciosamente
        }
      } catch {
        if (!cancelado) setVerificando(false);
      }
    }

    verificar();
    return () => { cancelado = true; };
  }, [protocolo]);

  async function handleDownload() {
    if (!pronto || baixando) return;
    setBaixando(true);
    setErro(null);
    try {
      await baixarVault(protocolo);
    } catch (e) {
      setErro("Não foi possível baixar o vault. Tente novamente.");
    } finally {
      setBaixando(false);
    }
  }

  // Vault ainda sendo gerado — spinner discreto
  if (verificando && !pronto) {
    return (
      <span className={`vault-download vault-download--gerando ${className}`} title="Gerando Vault Obsidian...">
        <span className="vault-download__spinner" />
        Gerando vault…
      </span>
    );
  }

  // Vault não disponível (timeout ou erro silencioso)
  if (!pronto) return null;

  return (
    <div className={`vault-download ${className}`}>
      <button
        className="vault-download__btn"
        onClick={handleDownload}
        disabled={baixando}
        title="Baixar Vault Obsidian — abra no Obsidian para ver o grafo de conexões entre findings"
      >
        {baixando ? (
          <>
            <span className="vault-download__spinner" />
            Baixando…
          </>
        ) : (
          <>
            <span className="vault-download__icon">🔮</span>
            Vault Obsidian
          </>
        )}
      </button>
      {erro && <p className="vault-download__erro">{erro}</p>}
    </div>
  );
}
