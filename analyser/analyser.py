"""
PhantomFix — Analyser
Recebe o caminho do findings.json gerado pelo scanner,
enriquece cada vulnerabilidade com score, justificativa,
categoria e recomendação usando Groq (Llama 3.3 70B),
e salva o resultado_enriquecido.json na mesma pasta.

Uso:
    python analyser.py <caminho_do_findings.json>
"""

import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime
import requests


class AnalyserAgent:
    def __init__(self, groq_api_key=None):
        self.api_key = groq_api_key or os.getenv("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError("Defina a variável de ambiente GROQ_API_KEY.")
        self.url   = "https://api.groq.com/openai/v1/chat/completions"
        self.model = "llama-3.3-70b-versatile"

    def _call_llm(self, prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type":  "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "Você é um analista de segurança. Responda apenas com JSON válido, sem comentários adicionais."},
                {"role": "user",   "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens":  512
        }
        for tentativa in range(3):
            try:
                resp = requests.post(self.url, headers=headers, json=payload, timeout=60)
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"]
            except requests.exceptions.RequestException as e:
                print(f"  Tentativa {tentativa+1} falhou: {e}")
                time.sleep(2)
        raise Exception("Falha ao comunicar com a API do Groq após 3 tentativas.")

    def barra_progresso(self, atual: int, total: int, largura: int = 35) -> str:
        preenchido = int(largura * atual / total) if total > 0 else 0
        barra      = "█" * preenchido + "░" * (largura - preenchido)
        pct        = int(100 * atual / total) if total > 0 else 0
        return f"  [{barra}] {pct:3d}% ({atual}/{total})"

    def analyze_findings(self, findings_path: Path) -> Path | None:
        if not findings_path.exists():
            print(f"Arquivo não encontrado: {findings_path}")
            return None

        data  = json.loads(findings_path.read_text(encoding="utf-8"))
        vulns = data.get("vulnerabilidades", [])

        limite = int(os.getenv("ANALYSER_LIMITE", "0"))
        vulns_para_analisar = vulns[:limite] if limite > 0 else vulns

        total = len(vulns_para_analisar)
        print(f"\nAnalisando {total} vulnerabilidades com Groq ({self.model})...")

        enriched = []
        for idx, vuln in enumerate(vulns_para_analisar, 1):
            print(self.barra_progresso(idx - 1, total), end="\r", flush=True)

            prompt = f"""Analise a vulnerabilidade abaixo e retorne **apenas** um objeto JSON com as chaves "score", "justificativa", "categoria" e "recomendacao". O JSON deve estar em uma linha, sem quebras de linha extras.

Vulnerabilidade:
{json.dumps(vuln, indent=2, ensure_ascii=False)}

Responda exatamente assim (exemplo):
{{"score": 8.5, "justificativa": "...", "categoria": "...", "recomendacao": "..."}}"""

            try:
                raw   = self._call_llm(prompt)
                clean = raw.strip()
                if clean.startswith("```json"):
                    clean = clean.split("```json")[1].split("```")[0].strip()
                elif clean.startswith("```"):
                    clean = clean.split("```")[1].split("```")[0].strip()

                result = json.loads(clean)
                vuln["score"]        = result.get("score", "N/A")
                vuln["justificativa"] = result.get("justificativa", "N/A")
                vuln["categoria"]    = result.get("categoria", "N/A")
                vuln["recomendacao"] = result.get("recomendacao", "N/A")
            except Exception as e:
                print(f"\n  ⚠ Erro em {vuln.get('id', '?')}: {e}")
                vuln["justificativa"] = f"Falha na análise: {str(e)[:100]}"
                vuln["score"]        = None
                vuln["categoria"]    = "Desconhecida"
                vuln["recomendacao"] = "Revisar manualmente"

            enriched.append(vuln)
            time.sleep(0.2)

        print(self.barra_progresso(total, total), flush=True)
        print(f"\n  Análise concluída.")

        output = {
            **data,
            "analisado_por_agente": True,
            "modelo_ia":            f"groq/{self.model}",
            "processado_em":        datetime.now().isoformat(),
            "vulnerabilidades":     enriched,
        }

        output_path = findings_path.parent / "resultado_enriquecido.json"
        output_path.write_text(
            json.dumps(output, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        print(f"Resultado enriquecido salvo em: {output_path}")
        return output_path


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python analyser.py <caminho_do_findings.json>")
        sys.exit(1)

    agent = AnalyserAgent()
    agent.analyze_findings(Path(sys.argv[1]))
