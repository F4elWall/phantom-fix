"""
PhantomFix — Analyser
Recebe o caminho do findings.json e o caminho de saída,
enriquece cada vulnerabilidade com score, justificativa,
categoria e recomendação usando Groq (Llama 3.3 70B),
ordena por score decrescente e salva o resultado.

Uso:
    python analyser.py <findings.json> <saida.json>
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

        for tentativa in range(5):
            try:
                resp = requests.post(self.url, headers=headers, json=payload, timeout=60)

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("retry-after", 60))
                    print(f"\n  ⏳ Rate limit — aguardando {retry_after}s...")
                    time.sleep(retry_after + 1)
                    continue

                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"]

            except requests.exceptions.RequestException as e:
                print(f"  Tentativa {tentativa+1} falhou: {e}")
                time.sleep(2)

        raise Exception("Falha ao comunicar com a API do Groq após 5 tentativas.")

    def barra_progresso(self, atual: int, total: int, largura: int = 35) -> str:
        preenchido = int(largura * atual / total) if total > 0 else 0
        barra      = "█" * preenchido + "░" * (largura - preenchido)
        pct        = int(100 * atual / total) if total > 0 else 0
        return f"  [{barra}] {pct:3d}% ({atual}/{total})"

    def analyze_findings(self, findings_path: Path, output_path: Path) -> Path | None:
        if not findings_path.exists():
            print(f"Arquivo não encontrado: {findings_path}")
            return None

        data  = json.loads(findings_path.read_text(encoding="utf-8"))
        vulns = data.get("vulnerabilidades", [])

        limite = int(os.getenv("ANALYSER_LIMITE", "0"))
        vulns_para_analisar = vulns[:limite] if limite > 0 else vulns

        total = len(vulns_para_analisar)
        print(f"\nAnalisando {total} vulnerabilidades com Groq ({self.model})...")
        print(f"  (intervalo de 2s entre chamadas para respeitar o rate limit)\n")

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

                if "```json" in clean:
                    clean = clean.split("```json")[1].split("```")[0].strip()
                elif "```" in clean:
                    clean = clean.split("```")[1].split("```")[0].strip()

                start = clean.find("{")
                end   = clean.rfind("}") + 1
                if start != -1 and end > start:
                    clean = clean[start:end]

                result = json.loads(clean)
                vuln["score"]         = result.get("score", "N/A")
                vuln["justificativa"] = result.get("justificativa", "N/A")
                vuln["categoria"]     = result.get("categoria", "N/A")
                vuln["recomendacao"]  = result.get("recomendacao", "N/A")
            except Exception as e:
                print(f"\n  ⚠ Erro em {vuln.get('id', '?')}: {e}")
                vuln["justificativa"] = f"Falha na análise: {str(e)[:100]}"
                vuln["score"]         = None
                vuln["categoria"]     = "Desconhecida"
                vuln["recomendacao"]  = "Revisar manualmente"

            enriched.append(vuln)
            time.sleep(2)

        print(self.barra_progresso(total, total), flush=True)
        print(f"\n  Análise concluída.")

        # Ordena por score decrescente
        enriched_ordenado = sorted(
            enriched,
            key=lambda v: float(v.get("score") or 0),
            reverse=True
        )

        output = {
            **data,
            "analisado_por_agente": True,
            "modelo_ia":            f"groq/{self.model}",
            "processado_em":        datetime.now().isoformat(),
            "vulnerabilidades":     enriched_ordenado,
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(output, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        print(f"Resultado enriquecido salvo em: {output_path}")
        return output_path


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python analyser.py <findings.json> <saida.json>")
        sys.exit(1)

    agent = AnalyserAgent()
    agent.analyze_findings(Path(sys.argv[1]), Path(sys.argv[2]))
