import json
import os
from pathlib import Path
from datetime import datetime
import requests
import time

class AnalyserAgent:
    def __init__(self, groq_api_key=None):
        self.api_key = groq_api_key or os.getenv("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError("Defina a variável de ambiente GROQ_API_KEY ou passe a chave no construtor.")
        self.url = "https://api.groq.com/openai/v1/chat/completions"
        self.model = "llama-3.3-70b-versatile"  # gratuito, rápido e inteligente

    def _call_llm(self, prompt: str) -> str:
        """Envia prompt para o Groq e retorna o texto da resposta."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "Você é um analista de segurança. Responda apenas com JSON válido, sem comentários adicionais."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 512
        }
        for tentativa in range(3):  # retry simples
            try:
                resp = requests.post(self.url, headers=headers, json=payload, timeout=60)
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"]
            except requests.exceptions.RequestException as e:
                print(f"Tentativa {tentativa+1} falhou: {e}")
                time.sleep(2)
        raise Exception("Falha ao comunicar com a API do Groq após 3 tentativas.")

    def analyze_findings(self, findings_path: Path):
        if not findings_path.exists():
            print("Arquivo não encontrado!")
            return None

        data = json.loads(findings_path.read_text(encoding="utf-8"))
        vulns = data.get("vulnerabilidades", [])

        print(f"Analisando {len(vulns)} vulnerabilidades com Groq (Llama 3.3 70B)...")

        enriched = []
        for idx, vuln in enumerate(vulns[:20], 1):  # limite de 20 para não abusar
            print(f"Processando {idx}/{min(len(vulns), 20)}: {vuln.get('tipo', 'N/A')[:60]}")

            prompt = f"""Analise a vulnerabilidade abaixo e retorne **apenas** um objeto JSON com as chaves "score", "justificativa", "categoria" e "recomendacao". O JSON deve estar em uma linha, sem quebras de linha extras.

Vulnerabilidade:
{json.dumps(vuln, indent=2, ensure_ascii=False)}

Responda exatamente assim (exemplo):
{{"score": 8.5, "justificativa": "...", "categoria": "...", "recomendacao": "..."}}"""

            try:
                raw = self._call_llm(prompt)
                # Limpeza básica: extrair JSON se vier entre crases
                clean = raw.strip()
                if clean.startswith("```json"):
                    clean = clean.split("```json")[1].split("```")[0].strip()
                elif clean.startswith("```"):
                    clean = clean.split("```")[1].split("```")[0].strip()

                # Tenta carregar o JSON
                result = json.loads(clean)
                # Garante que todas as chaves esperadas existam
                vuln["score"] = result.get("score", "N/A")
                vuln["justificativa"] = result.get("justificativa", "N/A")
                vuln["categoria"] = result.get("categoria", "N/A")
                vuln["recomendacao"] = result.get("recomendacao", "N/A")
            except Exception as e:
                print(f"  ⚠ Erro ao processar esta vulnerabilidade: {e}")
                # Fallback para não perder o registro
                vuln["justificativa"] = f"Falha na análise: {str(e)[:100]}"
                vuln["score"] = None
                vuln["categoria"] = "Desconhecida"
                vuln["recomendacao"] = "Revisar manualmente"

            enriched.append(vuln)
            time.sleep(0.2)  # pequena pausa para não sobrecarregar a API

        output = {
            **data,
            "analisado_por_agente": True,
            "modelo_ia": "groq/llama-3.3-70b",
            "processado_em": datetime.now().isoformat(),
            "vulnerabilidades": enriched
        }

        output_path = findings_path.parent / "resultado_enriquecido.json"
        output_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n✅ Análise com Groq concluída! Salvo em: {output_path}")
        return output_path

if __name__ == "__main__":
    agent = AnalyserAgent()  # chave virá da env GROQ_API_KEY
    agent.analyze_findings(Path("../core/resultado.json"))
