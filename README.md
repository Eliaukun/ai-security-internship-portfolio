# AI Security Internship Portfolio

Target role: LLM-enabled security research / AI security red team intern.

This portfolio is built around two small but complete projects that connect traditional cyber security experience with current AI security work:

- `llm-rag-agent-security-eval`: a lightweight evaluator for prompt injection, RAG poisoning, sensitive data exposure, and risky Agent tool calls.
- `ai-soc-alert-triage`: an AI-ready SOC alert triage prototype that ranks alerts, maps common tactics, and generates analyst-friendly summaries.

The code intentionally uses local sample data and standard Python libraries so it can be reviewed and run without private datasets, API keys, or offensive infrastructure.

## Why This Role

The selected target position is **LLM-enabled security attack and defense / AI security red team intern**. It matches:

- Web security, red team exercise, and blue team monitoring experience.
- Practical familiarity with OWASP Top 10, common vulnerability reproduction, traffic analysis, and emergency response.
- New AI security needs around prompt injection, RAG/Agent security, automated evaluation, and security alert reasoning.

## Repository Layout

```text
.
|-- llm-rag-agent-security-eval/
|   |-- README.md
|   |-- data/
|   |-- src/
|   `-- tests/
|-- ai-soc-alert-triage/
|   |-- README.md
|   |-- data/
|   |-- src/
|   `-- tests/
|-- docs/
|   |-- target-role.md
|   `-- project-cv-bullets.md
`-- scripts/
    `-- make_cv_docx.py
```

## Quick Start

Run the LLM security evaluator:

```bash
python llm-rag-agent-security-eval/src/evaluator.py --input llm-rag-agent-security-eval/data/cases.json --format table
```

Run SOC alert triage:

```bash
python ai-soc-alert-triage/src/triage.py --input ai-soc-alert-triage/data/alerts.jsonl --top 5
```

Run tests:

```bash
python -m unittest discover -s llm-rag-agent-security-eval/tests
python -m unittest discover -s ai-soc-alert-triage/tests
```
