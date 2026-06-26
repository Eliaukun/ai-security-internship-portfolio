# Design Notes

## Scope

AI Security Defense Lab focuses on two defensive workflows:

- Evaluating LLM applications that combine model prompts, retrieved context, and Agent tool calls.
- Prioritizing SOC alerts with transparent scoring and analyst-facing summaries.

The goal is not to replace a production SIEM, SOAR, or model safety platform. The goal is to keep the core risk logic small enough to inspect, test, and extend.

## Architecture

```text
sample data -> parser -> rules -> score -> report
```

Both prototypes follow the same pattern:

1. Load local JSON or JSONL test cases.
2. Normalize input fields.
3. Apply rule-based detections.
4. Calculate severity or priority.
5. Emit table or JSON output.

This makes behavior predictable and avoids hiding important security decisions inside an opaque model call.

## Extension Ideas

- Add LLM-as-judge evaluation for ambiguous prompt injection cases.
- Store findings in SARIF or another machine-readable reporting format.
- Add a policy file for tool allowlists, blocked destinations, and severity weights.
- Build a small web dashboard for reviewing evaluation and triage results.

