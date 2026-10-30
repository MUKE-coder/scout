---
title: AI / LLM application security
description: Scout flags insecure LLM and agent constructs in your source — model-driven code execution, eval-based chains, insecure output handling — and leaked LLM-provider keys.
---

Apps built on LLMs have their own failure modes: a prompt-injected or adversarial
model is **untrusted input**, and any construct that lets it run code, shell or
queries becomes remote code execution. The `code.llm-security` check
(`scout scan --repo .`) flags those patterns statically, mapped to the
[OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

## What it flags

| Pattern | Why it's dangerous |
|---|---|
| `allow_dangerous_code=True`, `allow_dangerous_requests=True`, `allow_dangerous_deserialization=True` | LangChain danger flags — the model's code/requests/objects are trusted |
| `PythonREPLTool`, `PythonAstREPLTool`, `ShellTool`, `BashProcess` | agent tools that run arbitrary Python/shell the model chooses |
| `LLMMathChain`, `PALChain`, `PAL(` | chains that `eval` model-generated code — a known RCE vector |
| `load_tools([… "python_repl" / "terminal" / "shell" …])` | a code/shell tool loaded for the agent |
| `create_pandas_dataframe_agent(…)`, `create_sql_agent(…)` | dataframe/SQL agents run model-generated code or queries |
| `eval(completion…)`, `exec(response…)` | LLM output passed straight to an execution sink (**LLM02 insecure output handling**) |

It covers Python, JavaScript/TypeScript and notebooks (`.ipynb`), and honours
`#nosec` / `biome-ignore` suppressions.

## Leaked model-provider keys

The secrets scanner (`code.secrets`) also recognises LLM-provider credentials, so
a committed key is caught like any other secret:

- **OpenAI** (`sk-…`, `sk-proj-…`), **Anthropic** (`sk-ant-…`),
  **Hugging Face** (`hf_…`), **Replicate** (`r8_…`), Google AI (`AIza…`).

## How to fix

Treat model output as untrusted input. Don't run model-generated code or shell;
remove REPL/shell tools and `*_dangerous_*` flags. If code execution is genuinely
required, run it in a **sandbox with no network and no secrets**, allowlist the
tools an agent may call, and never pass LLM output to `eval`/`exec`, a SQL query, a
shell or raw HTML — validate and encode it like any other untrusted input.

:::note
This is static detection of dangerous constructs. Live prompt-injection testing
against a running model endpoint is a separate, non-deterministic exercise Scout
does not perform — it would mean sending adversarial prompts to a third-party
model, which Scout deliberately avoids.
:::
