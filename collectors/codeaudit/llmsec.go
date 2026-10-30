package codeaudit

import (
	"context"
	"regexp"

	"github.com/MUKE-coder/scout/core"
)

// LLMSecurity flags insecure patterns in LLM/agent applications (OWASP LLM Top 10):
// framework constructs that let a model run arbitrary code or shell, chains that
// evaluate model-generated code, and LLM output passed to an execution sink. It
// reads source only.
type LLMSecurity struct{}

func (LLMSecurity) ID() string              { return "code.llm-security" }
func (LLMSecurity) Category() core.Category { return core.CategoryCode }
func (LLMSecurity) Mode() core.Mode         { return core.ModePassive }
func (LLMSecurity) Description() string {
	return "An LLM/agent construct can execute model-controlled code or shell (OWASP LLM Top 10)"
}
func (LLMSecurity) OWASP() []string { return []string{"A03:2021"} }
func (LLMSecurity) ASVS() []string  { return []string{"V5.2.4"} }

// llmSecurityRules are high-signal, well-documented dangerous constructs in the
// common LLM frameworks (LangChain, LlamaIndex) plus insecure output handling.
var llmSecurityRules = []rule{
	{
		re:   regexp.MustCompile(`(?i)allow_dangerous_(code|requests|deserialization|tools)\s*=\s*True`),
		note: "a LangChain danger flag is enabled — model-supplied code, requests or objects are trusted",
	},
	{
		re:   regexp.MustCompile(`(?i)\b(PythonREPLTool|PythonAstREPLTool|PythonREPL|ShellTool|BashProcess|ComputerTool)\b`),
		note: "an agent tool can execute arbitrary Python or shell chosen by the model",
	},
	{
		re:   regexp.MustCompile(`(?i)\b(LLMMathChain|PALChain)\b|\bPAL\s*\(`),
		note: "this chain evaluates LLM-generated code — a known remote-code-execution vector",
	},
	{
		re:   regexp.MustCompile(`(?i)load_tools\s*\([^)]*["'](python_repl|terminal|shell|requests_all)["']`),
		note: "a code/shell/unrestricted-HTTP tool is loaded for the agent",
	},
	{
		re:   regexp.MustCompile(`(?i)create_(pandas_dataframe|csv|spark_dataframe|xorbits|sql)_agent\s*\(`),
		note: "a dataframe/SQL agent runs model-generated code or queries",
	},
	{
		re:   regexp.MustCompile(`(?i)(?:\beval|\bexec)\s*\([^)]*\b(completion|completions|llm|chat|response|answer|generated|message|output)\w*`),
		note: "LLM output is passed to eval/exec — insecure output handling (OWASP LLM02)",
	},
}

func (LLMSecurity) Run(_ context.Context, t core.Target) ([]core.Finding, error) {
	return scan(t, "code.llm-security", core.CategoryCode, core.SeverityHigh,
		"Insecure LLM/agent construct", remLLMSecurity, []string{"CWE-94"}, []string{"A03:2021"},
		llmSecurityRules, append(append([]string{}, codeExts...), ".ipynb")...)
}

var remLLMSecurity = core.Remediation{
	What:       "The code uses an LLM/agent construct that can run code, shell or queries chosen by the model, or feeds model output into an execution sink.",
	Why:        "A prompt-injected or adversarial model turns these into remote code execution (OWASP LLM01 prompt injection, LLM02 insecure output handling). The model's output is untrusted input.",
	How:        []core.Fix{{Stack: "generic", Language: "text", Code: "Do not run model-generated code/shell. Remove python/shell REPL tools and *_dangerous_* flags; if code execution is unavoidable, run it in a sandbox with no network and no secrets, allowlist tools, and never pass LLM output to eval/exec, SQL, a shell or raw HTML — validate and encode it like any other untrusted input."}},
	Effort:     core.EffortM,
	References: []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/", "https://cwe.mitre.org/data/definitions/94.html"},
}
