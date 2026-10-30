package codeaudit

import "testing"

func TestLLMSecurityDetects(t *testing.T) {
	dir := repoWith(t, map[string]string{
		// LangChain danger flag + code-exec agent.
		"agent.py": "agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=True)\n",
		// A python REPL tool handed to the model.
		"tools.py": "from langchain_experimental.tools import PythonREPLTool\ntools = [PythonREPLTool()]\n",
		// Known eval-based chain.
		"math.py": "chain = LLMMathChain.from_llm(llm)\n",
		// Insecure output handling: eval over the model's response.
		"out.js": "const result = eval(completion.choices[0].text)\n",
	})
	got := run(t, LLMSecurity{}, dir)
	files := map[string]bool{}
	for _, f := range got {
		files[f.Asset.File] = true
	}
	for _, want := range []string{"agent.py", "tools.py", "math.py", "out.js"} {
		if !files[want] {
			t.Errorf("expected an LLM-security finding in %s; got %v", want, files)
		}
	}
}

func TestLLMSecurityNoFalsePositives(t *testing.T) {
	dir := repoWith(t, map[string]string{
		// Ordinary, safe LLM usage.
		"chat.py": "resp = client.chat.completions.create(model='gpt-4', messages=msgs)\nprint(resp.choices[0].message.content)\n",
		"safe.py": "agent = create_react_agent(llm, tools=[search_tool])\n",
		// A comment or disabled flag should not fire.
		"cfg.py": "config = {'allow_dangerous_code': False}\n",
	})
	if got := run(t, LLMSecurity{}, dir); len(got) != 0 {
		t.Fatalf("expected no findings on safe LLM code, got %+v", got)
	}
}
