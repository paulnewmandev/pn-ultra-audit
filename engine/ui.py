"""Terminal UI: Shannon-style phases with a live finding stream. Plain lines when not a TTY."""
import os, sys, time

C = dict(reset="\033[0m", dim="\033[2m", bold="\033[1m", red="\033[31m", green="\033[32m", yellow="\033[33m", blue="\033[34m", mag="\033[35m", cyan="\033[36m", gray="\033[90m", bred="\033[1;31m", bmag="\033[1;35m")
SEV_STYLE = {"critical": ("bmag", "✖"), "high": ("bred", "✖"), "medium": ("yellow", "▲"), "low": ("cyan", "●"), "info": ("gray", "·"), None: ("blue", "?")}
VERSION_BAR = 28


class UI:
    def __init__(self, total, color="auto", quiet=False, verbose=False, stream_limit=14):
        self.n, self.total, self.quiet, self.verbose, self.limit = 0, total, quiet, verbose, stream_limit
        self.tty = sys.stdout.isatty()
        self.color = (color == "always") or (color == "auto" and self.tty and "NO_COLOR" not in os.environ)
        self.live = self.tty and color != "always" or (color == "always" and self.tty)
        self.t0 = time.time(); self.t_stage = self.t0; self.name = ""; self.frac = 0.0; self.extra = ""; self.last_len = 0; self.streamed = 0; self.suppressed = 0; self.stats = []; self.mute = False

    def c(self, k, s): return f"{C[k]}{s}{C['reset']}" if self.color else s

    def _bar(self, f, w=VERSION_BAR): n = int(max(0, min(1, f)) * w); return "█" * n + "░" * (w - n)

    def _clear(self):
        if self.live and self.last_len: sys.stdout.write("\r" + " " * self.last_len + "\r"); self.last_len = 0

    def _progress(self, end=""):
        if not (self.live and not self.quiet): return
        s = f"   {self._bar(self.frac)} {int(self.frac * 100):>3}%  {self.extra}"
        self.last_len = len(s) + 2
        sys.stdout.write("\r" + self.c("dim", s) + end); sys.stdout.flush()

    def p(self, text=""):
        if self.quiet: return
        self._clear(); print(text); self._progress()

    def banner(self, title, rows):
        if self.quiet: return
        w = max(len(title) + 6, 64)
        print(self.c("bmag", "┌" + "─" * (w - 2) + "┐"))
        print(self.c("bmag", "│") + self.c("bold", title.center(w - 2)) + self.c("bmag", "│"))
        print(self.c("bmag", "└" + "─" * (w - 2) + "┘"))
        for k, v in rows: print(f" {self.c('gray', (k + ':').ljust(12))} {v}")
        print()

    def start(self, name):
        if self.mute: return
        self.n += 1; self.name = name; self.t_stage = time.time(); self.frac = 0.0; self.extra = ""; self.streamed = 0; self.suppressed = 0
        if self.quiet: return
        self._clear(); print(self.c("bold", f"▶ [{self.n:02d}/{self.total:02d}] {name}")); self._progress()
        if not self.live: pass

    def update(self, done, total, extra=""):
        if self.mute: return
        self.frac = done / max(total, 1); self.extra = extra; self._progress()

    def note(self, text):
        if self.mute: return
        self.extra = text; self._progress()

    def finding(self, f, force=False):
        """stream one finding. Confirmed medium+ by default; everything with --verbose."""
        if self.quiet or self.mute: return
        sev = f.get("severity"); conf = f.get("status") == "confirmed"
        show = self.verbose or force or (conf and sev in ("critical", "high", "medium"))
        if not show: return
        if self.streamed >= self.limit and not self.verbose: self.suppressed += 1; return
        self.streamed += 1
        col, ic = SEV_STYLE.get(sev if conf else None)
        tag = (sev or "").upper() if conf else "REVIEW"
        loc = f"{f['file']}:{f['line']}"
        self._clear()
        print("   " + self.c(col, f"{ic} {tag:<8}") + " " + self.c("gray", f"{f['rule']:<20}") + " " + f"{f['title'][:62]:<62} " + self.c("dim", loc[-46:]))
        self._progress()

    def done(self, summary="", warn=False):
        if self.mute: return
        dt = time.time() - self.t_stage
        if self.quiet: return
        self._clear()
        if self.suppressed: print("   " + self.c("dim", f"… {self.suppressed} more (use --verbose to stream every finding)"))
        mark = self.c("yellow", "!") if warn else self.c("green", "✓")
        print(f"   {mark} {summary} " + self.c("dim", f"({dt:.1f}s)")); print()
        self.stats.append((self.name, summary, dt))

    def skip(self, name, why):
        if self.quiet: return
        print(self.c("dim", f"▷ [--/{self.total:02d}] {name} - skipped: {why}")); print()

    def table(self, title, headers, rows):
        if self.quiet: return
        print(self.c("bold", title))
        w = [max(len(str(x)) for x in [h] + [r[i] for r in rows]) for i, h in enumerate(headers)]
        print("  " + "  ".join(self.c("gray", h.ljust(w[i])) for i, h in enumerate(headers)))
        for r in rows: print("  " + "  ".join(str(x).ljust(w[i]) for i, x in enumerate(r)))
        print()

    def finish(self, text):
        if not self.quiet: print(self.c("bold", text) + self.c("dim", f"  (total {time.time() - self.t0:.1f}s)"))

    def verdict(self, ok, text):
        if self.quiet: return
        print(self.c("green" if ok else "bred", ("✔ " if ok else "✘ ") + text))
