# FAQ and Troubleshooting

**The report only shows the header / a blank page.** Open `report.html` in a normal browser (Chrome, Firefox, Safari, Edge) with scripts enabled. If scripts are blocked (some IDE previews), a static summary and an error banner are shown; the full data is in `REPORT.md` and `findings.json`. Please file an issue with the banner text.

**Findings in my `examples/` or `docs/` folder.** Add them to `.pnauditignore`; project-type detection already ignores those folders.

**A finding is a false positive.** See [Suppressions and Baselines](Suppressions-and-Baselines); confirmed vs **to review** (needs context) findings are separate.

**The PDF is empty or missing.** Chrome/Chromium is required (`PDF skipped: Chrome/Chromium not found`). Set the `CHROME` path or install it.

**Links do not open my editor.** Click the folder button in the header and enter the absolute project path and editor (`vscode`, `cursor`, `windsurf`, `zed`, `vscodium`). Your browser may ask to allow the protocol.

**`--ssh` says connection failed.** Check key/agent auth, add `--accept-new-hostkey` the first time, and `--ssh-opts`. Passwords are never accepted on the command line.

**Results differ between runs.** Use `--baseline auto`; findings are matched by fingerprint, not by line number.

**Does it send my code anywhere?** No. It is offline except for features you explicitly enable (`--url`, `--psi` sends the URL to Google, `--git`, `--vercel-project`).

**Does it modify my project?** No. `--scaffold --write` is the only write mode and is opt-in; the fix scripts are generated, never executed.
