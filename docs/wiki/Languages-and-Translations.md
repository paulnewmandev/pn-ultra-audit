# Languages and Translations

Available now: `es` (Español), `en` (English), `zh` (中文).

`--lang auto` (default) follows your system language: English if your locale is English, Chinese for `zh`, **Spanish otherwise**. Force one with `--lang en` or the `PN_AUDIT_LANG` environment variable. The terminal, the dashboard and the Markdown report are translated; the long remediation guides are available in English and Spanish and fall back to English for other languages.

## Add a language (10 minutes)
1. Copy `engine/locales/zh.json` to `engine/locales/<code>.json` (for example `pt.json`, `fr.json`).
2. Translate the values:
   - `name` - the language's own name, `html_lang` - for example `pt-BR`
   - `ui` - dashboard labels
   - `md` - Markdown report strings
   - `x` - English sentence -> translation (CLI messages and dashboard text)
3. Run `python3 audit.py examples/vulnerable-demo --lang <code>`.

The pack is auto-discovered (also in `--lang` choices). Anything you skip falls back to English. Send a pull request!
