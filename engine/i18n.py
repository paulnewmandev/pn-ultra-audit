"""Language support. Built-in: Spanish (default) and English. Any other language is a JSON pack in engine/locales/<code>.json
(auto-discovered; no code change needed) with: name, html_lang, ui (dashboard strings), md (Markdown report strings) and
x (English sentence -> translation for CLI output and dashboard text). Missing keys fall back to English.
Resolution order: --lang > PN_AUDIT_LANG > system locale (LC_ALL/LC_MESSAGES/LANGUAGE/LANG, macOS AppleLanguages) > Spanish."""
import json, os, re, subprocess, sys

LOCALES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locales")
BUILTIN = {"es": "Español", "en": "English"}
ALIASES = {"japanese": "ja", "portuguese": "pt", "portugues": "pt", "português": "pt", "french": "fr", "francais": "fr", "français": "fr", "italian": "it", "italiano": "it", "hindi": "hi", "arabic": "ar", "arabe": "ar", "árabe": "ar", "jp": "ja", "chino": "zh", "japones": "ja", "japonés": "ja", "frances": "fr", "francés": "fr", "indu": "hi", "hindú": "hi", "zh-cn": "zh", "zh_cn": "zh", "zh-hans": "zh", "zh-tw": "zh", "zh_tw": "zh", "zh-hk": "zh", "cmn": "zh", "chinese": "zh", "spanish": "es", "english": "en", "español": "es"}


def available():
    """-> {code: native name}"""
    out = dict(BUILTIN)
    try:
        for f in sorted(os.listdir(LOCALES)):
            if f.endswith(".json"):
                try: out[f[:-5]] = json.load(open(os.path.join(LOCALES, f), encoding="utf-8")).get("name", f[:-5])
                except (OSError, ValueError): pass
    except OSError: pass
    return out


def normalize(code):
    c = (code or "").strip().lower().replace(".utf-8", "").replace(".utf8", "")
    if c in ALIASES: return ALIASES[c]
    c = re.split(r"[_\-.@]", c)[0]
    return ALIASES.get(c, c)


def _env_lang():
    for k in ("PN_AUDIT_LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"):
        v = os.environ.get(k, "")
        for tok in v.split(":"):
            tok = tok.strip()
            if tok and tok.upper() not in ("C", "POSIX") and not tok.upper().startswith(("C.", "POSIX")): return tok
    return None


def _mac_lang():
    if sys.platform != "darwin": return None
    try:
        r = subprocess.run(["defaults", "read", "-g", "AppleLanguages"], capture_output=True, text=True, timeout=3)
        m = re.search(r"\"?([A-Za-z]{2,3}(?:-[A-Za-z]+)?)\"?\s*[,)]", r.stdout)
        return m.group(1) if m else None
    except (OSError, subprocess.SubprocessError): return None


def resolve(requested):
    """-> a supported language code (never raises)."""
    av = available()
    if requested and requested != "auto":
        c = normalize(requested); return c if c in av else "en"
    for src in (_env_lang(), _mac_lang()):
        if src:
            c = normalize(src)
            if c in av: return c
            if c == "en": return "en"
    return "es"


def load(code):
    """-> pack dict (empty for built-ins)"""
    if code in BUILTIN: return {}
    try: return json.load(open(os.path.join(LOCALES, code + ".json"), encoding="utf-8"))
    except (OSError, ValueError): return {}
