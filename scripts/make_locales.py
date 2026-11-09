#!/usr/bin/env python3
"""Builds engine/locales/<code>.json from scripts/locale_data/<code>.py (UI, MD dicts keyed like the English sources; X = index into
locale_data/_xlist.json, the English reference list the translations were written against).  Run: python3 scripts/make_locales.py"""
import importlib, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from engine import dashboard, render_report  # noqa: E402

DATA = os.path.join(ROOT, "scripts", "locale_data"); OUT = os.path.join(ROOT, "engine", "locales")
XLIST = json.load(open(os.path.join(DATA, "_xlist.json"), encoding="utf-8"))
EN_UI, EN_MD = dashboard.I18N["en"], render_report.T["en"]
LANGS = ["ja", "pt", "fr", "it", "hi", "ar"]
CNT = "{n} confirmed findings: {c} critical, {h} high, {m} medium and {l} low."
EXTRA = {  # strings keyed by their English text that are not in the static index list (severity words and the risk sentence with placeholders)
    "ja": {"medium": "中", "low": "低", "info": "情報", CNT: "確定した検出 {n} 件: 重大 {c}、高 {h}、中 {m}、低 {l}。"},
    "pt": {"medium": "médio", "low": "baixo", "info": "info", CNT: "{n} achados confirmados: {c} críticos, {h} altos, {m} médios e {l} baixos."},
    "fr": {"medium": "moyen", "low": "faible", "info": "info", CNT: "{n} constats confirmés : {c} critiques, {h} élevés, {m} moyens et {l} faibles."},
    "it": {"medium": "medio", "low": "basso", "info": "info", CNT: "{n} rilevamenti confermati: {c} critici, {h} alti, {m} medi e {l} bassi."},
    "hi": {"medium": "मध्यम", "low": "निम्न", "info": "जानकारी", CNT: "{n} पुष्ट निष्कर्ष: {c} गंभीर, {h} उच्च, {m} मध्यम और {l} निम्न।"},
    "ar": {"medium": "متوسط", "low": "منخفض", "info": "معلومة", CNT: "{n} نتيجة مؤكدة: {c} حرجة و{h} عالية و{m} متوسطة و{l} منخفضة."}}


def merge_zh(zx):
    path = os.path.join(OUT, "zh.json"); pack = json.load(open(path, encoding="utf-8"))
    for i, v in zx.items(): pack["x"].setdefault(XLIST[i], v)
    pack["dir"] = "ltr"; json.dump(pack, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("zh: x", len(pack["x"]))


def main():
    sys.path.insert(0, os.path.dirname(DATA))
    merge_zh(importlib.import_module("locale_data.zh_extra").X)
    for code in LANGS:
        m = importlib.import_module(f"locale_data.{code}")
        miss_ui = [k for k in EN_UI if k not in m.UI]; miss_md = [k for k in EN_MD if k not in m.MD]
        x = {XLIST[i]: v for i, v in m.X.items() if 0 <= i < len(XLIST)}; x.update(EXTRA.get(code, {}))
        pack = {"code": code, "name": m.NAME, "html_lang": m.HTML_LANG, "dir": m.DIR, "ui": m.UI, "md": m.MD, "x": x,
                "_note": "Community language pack (see docs/wiki/Languages-and-Translations.md). Missing keys fall back to English."}
        json.dump(pack, open(os.path.join(OUT, code + ".json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print(f"{code}: ui {len(m.UI) - len(miss_ui)}/{len(EN_UI)} md {len(m.MD) - len(miss_md)}/{len(EN_MD)} x {len(x)}/{len(XLIST)}" + (f"  MISSING ui={miss_ui} md={miss_md}" if miss_ui or miss_md else ""))


if __name__ == "__main__":
    main()
