# Wiki source

These files are the wiki pages of the project (GitHub-wiki compatible: `Home.md`, `_Sidebar.md`, `_Footer.md`). They live in the main repository so they are versioned and reviewed with the code; `CLI-Reference`, `Auditors` and `Rule-Catalog` are generated (`python3 scripts/make_wiki.py`).

## Publish to the GitHub Wiki
1. In the repository settings enable **Wiki** and create the first page once (GitHub creates `https://github.com/paulnewmandev/pn-ultra-audit.wiki.git` on first save).
2. `bash scripts/publish_wiki.sh` clones the wiki repo into a temp folder, copies these pages and shows the diff; add `--push` to publish.

Read them here on GitHub, or locally: start at [Home.md](Home.md).
