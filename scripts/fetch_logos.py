#!/usr/bin/env python3
"""Downloads the brand logos used by the README badges from Simple Icons (data licensed CC0-1.0; the logos themselves remain trademarks of their
owners and are used only to identify supported technologies - no endorsement is implied). Cached in assets/logos/ so make_assets.py works offline.
Run:  python3 scripts/fetch_logos.py"""
import json, os, re, urllib.error, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "assets", "logos"); os.makedirs(OUT, exist_ok=True)
VER = "13.21.0"
BASE = f"https://cdn.jsdelivr.net/npm/simple-icons@{VER}"
SLUGS = {  # display name -> simple-icons slug
    "Python": "python", "JavaScript": "javascript", "TypeScript": "typescript", "PHP": "php", "Java": "openjdk", "Kotlin": "kotlin", "Swift": "swift", "Go": "go", "Rust": "rust", "C#": "csharp", "C": "c", "C++": "cplusplus",
    "Ruby": "ruby", "Dart": "dart", "Scala": "scala", "Solidity": "solidity", "Vue": "vuedotjs", "React": "react", "Svelte": "svelte", "Angular": "angular", "Shell": "gnubash", "PowerShell": "powershell", "Lua": "lua", "Perl": "perl",
    "R": "r", "Elixir": "elixir", "Haskell": "haskell", "Clojure": "clojure", "Julia": "julia", "Terraform": "terraform", "Docker": "docker", "PL/SQL": "oracle", "T-SQL": "microsoftsqlserver", "GraphQL": "graphql", "Zig": "zig",
    "Fortran": "fortran", "Groovy": "apachegroovy", "F#": "fsharp", "OCaml": "ocaml", "Erlang": "erlang",
    "SQLite": "sqlite", "PostgreSQL": "postgresql", "MySQL": "mysql", "MariaDB": "mariadb", "SQL Server": "microsoftsqlserver", "Oracle": "oracle", "MongoDB": "mongodb", "Redis": "redis", "AWS RDS": "amazonrds",
    "Android": "android", "iOS": "ios", "Flutter": "flutter", "React Native": "react", "Expo": "expo", "Next.js": "nextdotjs", "Node.js": "nodedotjs", "Laravel": "laravel", "Django": "django", "Spring": "spring", ".NET": "dotnet",
    "Rails": "rubyonrails", "Hardhat": "hardhat", "Kubernetes": "kubernetes", "GitHub Actions": "githubactions",
    "AWS": "amazonwebservices", "Azure": "microsoftazure", "Google Cloud": "googlecloud", "DigitalOcean": "digitalocean", "Hostinger": "hostinger", "Hetzner": "hetzner", "Vultr": "vultr", "Linode": "linode", "OVHcloud": "ovh",
    "Cloudflare": "cloudflare", "Vercel": "vercel", "Netlify": "netlify", "nginx": "nginx", "Apache": "apache", "Apache Kafka": "apachekafka", "RabbitMQ": "rabbitmq", "Elasticsearch": "elasticsearch", "Podman": "podman",
    "Claude Code": "claude", "Cursor": "cursor", "OpenAI Codex": "openai", "Windsurf": "windsurf", "GitHub Copilot": "githubcopilot", "Git": "git", "GitHub": "github", "GitLab": "gitlab", "Bitbucket": "bitbucket"}


def get(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "pn-ultra-audit"}), timeout=30) as r: return r.read().decode("utf-8")
    except (urllib.error.URLError, OSError): return None


def slugify(t): return re.sub(r"[^a-z0-9]", "", t.lower().replace("+", "plus").replace("&", "and").replace(".", "dot").replace("#", "sharp"))


def main():
    data = get(BASE + "/_data/simple-icons.json")
    hexes = {}
    if data:
        for e in json.loads(data).get("icons", []): hexes[e.get("slug") or slugify(e["title"])] = e["hex"]
    done, missing = {}, []
    for name, slug in SLUGS.items():
        svg = get(f"{BASE}/icons/{slug}.svg")
        if not svg: missing.append(name); continue
        paths = re.findall(r'<path[^>]*\sd="([^"]+)"', svg)
        if not paths: missing.append(name); continue
        open(os.path.join(OUT, slug + ".svg"), "w").write(svg)
        done[slug] = dict(hex="#" + hexes.get(slug, "6b7280"), path=" ".join(paths))
    json.dump(done, open(os.path.join(OUT, "logos.json"), "w"), indent=0)
    open(os.path.join(OUT, "README.md"), "w").write(f"# Brand logos\n\nIcons from [Simple Icons](https://simpleicons.org) v{VER} (data under CC0-1.0). The logos are trademarks of their respective owners and are shown only to identify the technologies PN-Ultra-Audit supports; no endorsement is implied. Refresh with `python3 scripts/fetch_logos.py`.\n")
    print(len(done), "logos cached;", "missing (monogram fallback):", ", ".join(missing) or "none")


if __name__ == "__main__":
    main()
