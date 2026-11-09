"""Original technology logos (Simple Icons, CC0 data; trademarks belong to their owners) for the "detected stack" badges in the report.
Reads assets/logos/logos.json; names without a logo fall back to a monogram chip in the dashboard. Read-only, offline."""
import json, os

SLUGS = {"Python": "python", "JavaScript": "javascript", "TypeScript": "typescript", "PHP": "php", "Java": "openjdk", "Kotlin": "kotlin", "Swift": "swift", "Go": "go", "Rust": "rust", "C#": "csharp", "C": "c", "C++": "cplusplus", "Ruby": "ruby", "Dart": "dart", "Scala": "scala", "Solidity": "solidity", "Vue": "vuedotjs", "React": "react", "Svelte": "svelte", "Angular": "angular", "Shell": "gnubash", "PowerShell": "powershell", "Lua": "lua", "Perl": "perl", "R": "r", "Elixir": "elixir", "Haskell": "haskell", "Clojure": "clojure", "Julia": "julia", "Terraform": "terraform", "Docker": "docker", "PL/SQL": "oracle", "T-SQL": "microsoftsqlserver", "GraphQL": "graphql", "Zig": "zig", "Fortran": "fortran", "Groovy": "apachegroovy", "F#": "fsharp", "OCaml": "ocaml", "Erlang": "erlang", "SQLite": "sqlite", "PostgreSQL": "postgresql", "MySQL": "mysql", "MariaDB": "mariadb", "SQL Server": "microsoftsqlserver", "Oracle": "oracle", "MongoDB": "mongodb", "Redis": "redis", "AWS RDS": "amazonrds", "Android": "android", "iOS": "ios", "Flutter": "flutter", "React Native": "react", "Expo": "expo", "Next.js": "nextdotjs", "Node.js": "nodedotjs", "Laravel": "laravel", "Django": "django", "Spring": "spring", ".NET": "dotnet", "Rails": "rubyonrails", "Hardhat": "hardhat", "Kubernetes": "kubernetes", "GitHub Actions": "githubactions", "AWS": "amazonwebservices", "Azure": "microsoftazure", "Google Cloud": "googlecloud", "DigitalOcean": "digitalocean", "Hostinger": "hostinger", "Hetzner": "hetzner", "Vultr": "vultr", "Linode": "linode", "OVHcloud": "ovh", "Cloudflare": "cloudflare", "Vercel": "vercel", "Netlify": "netlify", "nginx": "nginx", "Apache": "apache", "Apache Kafka": "apachekafka", "RabbitMQ": "rabbitmq", "Elasticsearch": "elasticsearch", "Podman": "podman", "Claude Code": "claude", "Cursor": "cursor", "OpenAI Codex": "openai", "Windsurf": "windsurf", "GitHub Copilot": "githubcopilot", "Git": "git", "GitHub": "github", "GitLab": "gitlab", "Bitbucket": "bitbucket"}
ALIAS = {"react-dom": "React", "node": "Node.js", "nodejs": "Node.js", "next": "Next.js", "rails": "Rails", "postgres": "PostgreSQL", "mongo": "MongoDB", "html/js/css": None}
_CACHE = {}


def _logos():
    if "d" not in _CACHE:
        p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets", "logos", "logos.json")
        try: _CACHE["d"] = json.load(open(p, encoding="utf-8"))
        except (OSError, ValueError): _CACHE["d"] = {}
    return _CACHE["d"]


def _lum(h):
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (1, 3, 5))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def for_names(names):
    """{name: {"h": brand hex, "p": svg path (24x24), "k": ink}} for every name that has an original logo."""
    L, low, out = _logos(), {k.lower(): v for k, v in SLUGS.items()}, {}
    for n in names:
        key = ALIAS.get(str(n).lower(), n)
        if key is None: continue
        slug = SLUGS.get(key) or low.get(str(key).lower()); lg = L.get(slug) if slug else None
        if not lg: continue
        h = lg["hex"]
        if _lum(h) < 0.02: h = "#2a3150"
        out[n] = {"h": h, "p": lg["path"], "k": "#111827" if _lum(h) > 0.45 else "#ffffff"}
    return out
