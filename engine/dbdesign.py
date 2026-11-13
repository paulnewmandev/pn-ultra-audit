"""Database DESIGN audit: modelling, relations, normalization, indexes, constraints, types, naming, migrations.

One neutral schema model is built from many sources and the same checks run on it:
  static  - SQL DDL, Prisma, Django models, Rails schema/migrations, Laravel migrations, SQLAlchemy, TypeORM
  live    - SQLite (PRAGMA), PostgreSQL (psql) and MySQL/MariaDB (mysql) catalogs, read-only
Read-only and stdlib-only. Deterministic structural facts are "confirmed"; naming/modelling heuristics are
"needs_validation" (they depend on intent). Fix SQL is only generated as text, never executed.

Schema model: {table: dict(cols=[dict(name,type,null,default,pk,unique)], pk=[names], fks=[dict(cols,ref,rcols,ondelete)],
               idx=[dict(cols,unique)], src=(file,line))}
"""
import os, re, shutil, sqlite3, subprocess
from urllib.parse import urlparse, unquote

RESERVED = {"user", "order", "group", "table", "select", "index", "key", "check", "column", "default", "desc", "from", "grant", "primary", "references", "role", "rank", "row", "type", "view", "when"}
MONEY = re.compile(r"(price|amount|total|balance|cost|salary|fee|tax|subtotal|payment|revenue|rate)", re.I)
DATEISH = re.compile(r"(^|_)(date|at|time|timestamp|datetime|dob|birthday|expires?|expiry)(_|$)|(_at|_date|_on)$", re.I)
UNIQUEISH = {"email", "username", "slug", "sku", "uuid", "handle", "token", "code", "iban", "tax_id", "dni", "phone_number", "api_key"}
CSVISH = re.compile(r"(^|_)(tags|ids|list|items|roles|permissions|categories|labels)$", re.I)
TEXTT = re.compile(r"^(var)?char|text|string|citext|clob|nvarchar|nchar", re.I)
FLOATT = re.compile(r"^(float|double|real|float4|float8)", re.I)
SKIP_TIMESTAMPS = re.compile(r"(migrations?|schema_migrations|alembic_version|ar_internal_metadata|sessions?|cache|failed_jobs|jobs|password_resets?|personal_access_tokens|django_|auth_|sqlite_|_prisma_migrations|knex_)", re.I)


def new_table(src):
    return dict(cols=[], pk=[], fks=[], idx=[], src=src)


def _col(name, typ="", null=True, default=None, pk=False, unique=False):
    return dict(name=name, type=(typ or "").strip(), null=null, default=default, pk=pk, unique=unique)


def _snake(s):
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", s)
    return s.lower()


def _plural(s):
    s = s.lower()
    return s + ("es" if s.endswith(("s", "x", "z", "ch", "sh")) else "s") if not s.endswith("y") else s[:-1] + "ies"


def _line(text, pos): return text[:pos].count("\n") + 1


# ────────────────────────────── parsers (source -> model) ──────────────────────────────
def parse_sql(text, rel, schema):
    for m in re.finditer(r"CREATE\s+(?:TEMP(?:ORARY)?\s+|UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"\[]?([\w.]+)[`\"\]]?\s*\(", text, re.I):
        i, depth = m.end(), 1
        while i < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[i], 0); i += 1
        body = text[m.end():i - 1]
        name = m.group(1).split(".")[-1].lower(); t = new_table((rel, _line(text, m.start()))); schema[name] = t
        parts, cur, d = [], "", 0
        for ch in body:
            if ch == "(": d += 1
            elif ch == ")": d -= 1
            if ch == "," and d == 0: parts.append(cur); cur = ""
            else: cur += ch
        parts.append(cur)
        for p in (x.strip() for x in parts):
            if not p: continue
            mm = re.match(r"(?:CONSTRAINT\s+\S+\s+)?PRIMARY\s+KEY\s*\(([^)]*)\)", p, re.I)
            if mm: t["pk"] += [re.sub(r"[`\"\[\]\s]", "", c).lower() for c in mm.group(1).split(",")]; continue
            mm = re.match(r"(?:CONSTRAINT\s+\S+\s+)?FOREIGN\s+KEY\s*\(([^)]*)\)\s*REFERENCES\s+[`\"\[]?([\w.]+)[`\"\]]?\s*(?:\(([^)]*)\))?(.*)", p, re.I | re.S)
            if mm:
                t["fks"].append(dict(cols=[re.sub(r"[`\"\[\]\s]", "", c).lower() for c in mm.group(1).split(",")], ref=mm.group(2).split(".")[-1].lower(), rcols=[], ondelete=bool(re.search(r"ON\s+DELETE", mm.group(4), re.I)))); continue
            mm = re.match(r"(?:CONSTRAINT\s+\S+\s+)?UNIQUE(?:\s+(?:KEY|INDEX))?\s*(?:\S+\s*)?\(([^)]*)\)", p, re.I)
            if mm: t["idx"].append(dict(cols=[re.sub(r"[`\"\[\]\s]|\(.*", "", c).lower() for c in mm.group(1).split(",")], unique=True)); continue
            mm = re.match(r"(?:KEY|INDEX)\s+\S*\s*\(([^)]*)\)", p, re.I)
            if mm: t["idx"].append(dict(cols=[re.sub(r"[`\"\[\]\s]|\(.*", "", c).lower() for c in mm.group(1).split(",")], unique=False)); continue
            if re.match(r"(CHECK|EXCLUDE|LIKE|PERIOD)\b", p, re.I): continue
            mm = re.match(r"[`\"\[]?(\w+)[`\"\]]?\s+([A-Za-z][\w]*(?:\s*\([^)]*\))?(?:\s+(?:unsigned|varying|precision|with(?:out)? time zone))*)(.*)", p, re.I | re.S)
            if not mm: continue
            cn, ty, rest = mm.group(1).lower(), mm.group(2), mm.group(3)
            pk = bool(re.search(r"PRIMARY\s+KEY", rest, re.I)); uq = bool(re.search(r"\bUNIQUE\b", rest, re.I))
            dm = re.search(r"DEFAULT\s+(\S+)", rest, re.I)
            t["cols"].append(_col(cn, ty, not (pk or re.search(r"NOT\s+NULL", rest, re.I)), dm.group(1) if dm else None, pk, uq))
            if pk: t["pk"].append(cn)
            rm = re.search(r"REFERENCES\s+[`\"\[]?([\w.]+)[`\"\]]?", rest, re.I)
            if rm: t["fks"].append(dict(cols=[cn], ref=rm.group(1).split(".")[-1].lower(), rcols=[], ondelete=bool(re.search(r"ON\s+DELETE", rest, re.I))))
            if uq: t["idx"].append(dict(cols=[cn], unique=True))
    for m in re.finditer(r"ALTER\s+TABLE\s+(?:ONLY\s+)?[`\"\[]?([\w.]+)[`\"\]]?\s+ADD\s+(?:CONSTRAINT\s+\S+\s+)?FOREIGN\s+KEY\s*\(([^)]*)\)\s*REFERENCES\s+[`\"\[]?([\w.]+)", text, re.I):
        t = schema.get(m.group(1).split(".")[-1].lower())
        if t: t["fks"].append(dict(cols=[re.sub(r"[`\"\[\]\s]", "", c).lower() for c in m.group(2).split(",")], ref=m.group(3).split(".")[-1].lower(), rcols=[], ondelete=False))
    for m in re.finditer(r"ALTER\s+TABLE\s+(?:ONLY\s+)?[`\"\[]?([\w.]+)[`\"\]]?\s+ADD\s+(?:CONSTRAINT\s+\S+\s+)?PRIMARY\s+KEY\s*\(([^)]*)\)", text, re.I):
        t = schema.get(m.group(1).split(".")[-1].lower())
        if t: t["pk"] += [re.sub(r"[`\"\[\]\s]", "", c).lower() for c in m.group(2).split(",")]
    for m in re.finditer(r"CREATE\s+(UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?\S+\s+ON\s+(?:ONLY\s+)?[`\"\[]?([\w.]+)[`\"\]]?\s*(?:USING\s+\w+\s*)?\(([^)]*)\)", text, re.I):
        t = schema.get(m.group(2).split(".")[-1].lower())
        if t: t["idx"].append(dict(cols=[re.sub(r"[`\"\[\]\s]|\(.*|\s+(asc|desc).*", "", c, flags=re.I).lower() for c in m.group(3).split(",")], unique=bool(m.group(1))))


def parse_prisma(text, rel, schema):
    for m in re.finditer(r"^model\s+(\w+)\s*\{(.*?)^\}", text, re.M | re.S):
        name = _snake(m.group(1)); t = new_table((rel, _line(text, m.start()))); schema[name] = t
        for ln in m.group(2).splitlines():
            ln = ln.split("//")[0].strip()
            if not ln: continue
            if ln.startswith("@@"):
                mm = re.match(r"@@(id|unique|index)\s*\(\s*(?:fields:\s*)?\[([^\]]*)\]", ln)
                if mm:
                    cols = [c.strip() for c in mm.group(2).split(",")]
                    if mm.group(1) == "id": t["pk"] += cols
                    else: t["idx"].append(dict(cols=cols, unique=mm.group(1) == "unique"))
                continue
            mm = re.match(r"(\w+)\s+(\w+)(\[\])?(\?)?\s*(.*)", ln)
            if not mm: continue
            cn, ty, lst, opt, rest = mm.groups()
            rel_m = re.search(r"@relation\((?=[^)]*fields:\s*\[([^\]]*)\])(?:[^)]*references:\s*\[([^\]]*)\])?([^)]*)\)", rest)
            if rel_m:
                t["fks"].append(dict(cols=[c.strip() for c in rel_m.group(1).split(",")], ref=_snake(ty), rcols=[], ondelete="onDelete" in rel_m.group(3))); continue
            if lst or ty[0].isupper() and ty not in ("String", "Int", "BigInt", "Float", "Decimal", "Boolean", "DateTime", "Json", "Bytes"): continue   # relation back-reference / enum handled below
            pk = "@id" in rest; uq = "@unique" in rest
            t["cols"].append(_col(cn, ty, not (opt is None) if False else bool(opt), "default" if "@default" in rest else None, pk, uq))
            if pk: t["pk"].append(cn)
            if uq: t["idx"].append(dict(cols=[cn], unique=True))


def parse_django(text, rel, schema):
    for m in re.finditer(r"^class\s+(\w+)\(([^)]*Model[^)]*)\):\s*\n((?:[ \t]+.*\n|\n)+)", text, re.M):
        if "abstract = True" in m.group(3): continue
        name = _snake(m.group(1)); t = new_table((rel, _line(text, m.start()))); schema[name] = t
        t["pk"] = ["id"]; t["cols"].append(_col("id", "AutoField", False, None, True))
        for fm in re.finditer(r"^[ \t]+(\w+)\s*=\s*(?:models\.)?(\w+Field|ForeignKey|OneToOneField|ManyToManyField)\(([^\n]*)", m.group(3), re.M):
            cn, ft, args = fm.groups()
            if ft == "ManyToManyField": continue
            if ft in ("ForeignKey", "OneToOneField"):
                rm = re.match(r"\s*['\"]?([\w.]+)['\"]?", args); ref = _snake((rm.group(1) if rm else "").split(".")[-1])
                t["fks"].append(dict(cols=[cn + "_id"], ref=ref, rcols=[], ondelete="on_delete" in args))
                t["cols"].append(_col(cn + "_id", "FK", "null=True" in args, None));
                if ft == "OneToOneField" or "db_index=False" not in args: t["idx"].append(dict(cols=[cn + "_id"], unique=ft == "OneToOneField"))
                continue
            if "primary_key=True" in args: t["pk"] = [cn]
            tm = {"CharField": "varchar", "TextField": "text", "FloatField": "float", "DecimalField": "decimal", "DateTimeField": "datetime", "DateField": "date", "EmailField": "varchar", "SlugField": "varchar", "UUIDField": "uuid", "JSONField": "json"}.get(ft, ft)
            t["cols"].append(_col(cn, tm, "null=True" in args, "default" if "default=" in args else None, "primary_key=True" in args, "unique=True" in args))
            if "unique=True" in args or "db_index=True" in args: t["idx"].append(dict(cols=[cn], unique="unique=True" in args))
        for im in re.finditer(r"(?:indexes|unique_together|constraints)\s*=\s*[\[(]([^\]\)]*[\])])", m.group(3)):
            for fm in re.finditer(r"fields\s*=\s*\[([^\]]*)\]|\(([^()]*)\)", im.group(1)):
                cols = [c.strip(" '\"") for c in (fm.group(1) or fm.group(2) or "").split(",") if c.strip(" '\"")]
                if cols: t["idx"].append(dict(cols=cols, unique=False))


def parse_rails(text, rel, schema):
    for m in re.finditer(r"create_table\s+[\"':]+(\w+)[\"']?([^\n]*?)do\s*\|(\w+)\|(.*?)^\s*end", text, re.M | re.S):
        name = m.group(1).lower(); v = m.group(3); t = new_table((rel, _line(text, m.start()))); schema[name] = t
        if "id: false" not in m.group(2): t["pk"] = ["id"]; t["cols"].append(_col("id", "bigint", False, None, True))
        if re.search(rf"^\s*{v}\.timestamps\b", m.group(4), re.M): t["cols"] += [_col("created_at", "datetime", False), _col("updated_at", "datetime", False)]
        for ln in m.group(4).splitlines():
            cm = re.match(rf"\s*{v}\.(\w+)\s+[\"':]+(\w+)[\"']?(.*)", ln)
            if not cm: continue
            ty, cn, rest = cm.group(1), cm.group(2), cm.group(3)
            if ty in ("references", "belongs_to"):
                t["cols"].append(_col(cn + "_id", "bigint", "null: false" not in rest))
                if "foreign_key" in rest: t["fks"].append(dict(cols=[cn + "_id"], ref=_plural(cn), rcols=[], ondelete="on_delete" in rest))
                if "index: false" not in rest: t["idx"].append(dict(cols=[cn + "_id"], unique="unique: true" in rest))
            elif ty == "index": t["idx"].append(dict(cols=[c for c in re.findall(r"[\"':](\w+)", cm.group(2) + rest)], unique="unique: true" in rest))
            elif ty not in ("timestamps",): t["cols"].append(_col(cn, ty, "null: false" not in rest, "default" if "default:" in rest else None))
            if ty == "timestamps": t["cols"] += [_col("created_at", "datetime", False), _col("updated_at", "datetime", False)]
    for m in re.finditer(r"add_index\s+[\"':]+(\w+)[\"']?\s*,\s*(\[[^\]]*\]|[\"':]+\w+[\"']?)([^\n]*)", text):
        t = schema.get(m.group(1).lower())
        if t: t["idx"].append(dict(cols=re.findall(r"\w+", m.group(2)), unique="unique: true" in m.group(3)))
    for m in re.finditer(r"add_foreign_key\s+[\"':]+(\w+)[\"']?\s*,\s*[\"':]+(\w+)[\"']?(?:,\s*column:\s*[\"':]+(\w+))?([^\n]*)", text):
        t = schema.get(m.group(1).lower())
        if t: t["fks"].append(dict(cols=[m.group(3) or _plural(m.group(2)).rstrip("s") + "_id"], ref=m.group(2).lower(), rcols=[], ondelete="on_delete" in m.group(4)))


def parse_laravel(text, rel, schema):
    for m in re.finditer(r"Schema::create\(\s*['\"](\w+)['\"].*?function\s*\([^)]*\)\s*\{(.*?)^\s*\}\);", text, re.S | re.M):
        name = m.group(1).lower(); t = new_table((rel, _line(text, m.start()))); schema[name] = t
        for ln in re.finditer(r"\$table->(\w+)\(([^)]*)\)([^;]*);", m.group(2)):
            ty, args, chain = ln.groups(); a0 = re.findall(r"['\"](\w+)['\"]", args)
            if ty in ("id", "bigIncrements", "increments", "uuid") and ty != "uuid" or (ty == "uuid" and not a0):
                nm = a0[0] if a0 else "id"; t["pk"].append(nm); t["cols"].append(_col(nm, "bigint", False, None, True))
            elif ty in ("foreignId", "foreignUuid", "unsignedBigInteger", "unsignedInteger"):
                nm = a0[0] if a0 else ""; t["cols"].append(_col(nm, "bigint", "nullable" in chain))
                if "constrained" in chain or "foreign" in chain: t["fks"].append(dict(cols=[nm], ref=(re.search(r"constrained\(\s*['\"](\w+)", chain) or [None, _plural(nm[:-3])])[1], rcols=[], ondelete="onDelete" in chain or "cascadeOnDelete" in chain or "nullOnDelete" in chain))
                if "index" in chain or "unique" in chain or "constrained" in chain or "foreign" in chain: t["idx"].append(dict(cols=[nm], unique="unique" in chain))
            elif ty == "timestamps": t["cols"] += [_col("created_at", "timestamp"), _col("updated_at", "timestamp")]
            elif ty == "softDeletes": t["cols"].append(_col("deleted_at", "timestamp"))
            elif ty in ("index", "unique", "primary"):
                cols = a0 if "[" not in args else re.findall(r"['\"](\w+)['\"]", args)
                (t["pk"].extend(cols) if ty == "primary" else t["idx"].append(dict(cols=cols, unique=ty == "unique")))
            elif ty == "foreign" and a0: t["fks"].append(dict(cols=a0[:1], ref=(re.search(r"on\(\s*['\"](\w+)", chain) or [None, "?"])[1], rcols=[], ondelete="onDelete" in chain))
            elif a0 and ty not in ("dropColumn", "rememberToken"):
                t["cols"].append(_col(a0[0], ty, "nullable" in chain, "default" if "default(" in chain else None, False, "unique" in chain))
                if "unique" in chain: t["idx"].append(dict(cols=[a0[0]], unique=True))
                elif "index" in chain: t["idx"].append(dict(cols=[a0[0]], unique=False))


def parse_sqlalchemy(text, rel, schema):
    for m in re.finditer(r"^class\s+(\w+)\([^)]*(?:Base|db\.Model|DeclarativeBase|Model)[^)]*\):\s*\n((?:[ \t]+.*\n|\n)+)", text, re.M):
        body = m.group(2); tn = re.search(r"__tablename__\s*=\s*['\"](\w+)['\"]", body)
        if not tn: continue
        t = new_table((rel, _line(text, m.start()))); schema[tn.group(1).lower()] = t
        for cm in re.finditer(r"^[ \t]+(\w+)\s*(?::[^=\n]+)?=\s*(?:db\.)?(?:Column|mapped_column)\(([^\n]*)", body, re.M):
            cn, args = cm.groups(); ty = (re.match(r"\s*(?:db\.)?(\w+)", args) or [None, ""])[1]
            if ty in ("ForeignKey",): ty = ""
            fk = re.search(r"ForeignKey\(\s*['\"](\w+)\.(\w+)['\"]", args)
            pk = "primary_key=True" in args; uq = "unique=True" in args
            t["cols"].append(_col(cn, ty, "nullable=False" not in args and not pk, "default" if "default" in args else None, pk, uq))
            if pk: t["pk"].append(cn)
            if fk:
                t["fks"].append(dict(cols=[cn], ref=fk.group(1).lower(), rcols=[fk.group(2)], ondelete="ondelete" in args))
                if "index=True" in args or uq: t["idx"].append(dict(cols=[cn], unique=uq))
            elif "index=True" in args or uq: t["idx"].append(dict(cols=[cn], unique=uq))
        for im in re.finditer(r"Index\(\s*['\"]\w+['\"]\s*,([^)]*)\)", body):
            t["idx"].append(dict(cols=re.findall(r"['\"](\w+)['\"]", im.group(1)), unique="unique=True" in im.group(1)))


def parse_typeorm(text, rel, schema):
    for m in re.finditer(r"@Entity\(([^)]*)\)\s*(?:export\s+)?class\s+(\w+)[^{]*\{(.*?)^\}", text, re.M | re.S):
        tn = re.search(r"['\"](\w+)['\"]", m.group(1)); name = (tn.group(1) if tn else _snake(m.group(2))).lower()
        t = new_table((rel, _line(text, m.start()))); schema[name] = t
        for cm in re.finditer(r"((?:@\w+\((?:[^()]|\([^()]*\))*\)\s*)+)(\w+)[!?]?\s*:\s*([\w\[\]<>| ]+)", m.group(3)):
            decos, cn, ty = cm.groups()
            if "@PrimaryGeneratedColumn" in decos or "@PrimaryColumn" in decos: t["pk"].append(cn); t["cols"].append(_col(cn, ty, False, None, True)); continue
            if "@ManyToOne" in decos or "@OneToOne" in decos:
                jc = re.search(r"name:\s*['\"](\w+)", decos); nm = jc.group(1) if jc else cn + "Id"
                t["fks"].append(dict(cols=[nm], ref=_snake(ty.strip()), rcols=[], ondelete="onDelete" in decos)); t["cols"].append(_col(nm, "FK", True)); continue
            if "@Column" in decos or "@CreateDateColumn" in decos or "@UpdateDateColumn" in decos:
                t["cols"].append(_col(cn, ty.strip().lower(), "nullable: true" in decos, "default" if "default" in decos else None, False, "unique: true" in decos))
                if "unique: true" in decos: t["idx"].append(dict(cols=[cn], unique=True))
        for im in re.finditer(r"@(Unique|Index)\(\s*(?:['\"]\w+['\"]\s*,\s*)?\[([^\]]*)\]", m.group(0)):
            t["idx"].append(dict(cols=re.findall(r"['\"](\w+)['\"]", im.group(2)), unique=im.group(1) == "Unique"))
        for im in re.finditer(r"@Index\(\)\s*@Column[^\n]*\n\s*(\w+)", m.group(3)): t["idx"].append(dict(cols=[im.group(1)], unique=False))
        for im in re.finditer(r"@Index\(\)\s*(?:@\w+\([^)]*\)\s*)*(\w+)", m.group(3)): t["idx"].append(dict(cols=[im.group(1)], unique=False))


# ────────────────────────────── live introspection ──────────────────────────────
def from_sqlite(path):
    schema = {}
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    try:
        cur = con.cursor()
        for (tn,) in cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
            t = new_table((os.path.basename(path), 1)); schema[tn.lower()] = t
            pk = []
            for cid, cn, ty, nn, dflt, p in cur.execute(f'PRAGMA table_info("{tn}")').fetchall():
                t["cols"].append(_col(cn.lower(), ty, not (nn or p), dflt, bool(p)));
                if p: pk.append((p, cn.lower()))
            t["pk"] = [c for _, c in sorted(pk)]
            groups = {}
            for row in cur.execute(f'PRAGMA foreign_key_list("{tn}")').fetchall(): groups.setdefault(row[0], []).append(row)
            for rows in groups.values(): t["fks"].append(dict(cols=[r[3].lower() for r in rows], ref=rows[0][2].lower(), rcols=[], ondelete=rows[0][6] not in ("NO ACTION", None, "")))
            for row in cur.execute(f'PRAGMA index_list("{tn}")').fetchall():
                cols = [r[2].lower() for r in cur.execute(f'PRAGMA index_info("{row[1]}")').fetchall() if r[2]]
                if cols: t["idx"].append(dict(cols=cols, unique=bool(row[2])))
    finally:
        con.close()
    return schema


def _split_rows(out): return [r.split("|") for r in out.strip().splitlines() if r.strip()]


def from_postgres(url):
    u = urlparse(url)
    if not shutil.which("psql"): return None, "psql not installed"
    env = dict(os.environ); env["PGPASSWORD"] = unquote(u.password or env.get("PGPASSWORD", "")); env["PGOPTIONS"] = "-c default_transaction_read_only=on"
    base = ["psql", "-h", u.hostname or "localhost", "-p", str(u.port or 5432), "-U", unquote(u.username or "postgres"), "-d", (u.path or "/postgres")[1:] or "postgres", "-At", "-F", "|", "-v", "ON_ERROR_STOP=1", "-c"]
    ns = "table_schema NOT IN ('pg_catalog','information_schema')"
    def q(sql):
        r = subprocess.run(base + [sql], env=env, capture_output=True, text=True, timeout=40)
        if r.returncode: raise RuntimeError(r.stderr.strip()[:140])
        return _split_rows(r.stdout)
    schema = {}; label = f"postgres://{u.hostname}{u.path}"
    try:
        for tn, cn, dt, nl, df in q(f"SELECT table_name,column_name,data_type,is_nullable,coalesce(column_default,'') FROM information_schema.columns WHERE {ns} AND table_name IN (SELECT table_name FROM information_schema.tables WHERE table_type='BASE TABLE' AND {ns}) ORDER BY table_name,ordinal_position"):
            schema.setdefault(tn.lower(), new_table((label, 1)))["cols"].append(_col(cn.lower(), dt, nl == "YES", df or None))
        for tn, cn in q("SELECT c.conrelid::regclass::text, a.attname FROM pg_constraint c JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=ANY(c.conkey) WHERE c.contype='p'"):
            t = schema.get(tn.lower().split(".")[-1].strip('"'))
            if t: t["pk"].append(cn.lower())
        for tn, cols, rt, od in q("SELECT conrelid::regclass::text, (SELECT string_agg(attname,',') FROM pg_attribute WHERE attrelid=conrelid AND attnum=ANY(conkey)), confrelid::regclass::text, confdeltype FROM pg_constraint WHERE contype='f'"):
            t = schema.get(tn.lower().split(".")[-1].strip('"'))
            if t: t["fks"].append(dict(cols=cols.lower().split(","), ref=rt.lower().split(".")[-1].strip('"'), rcols=[], ondelete=od != "a"))
        for tn, cols, uq in q("SELECT i.indrelid::regclass::text, (SELECT string_agg(attname,',' ORDER BY k.n) FROM unnest(i.indkey) WITH ORDINALITY k(a,n) JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.a), i.indisunique FROM pg_index i WHERE NOT i.indisprimary"):
            t = schema.get(tn.lower().split(".")[-1].strip('"'))
            if t and cols: t["idx"].append(dict(cols=cols.lower().split(","), unique=uq == "t"))
        stats = q("SELECT relname, seq_scan, coalesce(idx_scan,0), n_live_tup, n_dead_tup FROM pg_stat_user_tables")
        unused = q("SELECT relname, indexrelname, pg_relation_size(indexrelid) FROM pg_stat_user_indexes JOIN pg_index USING (indexrelid) WHERE idx_scan=0 AND NOT indisunique AND NOT indisprimary")
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as e:
        return None, f"introspection failed: {e}"
    return dict(schema=schema, label=label, stats=stats, unused=unused), "ok"


def from_mysql(url):
    u = urlparse(url)
    exe = shutil.which("mysql") or shutil.which("mariadb")
    if not exe: return None, "mysql client not installed"
    env = dict(os.environ); env["MYSQL_PWD"] = unquote(u.password or env.get("MYSQL_PWD", ""))
    db = (u.path or "/")[1:]
    base = [exe, "-h", u.hostname or "localhost", "-P", str(u.port or 3306), "-u", unquote(u.username or "root"), "-N", "-B", "-e"]
    def q(sql):
        r = subprocess.run(base + [sql], env=env, capture_output=True, text=True, timeout=40)
        if r.returncode: raise RuntimeError(r.stderr.strip()[:140])
        return [x.split("\t") for x in r.stdout.strip().splitlines() if x.strip()]
    schema = {}; label = f"mysql://{u.hostname}/{db}"; w = f"table_schema='{db}'" if db else "table_schema NOT IN ('mysql','sys','information_schema','performance_schema')"
    try:
        for tn, cn, dt, ct, nl, df, ck in q(f"SELECT table_name,column_name,data_type,column_type,is_nullable,IFNULL(column_default,''),column_key FROM information_schema.columns WHERE {w} AND table_name IN (SELECT table_name FROM information_schema.tables WHERE table_type='BASE TABLE' AND {w}) ORDER BY table_name,ordinal_position"):
            t = schema.setdefault(tn.lower(), new_table((label, 1))); t["cols"].append(_col(cn.lower(), ct if dt in ("varchar", "char", "decimal", "tinyint") else dt, nl == "YES", df or None, ck == "PRI"))
            if ck == "PRI": t["pk"].append(cn.lower())
        for tn, cn, rt, ud in q(f"SELECT k.table_name,k.column_name,k.referenced_table_name,r.delete_rule FROM information_schema.key_column_usage k JOIN information_schema.referential_constraints r ON r.constraint_name=k.constraint_name AND r.constraint_schema=k.table_schema WHERE k.referenced_table_name IS NOT NULL AND k.{w}"):
            t = schema.get(tn.lower())
            if t: t["fks"].append(dict(cols=[cn.lower()], ref=rt.lower(), rcols=[], ondelete=ud not in ("NO ACTION", "RESTRICT")))
        groups = {}
        for tn, ix, nu, cn, seq in q(f"SELECT table_name,index_name,non_unique,column_name,seq_in_index FROM information_schema.statistics WHERE {w} AND index_name<>'PRIMARY' ORDER BY table_name,index_name,seq_in_index"):
            groups.setdefault((tn.lower(), ix), dict(cols=[], unique=nu == "0"))["cols"].append(cn.lower())
        for (tn, _), d in groups.items():
            if tn in schema: schema[tn]["idx"].append(d)
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as e:
        return None, f"introspection failed: {e}"
    return dict(schema=schema, label=label, stats=[], unused=[]), "ok"


# ────────────────────────────── analysis ──────────────────────────────
def _mk(rule, title, typ, sev, file, line, ev, impact, fix, effort, status="confirmed", priority=None, why=None, cwe=()):
    return dict(rule=rule, title=title, family="sql-schema", type=typ, severity=sev if status == "confirmed" else None, category="database", file=file, line=line, evidence=ev,
                impact=impact, fix=fix, effort_min=effort, cwe=list(cwe), owasp=[], status=status, priority=priority if status != "confirmed" else None,
                why=why if status != "confirmed" else None)


def _has_index(t, cols, any_position=False):
    cols = [c.lower() for c in cols]
    if [c.lower() for c in t["pk"]][:len(cols)] == cols: return True
    return any([c.lower() for c in i["cols"]][:len(cols)] == cols for i in t["idx"])


def analyze(schema, covered=(), live=None):
    """covered: rule ids the caller already reports for this source (avoid duplicates, e.g. the legacy raw-SQL checks)."""
    out = []; names = set(schema)
    def add(f):
        if f["rule"] not in covered: out.append(f)
    nfk = sum(len(t["fks"]) for t in schema.values())
    big = [n for n, t in schema.items() if len(t["cols"]) > 0]
    for tn, t in sorted(schema.items()):
        f, ln = t["src"]; cols = {c["name"]: c for c in t["cols"]}; cn = list(cols)
        if t["cols"] and not t["pk"]:
            add(_mk("SQL-NO-PK", f"Table `{tn}` has no PRIMARY KEY", "code_smell", "medium", f, ln, f"{tn}({', '.join(cn[:6])})", "Duplicate rows, slow lookups, replication/ORM problems.", f"Add a primary key to `{tn}` in a new migration.", 20, cwe=["CWE-1007"]))
        fkcols = set()
        for fk in t["fks"]:
            fkcols.update(fk["cols"])
            if not _has_index(t, fk["cols"]):
                add(_mk("SQL-FK-NO-INDEX", f"Foreign key `{tn}.{','.join(fk['cols'])}` without index", "performance", "low", f, ln, f"FOREIGN KEY ({','.join(fk['cols'])}) -> {fk['ref']}", "Joins and cascading deletes scan the table; lock contention under load.", f"CREATE INDEX idx_{tn}_{'_'.join(fk['cols'])} ON {tn}({', '.join(fk['cols'])});", 10))
            if fk["ref"] not in names and names and fk["ref"] not in ("?", "user", "users", "auth_user", "group", "groups", "permission", "contenttype", "self") and len(names) >= 3:
                add(_mk("DBD-FK-DANGLING", f"Foreign key `{tn}.{','.join(fk['cols'])}` points to table `{fk['ref']}` that is not in the analysed schema", "bug", None, f, ln, f"{tn} -> {fk['ref']}", "The relation cannot be enforced if the table does not exist; or the model lives in a file/app that was not analysed.", "Check the referenced table name (and that its migration runs first).", 20, status="needs_validation", priority="low", why="The referenced model may be defined elsewhere (another app/package)."))
            if not fk["ondelete"]:
                add(_mk("DBD-FK-NO-ONDELETE", f"Foreign key `{tn}.{','.join(fk['cols'])}` has no explicit ON DELETE policy", "code_smell", None, f, ln, f"{tn}.{','.join(fk['cols'])} -> {fk['ref']}", "The default (restrict / no action) may block deletes unexpectedly, or an ORM may leave orphans; the intent is not documented.", "Decide per relation: ON DELETE CASCADE (owned child), SET NULL (optional link) or RESTRICT (protected), and state it explicitly.", 15, status="needs_validation", priority="low", why="Heuristic: the default may be intentional."))
        for fk in t["fks"]:
            for c in fk["cols"]:
                if c in cols and cols[c]["null"] is False and fk["ondelete"] is False and False: pass
        # modelling: *_id columns that look like relations but have no FK
        for c in cn:
            m = re.match(r"^(\w+?)_id$", c) or re.match(r"^([a-z]\w*?)Id$", c)
            if m and c not in fkcols and c not in t["pk"] and c.lower() != "id":
                base = _snake(m.group(1)); cand = [x for x in (base, _plural(base), base + "s") if x in names and x != tn]
                if cand and not (cols.get(base + "_type")):
                    add(_mk("DBD-MISSING-FK", f"`{tn}.{c}` looks like a reference to `{cand[0]}` but has no FOREIGN KEY", "bug", None, f, ln, f"{tn}.{c} (no constraint) / table {cand[0]} exists", "Nothing prevents orphan rows or invalid ids: referential integrity depends on every code path being perfect.", f"ALTER TABLE {tn} ADD CONSTRAINT fk_{tn}_{c} FOREIGN KEY ({c}) REFERENCES {cand[0]}(id);  -- clean orphans first", 30, status="needs_validation", priority="medium", why="Heuristic by column name: confirm it is a real relation (and not e.g. an external id)."))
        # polymorphic association (type + id) cannot have a real FK
        for c in cn:
            if c.endswith("_type") and c[:-5] + "_id" in cols:
                add(_mk("DBD-POLYMORPHIC", f"`{tn}.{c[:-5]}_id/{c}` is a polymorphic association", "code_smell", None, f, ln, f"{tn}.({c[:-5]}_id, {c})", "A database cannot enforce a foreign key across several tables; orphans are likely and joins are harder to index.", "Prefer one nullable FK per target (with a CHECK that exactly one is set) or a shared supertype table.", 60, status="needs_validation", priority="low", why="Common ORM pattern: accept it only if orphans are cleaned in code."))
        # 1NF: repeating groups / csv in a column
        groups = {}
        for c in cn:
            m = re.match(r"^(\w*?[a-z])_?(\d{1,2})$", c)
            if m: groups.setdefault(m.group(1), []).append(c)
        for g, cs in groups.items():
            if len(cs) >= 3:
                add(_mk("DBD-REPEATING-GROUP", f"`{tn}` has repeating columns {cs[0]}, {cs[1]}, {cs[2]}…", "code_smell", None, f, ln, ", ".join(cs[:5]), "Violates 1NF: adding a 4th value needs a schema change; queries must OR across columns.", f"Move the values to a child table `{tn}_{g}` (one row per value) with a FK to `{tn}`.", 90, status="needs_validation", priority="medium", why="Heuristic by column names."))
        for c in cn:
            if CSVISH.search(c) and TEXTT.match(cols[c]["type"] or "") and not c.endswith(("_id",)):
                add(_mk("DBD-CSV-COLUMN", f"`{tn}.{c}` looks like a list stored in a text column", "code_smell", None, f, ln, f"{tn}.{c} {cols[c]['type']}", "Violates 1NF: cannot be indexed, joined or constrained; updates are read-modify-write.", "Use a join table (many-to-many) or a native array/JSON column if it is truly opaque.", 90, status="needs_validation", priority="low", why="Confirm the column really holds several values."))
        # EAV anti-pattern
        if {"entity_id", "attribute"} <= set(cn) or ({"key", "value"} <= set(cn) and len(cn) <= 6 and any(x.endswith("_id") for x in cn)) or {"attribute_id", "value"} <= set(cn) and "entity_id" in cn:
            add(_mk("DBD-EAV", f"`{tn}` looks like an Entity-Attribute-Value table", "code_smell", None, f, ln, ", ".join(cn[:6]), "No type safety or constraints, expensive pivots, poor query planning.", "Model the known attributes as columns (or JSONB for truly dynamic ones).", 120, status="needs_validation", priority="low", why="EAV is sometimes intended (settings/flags)."))
        # money as float
        for c in cn:
            if MONEY.search(c) and FLOATT.match(cols[c]["type"] or ""):
                add(_mk("SQL-MONEY-FLOAT", f"Money column `{tn}.{c}` uses {cols[c]['type'].upper()}", "bug", "medium", f, ln, f"{c} {cols[c]['type']}", "Rounding errors in totals/invoices.", "Use DECIMAL(12,2) (or integer minor units).", 30, cwe=["CWE-681"]))
        # dates as strings, uuid as char
        for c in cn:
            ty = (cols[c]["type"] or "").lower()
            if DATEISH.search(c) and TEXTT.match(ty) and not re.search(r"(format|timezone|tz|label|name|text|desc)", c):
                add(_mk("DBD-DATE-AS-STRING", f"`{tn}.{c}` looks like a date/time stored as {ty or 'text'}", "bug", None, f, ln, f"{c} {ty}", "No date validation, wrong ordering/range queries, timezone bugs.", "Use a native timestamp/date type (timestamptz in PostgreSQL).", 60, status="needs_validation", priority="medium", why="Heuristic by column name."))
            if re.match(r"^(var)?char\(?36\)?$", ty.replace(" ", "")) or ty == "char(36)" or (c in ("uuid", "guid") and TEXTT.match(ty)):
                add(_mk("DBD-UUID-AS-CHAR", f"`{tn}.{c}` stores a UUID as text", "performance", "low", f, ln, f"{c} {ty}", "36 bytes per key (vs 16): bigger indexes and slower joins.", "Use the native uuid type (PostgreSQL) or BINARY(16) (MySQL).", 60))
        # uniqueness
        for c in cn:
            if c in UNIQUEISH and not cols[c]["pk"] and not any(i["unique"] and [x.lower() for x in i["cols"]] == [c.lower()] for i in t["idx"]) and not any(i["unique"] and i["cols"][-1:] == [c] and len(i["cols"]) > 1 for i in t["idx"]) and not (c == "code" and True):
                add(_mk("DBD-NOT-UNIQUE", f"`{tn}.{c}` is an identifier but has no UNIQUE constraint", "bug", None, f, ln, f"{tn}.{c} (no unique index)", "Duplicates (two accounts with the same email) become possible under concurrency even when the app checks first.", f"CREATE UNIQUE INDEX uq_{tn}_{c} ON {tn}({c});  -- resolve duplicates first", 30, status="needs_validation", priority="medium", why="Heuristic by column name: ignore if duplicates are valid here (e.g. per-tenant uniqueness)."))
        # nullable overload / wide table / no timestamps / naming
        if len(cn) >= 6 and sum(1 for c in t["cols"] if c["null"] and not c["pk"]) / max(1, len(cn)) > .85:
            add(_mk("DBD-ALL-NULLABLE", f"`{tn}`: {sum(1 for c in t['cols'] if c['null'])} of {len(cn)} columns are nullable", "code_smell", None, f, ln, f"{tn}: almost every column NULL", "Without NOT NULL the database cannot guarantee required data; every reader must handle NULL.", "Mark mandatory columns NOT NULL (with a default or backfill).", 60, status="needs_validation", priority="low", why="Heuristic: ORM schemas often omit NOT NULL by default."))
        if len(cn) > 40:
            add(_mk("DBD-WIDE-TABLE", f"`{tn}` has {len(cn)} columns", "code_smell", None, f, ln, f"{len(cn)} columns", "Usually several entities in one table (low normalization): hard to index, high row width, frequent NULLs.", "Extract cohesive column groups (address, billing, settings…) into related tables (2NF/3NF).", 180, status="needs_validation", priority="low", why="Some wide tables are legitimate (reporting)."))
        if len(cn) >= 4 and len(t["fks"]) < 2 and not SKIP_TIMESTAMPS.search(tn) and not any(re.search(r"(created|updated|inserted|modified)", c) for c in cn) and not tn.endswith(("_pivot",)):
            add(_mk("DBD-NO-TIMESTAMPS", f"`{tn}` has no created/updated timestamps", "code_smell", None, f, ln, f"{tn}({', '.join(cn[:6])}…)", "No audit trail of when rows changed: harder debugging, incremental sync and data-retention work.", "Add `created_at` / `updated_at` (default now(), updated by trigger or ORM).", 30, status="needs_validation", priority="low", why="Skip for static lookup tables."))
        # redundant indexes
        seen = []
        for i in t["idx"]:
            for j in t["idx"]:
                if i is not j and j["cols"][:len(i["cols"])] == i["cols"] and (len(j["cols"]) > len(i["cols"]) or (j["cols"] == i["cols"] and id(i) > id(j))) and not i["unique"] and i["cols"] not in seen:
                    seen.append(i["cols"])
                    add(_mk("DBD-REDUNDANT-INDEX", f"Index on `{tn}({', '.join(i['cols'])})` is redundant", "performance", "low", f, ln, f"{', '.join(i['cols'])} is a prefix of ({', '.join(j['cols'])})", "Every extra index slows INSERT/UPDATE and uses disk without helping reads.", f"DROP INDEX <name of the {', '.join(i['cols'])} index>;  -- after checking query plans", 15))
        if t["pk"] and any(c in t["pk"] for c in cn) and any((cols[c]["type"] or "").lower().startswith(("varchar", "text", "char", "string")) and len(t["pk"]) == 1 for c in t["pk"] if c in cols) and not any(c in ("uuid", "slug", "code", "id") for c in t["pk"]):
            add(_mk("DBD-TEXT-PK", f"`{tn}` uses a text primary key (`{t['pk'][0]}`)", "performance", None, f, ln, f"PRIMARY KEY ({t['pk'][0]})", "Wide keys bloat every index and foreign key; natural keys also change over time.", "Prefer a surrogate integer/uuid key and keep the natural key UNIQUE.", 120, status="needs_validation", priority="low", why="Fine for stable codes (ISO country)."))
    # naming consistency across the schema
    if len(schema) >= 4:
        allcols = [c["name"] for t in schema.values() for c in t["cols"]]
        camel = [c for c in allcols if re.search(r"[a-z][A-Z]", c)]; snake = [c for c in allcols if "_" in c]
        if len(camel) >= 3 and len(snake) >= 3:
            first = next(iter(schema.values()))["src"]
            add(_mk("DBD-NAMING-MIXED", f"Mixed naming styles: {len(camel)} camelCase and {len(snake)} snake_case columns", "code_smell", None, first[0], first[1], f"e.g. {camel[0]} vs {snake[0]}", "Inconsistent names cause quoting problems (case folding) and confusion in queries.", "Pick one convention (snake_case recommended) and map the exceptions.", 120, status="needs_validation", priority="low", why="Heuristic: columns are lower-cased by some sources."))
        sing = [n for n in schema if n.endswith("s") and not n.endswith("ss")]
        if 0 < len(sing) < len(schema) - 1 and len(sing) >= 2 and len(schema) - len(sing) >= 2:
            first = next(iter(schema.values()))["src"]
            add(_mk("DBD-NAMING-PLURAL", "Table names mix singular and plural", "code_smell", None, first[0], first[1], f"{sing[0]} vs {next(n for n in schema if n not in sing)}", "Inconsistent conventions make the schema harder to read and to generate code for.", "Choose singular or plural for all tables.", 60, status="needs_validation", priority="low", why="Heuristic by trailing 's'."))
    for tn, t in schema.items():
        if tn in RESERVED:
            add(_mk("DBD-RESERVED-NAME", f"Table named `{tn}` is a reserved word", "code_smell", "low", t["src"][0], t["src"][1], tn, "Needs quoting in every query; breaks some tools and raw SQL.", f"Rename to a non-reserved name (e.g. `{_plural(tn)}` / `app_{tn}`).", 60))
        for c in t["cols"]:
            if re.search(r"\s", c["name"]): add(_mk("DBD-BAD-NAME", f"Column `{tn}.{c['name']}` contains spaces", "code_smell", "low", t["src"][0], t["src"][1], c["name"], "Needs quoting everywhere.", "Rename to snake_case.", 30))
    if len(big) >= 5 and nfk == 0:
        first = schema[sorted(schema)[0]]["src"]
        add(_mk("DBD-NO-RELATIONS", f"{len(big)} tables but NO foreign keys: relations are not modelled in the database", "bug", "medium", first[0], first[1], f"{len(big)} tables, 0 foreign keys", "Referential integrity is left to application code: orphans and inconsistent data accumulate over time.", "Declare the relations (FOREIGN KEY with ON DELETE policy) after cleaning orphan rows.", 240))
    # live statistics (PostgreSQL)
    if live:
        for rel_, seq, idx, live_n, dead in live.get("stats", []):
            try: seq, idx, live_n, dead = int(seq), int(idx), int(live_n), int(dead)
            except ValueError: continue
            if live_n > 10000 and seq > 1000 and seq > idx * 5:
                add(_mk("DBD-SEQSCAN-HOT", f"`{rel_}` ({live_n:,} rows) is read by sequential scans {seq:,} times vs {idx:,} index scans", "performance", "medium", live["label"], 1, f"seq_scan={seq} idx_scan={idx}", "Likely a missing index on a frequent filter/join column.", f"Find the slow queries (pg_stat_statements / EXPLAIN) and add the matching index on `{rel_}`.", 60, cwe=[]))
            if live_n > 10000 and dead > live_n * .2:
                add(_mk("DBD-BLOAT", f"`{rel_}` has {dead:,} dead rows ({dead * 100 // max(1, live_n + dead)}%)", "performance", "low", live["label"], 1, f"n_dead_tup={dead}", "Table/index bloat slows scans; autovacuum is not keeping up.", f"VACUUM (ANALYZE) {rel_}; tune autovacuum_vacuum_scale_factor for this table.", 30))
        for rel_, ix, size in live.get("unused", []):
            try: size = int(size)
            except ValueError: size = 0
            if size > 1_000_000:
                add(_mk("DBD-UNUSED-INDEX", f"Index `{ix}` on `{rel_}` has never been used ({size // 1_000_000} MB)", "performance", "low", live["label"], 1, f"idx_scan=0 size={size}", "Costs writes and disk with no read benefit (counter resets on restart: confirm over a full business cycle).", f"DROP INDEX {ix};  -- only after confirming over a representative period", 20))
    return out


MIGRATION_RISK = [
    ("DBD-MIG-DROP", re.compile(r"(?i)\bDROP\s+(TABLE|COLUMN)\b|\bdrop_table\b|\bremove_column\b|\bdropColumn\b|\bdropIfExists\b|migrations\.(RemoveField|DeleteModel)|op\.drop_(table|column)"), "Migration drops data", "high", "Irreversible data loss if applied without a verified backup and an expand/contract rollout.", "Use expand/contract: stop writing, deploy, back up, then drop in a later release."),
    ("DBD-MIG-NOTNULL-NODEFAULT", re.compile(r"(?i)ADD\s+COLUMN\s+\S+\s+[\w()]+\s+NOT\s+NULL(?![^;]*DEFAULT)|add_column[^\n]*null:\s*false(?![^\n]*default)|\$table->\w+\([^)]*\)\s*;\s*//\s*not null"), "Migration adds a NOT NULL column without a default", "medium", "Fails on a table that already has rows (or rewrites the whole table under a lock).", "Add the column nullable, backfill in batches, then set NOT NULL."),
    ("DBD-MIG-INDEX-LOCK", re.compile(r"(?i)CREATE\s+(UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY)(?!IF\s+NOT\s+EXISTS\s+CONCURRENTLY)\w+\s+ON\s+(?!ONLY)\w+\s*(?:USING\s+\w+\s*)?\("), "Index created without CONCURRENTLY (PostgreSQL)", "low", "Blocks writes on the table for the whole build on a large table.", "Use CREATE INDEX CONCURRENTLY (outside a transaction block)."),
]


def migration_checks(text, rel):
    out = []
    if not re.search(r"(?i)(^|/)(migrat|db/migrate|alembic|flyway|liquibase|prisma/migrations|database/migrations)", rel): return out
    for rid, rx, title, sev, imp, fix in MIGRATION_RISK:
        if rid == "DBD-MIG-INDEX-LOCK" and not re.search(r"(?i)postgres|pg_|\.sql$", text + rel): continue
        m = rx.search(text)
        if m: out.append(_mk(rid, title, "code_smell", sev if sev != "high" else "medium", rel, _line(text, m.start()), m.group(0)[:90].replace("\n", " "), imp, fix, 30, status="needs_validation" if sev == "high" else "confirmed", priority="medium", why="A destructive migration may be intentional: confirm there is a backup and a rollout plan."))
    return out


# ────────────────────────────── drivers ──────────────────────────────
PARSERS = (("prisma", parse_prisma), ("django", parse_django), ("rails", parse_rails), ("laravel", parse_laravel), ("sqlalchemy", parse_sqlalchemy), ("typeorm", parse_typeorm), ("sql", parse_sql))


def kind_of(rel, ext, text):
    low = rel.lower()
    if ext == "prisma" or low.endswith("schema.prisma"): return "prisma"
    if ext == "py" and re.search(r"models\.Model\b", text) and "class " in text: return "django"
    if ext == "py" and re.search(r"__tablename__|DeclarativeBase|declarative_base", text): return "sqlalchemy"
    if ext == "rb" and re.search(r"create_table|add_index|add_foreign_key", text): return "rails"
    if ext == "php" and "Schema::create" in text: return "laravel"
    if ext in ("ts", "js") and "@Entity(" in text: return "typeorm"
    if ext in ("sql", "pls", "pks", "pkb", "tsql") or (ext == "" and low.endswith(".sql")): return "sql"
    return None


def audit_project(files, read, ui_note=lambda s: None):
    """files: [(rel, abs, ext, _)]; read(abs)->text. Returns (findings, summary dict, schema)."""
    schema, per_kind, migs = {}, {}, []
    for rel, ab, ext, _ in files:
        if ext not in ("prisma", "py", "rb", "php", "ts", "js", "sql", "pls", "pks", "pkb", "tsql"): continue
        if re.search(r"(^|/)(node_modules|vendor|site-packages)/", rel): continue
        try:
            if os.path.getsize(ab) > 1_500_000: continue
            text = read(ab)
        except OSError: continue
        k = kind_of(rel, ext, text)
        if k:
            before = len(schema); dict(PARSERS)[k](text, rel, schema); per_kind[k] = per_kind.get(k, 0) + len(schema) - before
        if re.search(r"(?i)migrat|alembic|flyway|liquibase", rel): migs += migration_checks(text, rel)
    out = []
    if schema:
        # raw SQL keeps its legacy checks (SQL-NO-PK / FK index / MONEY-FLOAT / ...): only ORM sources add those here
        out += analyze({n: t for n, t in schema.items()}, covered=("SQL-NO-PK", "SQL-FK-NO-INDEX", "SQL-MONEY-FLOAT") if per_kind.get("sql") and len(per_kind) == 1 else ())
    out += migs
    return out, dict(tables=len(schema), relations=sum(len(t["fks"]) for t in schema.values()), indexes=sum(len(t["idx"]) for t in schema.values()), sources=per_kind), schema


def audit_live(spec):
    """spec: sqlite path or postgres/mysql URL -> (findings, summary, schema, message). Never raises."""
    try:
        if "://" in spec:
            sch = spec.split("://")[0].lower()
            r, msg = (from_postgres(spec) if sch.startswith("postgres") else from_mysql(spec) if sch.startswith(("mysql", "maria")) else (None, "unsupported scheme"))
            if not r: return [], {}, {}, msg
            return analyze(r["schema"], covered=("SQL-NO-PK", "SQL-FK-NO-INDEX", "SQL-MONEY-FLOAT"), live=r), dict(tables=len(r["schema"]), relations=sum(len(t["fks"]) for t in r["schema"].values()), indexes=sum(len(t["idx"]) for t in r["schema"].values())), r["schema"], "ok"
        if os.path.isfile(spec):
            s = from_sqlite(spec)
            return analyze(s, covered=("SQL-NO-PK", "SQL-FK-NO-INDEX", "SQL-MONEY-FLOAT")), dict(tables=len(s), relations=sum(len(t["fks"]) for t in s.values()), indexes=sum(len(t["idx"]) for t in s.values())), s, "ok"
    except (sqlite3.Error, OSError, subprocess.SubprocessError) as e:
        return [], {}, {}, f"design audit skipped: {str(e)[:100]}"
    return [], {}, {}, "not found"


def mermaid(schema, limit=40):
    """ER diagram (Mermaid) of the model: tables with PK/FK markers and relations."""
    names = sorted(schema, key=lambda n: -(len(schema[n]["fks"]) + sum(1 for t in schema.values() for f in t["fks"] if f["ref"] == n)))[:limit]
    L = ["erDiagram"]
    for n in names:
        t = schema[n]; L.append(f"  {re.sub(r'[^A-Za-z0-9_]', '_', n)} {{")
        fkc = {c for f in t["fks"] for c in f["cols"]}
        for c in t["cols"][:14]:
            tag = "PK" if c["name"] in t["pk"] else ("FK" if c["name"] in fkc else "")
            L.append(f"    {re.sub(r'[^A-Za-z0-9_]', '', (c['type'] or 'any').split('(')[0]) or 'any'} {re.sub(r'[^A-Za-z0-9_]', '_', c['name'])} {tag}".rstrip())
        L.append("  }")
    for n in names:
        for f in schema[n]["fks"]:
            if f["ref"] in names: L.append(f"  {re.sub(r'[^A-Za-z0-9_]', '_', f['ref'])} ||--o{{ {re.sub(r'[^A-Za-z0-9_]', '_', n)} : \"{','.join(f['cols'])}\"")
    return "\n".join(L) + "\n"


def fix_sql(findings):
    """Review-first SQL for the findings that have a concrete statement. Generated as TEXT; the tool never runs it."""
    L = ["-- PN-Ultra-Audit: database fixes. REVIEW EVERY STATEMENT, test on a copy and take a backup first.", "-- This file is never executed by the tool.", ""]
    n = 0
    for f in findings:
        if f["rule"] in ("SQL-FK-NO-INDEX", "DBD-MISSING-FK", "DBD-NOT-UNIQUE", "DBD-REDUNDANT-INDEX", "DBD-UNUSED-INDEX") and re.search(r"(?i)^(CREATE|ALTER|DROP)", f["fix"]):
            n += 1; L += [f"-- [{f['rule']}] {f['title']}  ({f['file']}:{f['line']})", ("-- " if f["rule"] in ("DBD-REDUNDANT-INDEX", "DBD-UNUSED-INDEX", "DBD-MISSING-FK", "DBD-NOT-UNIQUE") else "") + f["fix"].split("  --")[0].strip(), ""]
    return "\n".join(L) + "\n" if n else ""
