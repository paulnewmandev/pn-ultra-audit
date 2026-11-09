"""Database auditing: static (.sql dumps/migrations) and live read-only (SQLite file,
PostgreSQL via psql, MySQL/MariaDB via mysql client). No third-party Python packages.

Live connections are READ-ONLY catalog queries. Passwords are passed via environment
variables (PGPASSWORD / MYSQL_PWD), never on the command line.
"""
import json, os, re, shutil, sqlite3, subprocess
from urllib.parse import urlparse, unquote

MONEY = re.compile(r"(price|amount|total|balance|cost|salary|fee|tax|subtotal|payment)", re.I)
PWDCOL = re.compile(r"^(password|passwd|pwd|pass|senha|contrasena|hash_password)$", re.I)
LOOKS_HASHED = re.compile(r"^(\$2[aby]\$|\$argon2|\$pbkdf2|\$scrypt|\$[156]\$|pbkdf2_|sha\d+\$|bcrypt\$|[A-Fa-f0-9]{32,})")


def mk(rule, title, family, typ, sev, cat, file, line, evidence, impact, fix, effort, cwe=(), owasp=(), status="confirmed", priority=None, why=None):
    return dict(rule=rule, title=title, family=family, type=typ, severity=sev if status == "confirmed" else None, category=cat,
                file=file, line=line, evidence=evidence, impact=impact, fix=fix, effort_min=effort, cwe=list(cwe), owasp=list(owasp),
                status=status, priority=priority, why=why)


# ─────────────────────────── static SQL ───────────────────────────
CREATE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"\[]?([\w.]+)[`\"\]]?\s*\((.*?)\)\s*(?:ENGINE|;|WITH|INHERITS|COMMENT|DEFAULT|TABLESPACE|$)", re.I | re.S)


def static_sql(text, relpath):
    out = []
    idx_cols = set()
    for m in re.finditer(r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+\S+\s+ON\s+[`\"\[]?([\w.]+)[`\"\]]?\s*\(([^)]*)\)", text, re.I):
        for c in m.group(2).split(","):
            idx_cols.add((m.group(1).lower(), re.sub(r"[`\"\[\]\s]|\(.*", "", c).lower()))
    for m in CREATE.finditer(text):
        table, body = m.group(1), m.group(2)
        line = text[:m.start()].count("\n") + 1
        has_pk = bool(re.search(r"PRIMARY\s+KEY", body, re.I))
        if not has_pk:
            out.append(mk("SQL-NO-PK", f"Table `{table}` has no PRIMARY KEY", "sql-schema", "code_smell", "medium", "database", relpath, line,
                          f"CREATE TABLE {table} (...)  -- no PRIMARY KEY", "Duplicate rows, slow lookups, replication/ORM problems.",
                          f"Add a primary key to `{table}` (surrogate `id` or natural unique key) in a new migration.", 20, ["CWE-1007"]))
        for fk in re.finditer(r"(?:FOREIGN\s+KEY\s*\(\s*[`\"]?(\w+)[`\"]?\s*\)|[`\"]?(\w+)[`\"]?\s+[\w()]+(?:\s+\w+)*?\s+REFERENCES)", body, re.I):
            col = (fk.group(1) or fk.group(2) or "").lower()
            tl = table.lower().split(".")[-1]
            if col and (tl, col) not in idx_cols and not re.search(rf"(?<!FOREIGN )(KEY|INDEX|UNIQUE)\s*[`\"\w ]*\(\s*[`\"]?{col}[`\"]?", body, re.I) \
                    and not re.search(rf"PRIMARY\s+KEY\s*\([^)]*\b{col}\b", body, re.I):
                out.append(mk("SQL-FK-NO-INDEX", f"Foreign key `{table}.{col}` without index", "sql-schema", "performance", "low", "database", relpath, line,
                              f"FOREIGN KEY ({col}) ...", "Joins and cascading deletes scan the table; lock contention under load.",
                              f"CREATE INDEX idx_{tl}_{col} ON {table}({col});", 10))
        for col in re.finditer(r"(?:^|,)\s*[`\"]?(\w+)[`\"]?\s+(FLOAT|DOUBLE|REAL)\b", body, re.I | re.M):
            if MONEY.search(col.group(1)):
                out.append(mk("SQL-MONEY-FLOAT", f"Money column `{table}.{col.group(1)}` uses {col.group(2).upper()}", "sql-schema", "bug", "medium", "database", relpath, line,
                              col.group(0).strip(), "Rounding errors in totals/invoices.", "Use DECIMAL(12,2) (or integer cents).", 30, ["CWE-681"]))
        for col in re.finditer(r"(?:^|,)\s*[`\"]?(\w+)[`\"]?\s+(VARCHAR\s*\((\d+)\)|TEXT|CHAR\s*\((\d+)\))", body, re.I | re.M):
            if PWDCOL.match(col.group(1)):
                n = int(col.group(3) or col.group(4) or 255)
                if n < 60 and col.group(2).upper().startswith(("VARCHAR", "CHAR")):
                    out.append(mk("SQL-PWD-SHORT", f"Password column `{table}.{col.group(1)}` too short for a modern hash ({n})", "sql-schema", "vulnerability", "medium", "database", relpath, line,
                                  col.group(0).strip(), "Suggests plaintext or truncated hashes.", "Widen to VARCHAR(255) and store argon2id/bcrypt hashes.", 30, ["CWE-257"], ["A02:2021"]))
        if re.search(r"ENGINE\s*=\s*MyISAM", text[m.start():m.end() + 60], re.I):
            out.append(mk("SQL-MYISAM", f"Table `{table}` uses MyISAM", "sql-schema", "code_smell", "low", "database", relpath, line,
                          "ENGINE=MyISAM", "No transactions, no foreign keys, table-level locks, crash-unsafe.", "Convert to InnoDB (`ALTER TABLE t ENGINE=InnoDB`).", 20))
    for m in re.finditer(r"CHARSET\s*=\s*utf8\b(?!mb4)|CHARACTER\s+SET\s+utf8\b(?!mb4)", text, re.I):
        out.append(mk("SQL-UTF8MB3", "MySQL `utf8` is 3-byte only (no emoji/some CJK)", "sql-schema", "bug", "low", "database", relpath, text[:m.start()].count("\n") + 1,
                      m.group(0), "Insert errors/truncation on 4-byte characters.", "Use utf8mb4 and utf8mb4_0900_ai_ci / utf8mb4_unicode_ci.", 30))
        break
    for m in re.finditer(r"xp_cmdshell'?\s*,\s*'?1|sp_configure\s+'xp_cmdshell'|TRUSTWORTHY\s+ON|GRANT\s+DBA\s+TO|ALTER\s+USER\s+sa\b.*ENABLE|CREATE\s+LOGIN\s+\w+\s+WITH\s+PASSWORD\s*=\s*'[^']+'|IDENTIFIED\s+BY\s+VALUES", text, re.I):
        out.append(mk("SQL-DANGEROUS-ENGINE-OPTION", "Dangerous database engine option or inline credential (T-SQL/PL-SQL)", "sql-schema", "vulnerability", "high", "authz", relpath, text[:m.start()].count("\n") + 1, re.sub(r"'[^']{3,}'", "'***'", m.group(0))[:120],
                      "Enables OS command execution, trust escalation or leaks a login password.", "Leave xp_cmdshell disabled, avoid TRUSTWORTHY ON and DBA grants; create logins out-of-band.", 30, ["CWE-250", "CWE-798"], ["A05:2021"]))
    for m in re.finditer(r"GRANT\s+ALL(\s+PRIVILEGES)?\s+ON\s+\*\.\*|GRANT\s+ALL\s+ON\s+ALL\s+TABLES|GRANT\s+.*\s+TO\s+['\"]?(PUBLIC|public)['\"]?|WITH\s+GRANT\s+OPTION", text, re.I):
        out.append(mk("SQL-GRANT-ALL", "Over-broad GRANT", "sql-schema", "vulnerability", "high", "authz", relpath, text[:m.start()].count("\n") + 1,
                      m.group(0), "App compromise = full DB compromise.", "Grant only the needed privileges on the needed schema/tables to a dedicated app role.", 20, ["CWE-250"], ["A01:2021"]))
    for m in re.finditer(r"(CREATE|ALTER)\s+USER\s+[^;]*?(IDENTIFIED\s+BY|PASSWORD)\s+['\"]([^'\"]+)['\"]", text, re.I):
        pw = m.group(3)
        out.append(mk("SQL-PLAIN-PWD", "Database user password in SQL script", "secrets", "vulnerability", "high", "secrets", relpath, text[:m.start()].count("\n") + 1,
                      re.sub(r"(['\"])[^'\"]+(['\"])$", r"\1" + pw[:2] + r"…\2", m.group(0))[:160], "Credential in source control.",
                      "Rotate it; create users out-of-band or inject via secret manager.", 20, ["CWE-798"], ["A07:2021"]))
    for m in re.finditer(r"INSERT\s+INTO\s+[`\"]?\w*users?[`\"]?\s*\([^)]*password[^)]*\)\s*VALUES\s*\([^)]*['\"]([^'\"]{3,40})['\"]", text, re.I):
        v = m.group(1)
        if not LOOKS_HASHED.match(v):
            out.append(mk("SQL-PLAIN-PWD-ROW", "Seed data stores a plaintext-looking password", "crypto-pwd", "vulnerability", "high", "crypto", relpath, text[:m.start()].count("\n") + 1,
                          m.group(0)[:60] + "…", "Plaintext passwords in seeds/dumps.", "Hash with argon2id/bcrypt; never ship default credentials.", 20, ["CWE-256"], ["A02:2021"]))
    return out


# ─────────────────────────── live: SQLite ───────────────────────────
def audit_sqlite(path, label=None, sample=False):
    label = label or os.path.basename(path)
    out, rel = [], label
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error as e:
        return [], f"cannot open: {e}"
    try:
        cur = con.cursor()
        res = cur.execute("PRAGMA integrity_check").fetchall()
        if res and res[0][0] != "ok":
            out.append(mk("DB-INTEGRITY", "SQLite integrity_check failed", "sql-schema", "bug", "high", "database", rel, 1, str(res[:3]), "Corrupted database.", "Restore from backup; run `.recover`.", 60))
        try:
            fkc = cur.execute("PRAGMA foreign_key_check").fetchall()
        except sqlite3.Error as e:
            fkc = []
            out.append(mk("DB-FK-MISMATCH", "Invalid foreign key definition", "sql-schema", "bug", "medium", "database", rel, 1, str(e)[:160],
                          "Constraint cannot be enforced; inserts/deletes may fail or silently skip integrity.", "Make the parent column PRIMARY KEY or UNIQUE and reference it by name.", 30))
        if fkc:
            out.append(mk("DB-FK-VIOLATIONS", f"{len(fkc)} foreign-key violations (orphan rows)", "sql-schema", "bug", "medium", "database", rel, 1, str(fkc[:3]),
                          "Referential integrity broken; app errors on joins.", "Delete/repair orphan rows, then enable `PRAGMA foreign_keys=ON` on every connection.", 45))
        if cur.execute("PRAGMA foreign_keys").fetchone()[0] == 0 and cur.execute("SELECT count(*) FROM sqlite_master WHERE sql LIKE '%REFERENCES%'").fetchone()[0]:
            out.append(mk("DB-FK-OFF", "Foreign keys declared but PRAGMA foreign_keys is OFF by default", "sql-schema", "code_smell", "low", "database", rel, 1,
                          "PRAGMA foreign_keys = 0", "Constraints are not enforced unless each connection enables them.", "Execute `PRAGMA foreign_keys=ON` when opening every connection.", 10))
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        for t in tables:
            cols = cur.execute(f'PRAGMA table_info("{t}")').fetchall()
            if not any(c[5] for c in cols):
                out.append(mk("SQL-NO-PK", f"Table `{t}` has no PRIMARY KEY", "sql-schema", "code_smell", "medium", "database", rel, 1, f"{t}({', '.join(c[1] for c in cols)})",
                              "Duplicate rows, ambiguous updates.", "Rebuild the table with a primary key (SQLite needs create-copy-rename).", 25, ["CWE-1007"]))
            idx_cols = set()
            for ix in cur.execute(f'PRAGMA index_list("{t}")').fetchall():
                for ic in cur.execute(f'PRAGMA index_info("{ix[1]}")').fetchall():
                    idx_cols.add(ic[2])
            for fk in cur.execute(f'PRAGMA foreign_key_list("{t}")').fetchall():
                if fk[3] not in idx_cols and not any(c[1] == fk[3] and c[5] == 1 for c in cols):
                    out.append(mk("SQL-FK-NO-INDEX", f"Foreign key `{t}.{fk[3]}` without index", "sql-schema", "performance", "low", "database", rel, 1,
                                  f"FOREIGN KEY({fk[3]}) REFERENCES {fk[2]}", "Slow joins/cascades.", f"CREATE INDEX idx_{t}_{fk[3]} ON {t}({fk[3]});", 10))
            for c in cols:
                if MONEY.search(c[1]) and c[2].upper() in ("REAL", "FLOAT", "DOUBLE"):
                    out.append(mk("SQL-MONEY-FLOAT", f"Money column `{t}.{c[1]}` uses {c[2].upper()}", "sql-schema", "bug", "medium", "database", rel, 1, f"{c[1]} {c[2]}",
                                  "Rounding errors.", "Store integer cents or use a decimal TEXT/NUMERIC with app-side Decimal.", 30, ["CWE-681"]))
                if sample and PWDCOL.match(c[1]):
                    try:
                        rows = [r[0] for r in cur.execute(f'SELECT "{c[1]}" FROM "{t}" WHERE "{c[1]}" IS NOT NULL LIMIT 200')]
                    except sqlite3.Error:
                        rows = []
                    bad = [r for r in rows if isinstance(r, str) and not LOOKS_HASHED.match(r)]
                    if bad:
                        out.append(mk("DB-PLAINTEXT-PASSWORDS", f"{len(bad)} of {len(rows)} sampled `{t}.{c[1]}` values do not look hashed", "crypto-pwd", "vulnerability", "critical", "crypto", rel, 1,
                                      f"{len(bad)}/{len(rows)} sampled rows in {t}.{c[1]} (values not shown)", "A DB leak exposes every user's real password (and reuse elsewhere).",
                                      "Hash with argon2id/bcrypt, force password reset, add `hash_version` column.", 120, ["CWE-256"], ["A02:2021"]))
        try:
            mode = os.stat(path).st_mode & 0o777
            if mode & 0o007:
                out.append(mk("DB-FILE-PERMS", f"SQLite file is world-accessible ({oct(mode)})", "chmod", "vulnerability", "medium", "misconfiguration", rel, 1, oct(mode),
                              "Any local user can read/modify the data.", f"chmod 600 {path}", 5, ["CWE-732"], ["A05:2021"]))
        except OSError:
            pass
        return out, f"{len(tables)} tables"
    finally:
        con.close()


# ─────────────────────────── live: Postgres / MySQL via CLI ───────────────────────────
def _run(cmd, env, timeout=30):
    try:
        r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except (subprocess.TimeoutExpired, OSError) as e:
        return 1, "", str(e)


def audit_url(url, sample=False):
    u = urlparse(url)
    scheme = u.scheme.lower()
    label = f"{scheme}://{u.hostname}{u.path}"
    env = dict(os.environ)
    if scheme in ("postgres", "postgresql"):
        if not shutil.which("psql"): return [], "psql not installed (install postgresql-client to audit live Postgres)"
        env["PGPASSWORD"] = unquote(u.password or env.get("PGPASSWORD", ""))
        base = ["psql", "-h", u.hostname or "localhost", "-p", str(u.port or 5432), "-U", unquote(u.username or "postgres"), "-d", (u.path or "/postgres")[1:] or "postgres",
                "-At", "-F", "|", "-v", "ON_ERROR_STOP=1", "-c"]
        env["PGOPTIONS"] = "-c default_transaction_read_only=on"
        q = {
         "nopk": "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname NOT IN ('pg_catalog','information_schema') AND NOT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid=c.oid AND i.indisprimary)",
         "fknoidx": "SELECT conrelid::regclass, a.attname FROM pg_constraint co JOIN pg_attribute a ON a.attrelid=co.conrelid AND a.attnum=co.conkey[1] WHERE co.contype='f' AND NOT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid=co.conrelid AND i.indkey[0]=co.conkey[1])",
         "super": "SELECT rolname FROM pg_roles WHERE rolsuper AND rolcanlogin",
         "money": "SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema NOT IN ('pg_catalog','information_schema') AND data_type IN ('real','double precision','money') AND column_name ~* '(price|amount|total|balance|cost|fee|tax)'",
         "ssl": "SHOW ssl", "ver": "SHOW server_version",
        }
        out = []
        for k, sql in q.items():
            rc, so, se = _run(base + [sql], env)
            if rc != 0:
                return out, f"connection/query failed: {se.strip()[:160]}"
            rows = [r for r in so.strip().splitlines() if r]
            if k == "nopk":
                for r in rows: out.append(mk("SQL-NO-PK", f"Table `{r}` has no PRIMARY KEY", "sql-schema", "code_smell", "medium", "database", label, 1, r, "Duplicates, replication issues.", "Add a primary key.", 20, ["CWE-1007"]))
            elif k == "fknoidx":
                for r in rows: out.append(mk("SQL-FK-NO-INDEX", f"Foreign key without index: {r.replace('|', '.')}", "sql-schema", "performance", "low", "database", label, 1, r, "Slow joins/cascades.", "CREATE INDEX on the FK column.", 10))
            elif k == "super":
                for r in rows: out.append(mk("DB-SUPERUSER-LOGIN", f"Login role `{r}` is SUPERUSER", "sql-schema", "vulnerability", "high", "authz", label, 1, r, "App/user compromise = full server compromise.", "Use a least-privilege role for the application; keep superuser for admin only.", 30, ["CWE-250"], ["A01:2021"]))
            elif k == "money":
                for r in rows: out.append(mk("SQL-MONEY-FLOAT", f"Money column uses float: {r.replace('|', '.')}", "sql-schema", "bug", "medium", "database", label, 1, r, "Rounding errors.", "Use NUMERIC(12,2).", 30, ["CWE-681"]))
            elif k == "ssl" and rows and rows[0] == "off":
                out.append(mk("DB-NO-TLS", "PostgreSQL server has ssl=off", "tls", "vulnerability", "medium", "crypto", label, 1, "ssl = off", "Credentials/data in cleartext on the wire.", "Enable ssl=on with a valid cert; require `sslmode=verify-full` in clients.", 30, ["CWE-319"], ["A02:2021"]))
        if sample:
            rc, so, se = _run(base + ["SELECT table_schema||'.'||table_name||'|'||column_name FROM information_schema.columns WHERE column_name ~* '^(password|passwd|pwd|pass)$' AND table_schema NOT IN ('pg_catalog','information_schema')"], env)
            for r in [x for x in so.strip().splitlines() if x] if rc == 0 else []:
                tbl, col = r.split("|")
                rx = r"^(\\$2[aby]\\$|\\$argon2|\\$pbkdf2|\\$scrypt|\\$[156]\\$|pbkdf2_|[a-fA-F0-9]{32,})"
                rc2, so2, _ = _run(base + [f'SELECT count(*) FILTER (WHERE "{col}" !~ \'{rx}\'), count(*) FROM (SELECT "{col}" FROM {tbl} WHERE "{col}" IS NOT NULL LIMIT 200) s'], env)
                if rc2 == 0 and "|" in so2:
                    bad, tot = [int(x) for x in so2.strip().split("|")]
                    if bad: out.append(mk("DB-PLAINTEXT-PASSWORDS", f"{bad} of {tot} sampled `{tbl}.{col}` values do not look hashed", "crypto-pwd", "vulnerability", "critical", "crypto", label, 1, f"{bad}/{tot} sampled rows (aggregate only; no values read)", "A DB leak exposes real passwords.", "Hash with argon2id/bcrypt, force reset.", 120, ["CWE-256"], ["A02:2021"]))
        return out, "postgres OK"
    if scheme in ("mysql", "mariadb"):
        cli = shutil.which("mysql") or shutil.which("mariadb")
        if not cli: return [], "mysql client not installed (install mysql-client to audit live MySQL/MariaDB)"
        env["MYSQL_PWD"] = unquote(u.password or env.get("MYSQL_PWD", ""))
        db = (u.path or "/")[1:]
        base = [cli, "-h", u.hostname or "localhost", "-P", str(u.port or 3306), "-u", unquote(u.username or "root"), "-N", "-B", "--connect-timeout=10"] + ([db] if db else []) + ["-e"]
        sc = f"'{db}'" if db else "DATABASE()"
        q = {
         "nopk": f"SELECT t.table_name FROM information_schema.tables t LEFT JOIN information_schema.table_constraints c ON c.table_schema=t.table_schema AND c.table_name=t.table_name AND c.constraint_type='PRIMARY KEY' WHERE t.table_schema={sc} AND t.table_type='BASE TABLE' AND c.constraint_name IS NULL",
         "myisam": f"SELECT table_name FROM information_schema.tables WHERE table_schema={sc} AND engine='MyISAM'",
         "utf8": f"SELECT table_name, table_collation FROM information_schema.tables WHERE table_schema={sc} AND table_collation LIKE 'utf8\\_%' ESCAPE '\\\\' AND table_collation NOT LIKE 'utf8mb4%'",
         "fknoidx": f"SELECT k.table_name, k.column_name FROM information_schema.key_column_usage k WHERE k.table_schema={sc} AND k.referenced_table_name IS NOT NULL AND NOT EXISTS (SELECT 1 FROM information_schema.statistics s WHERE s.table_schema=k.table_schema AND s.table_name=k.table_name AND s.column_name=k.column_name AND s.seq_in_index=1)",
         "money": f"SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema={sc} AND data_type IN ('float','double') AND column_name REGEXP 'price|amount|total|balance|cost|fee|tax'",
         "emptypw": "SELECT user, host FROM mysql.user WHERE (authentication_string='' OR authentication_string IS NULL) AND account_locked='N'",
         "anon": "SELECT host FROM mysql.user WHERE user=''",
         "rootany": "SELECT host FROM mysql.user WHERE user='root' AND host='%'",
         "ssl": "SELECT @@have_ssl",
        }
        out = []
        for k, sql in q.items():
            rc, so, se = _run(base + [sql], env)
            if rc != 0:
                if k in ("emptypw", "anon", "rootany", "ssl"): continue  # lacking privilege on mysql.user is normal
                return out, f"connection/query failed: {se.strip()[:160]}"
            rows = [r for r in so.strip().splitlines() if r]
            for r in rows:
                r2 = r.replace("\t", ".")
                if k == "nopk": out.append(mk("SQL-NO-PK", f"Table `{r2}` has no PRIMARY KEY", "sql-schema", "code_smell", "medium", "database", label, 1, r2, "Duplicates, replication issues.", "Add a primary key.", 20, ["CWE-1007"]))
                elif k == "myisam": out.append(mk("SQL-MYISAM", f"Table `{r2}` uses MyISAM", "sql-schema", "code_smell", "low", "database", label, 1, r2, "No transactions/FKs.", "ALTER TABLE ... ENGINE=InnoDB;", 20))
                elif k == "utf8": out.append(mk("SQL-UTF8MB3", f"Table uses 3-byte utf8: {r2}", "sql-schema", "bug", "low", "database", label, 1, r2, "4-byte chars fail.", "Convert to utf8mb4.", 30))
                elif k == "fknoidx": out.append(mk("SQL-FK-NO-INDEX", f"Foreign key without index: {r2}", "sql-schema", "performance", "low", "database", label, 1, r2, "Slow joins/cascades.", "CREATE INDEX on the FK column.", 10))
                elif k == "money": out.append(mk("SQL-MONEY-FLOAT", f"Money column uses float: {r2}", "sql-schema", "bug", "medium", "database", label, 1, r2, "Rounding errors.", "Use DECIMAL(12,2).", 30, ["CWE-681"]))
                elif k == "emptypw": out.append(mk("DB-EMPTY-PASSWORD", f"MySQL account with empty password: {r2}", "sql-schema", "vulnerability", "critical", "authn", label, 1, r2, "Anyone can log in.", "Set a strong password or lock the account.", 10, ["CWE-258"], ["A07:2021"]))
                elif k == "anon": out.append(mk("DB-ANON-USER", f"Anonymous MySQL user from host {r2}", "sql-schema", "vulnerability", "high", "authn", label, 1, r2, "Unauthenticated access.", "DROP USER ''@'host';", 5, ["CWE-287"], ["A07:2021"]))
                elif k == "rootany": out.append(mk("DB-ROOT-REMOTE", "MySQL root can log in from any host (%)", "sql-schema", "vulnerability", "high", "authz", label, 1, "root@%", "Remote root login enables brute force and full takeover.", "Restrict root to localhost; create a limited app user.", 10, ["CWE-250"], ["A01:2021"]))
                elif k == "ssl" and r2 not in ("YES", "1"): out.append(mk("DB-NO-TLS", "MySQL server TLS unavailable", "tls", "vulnerability", "medium", "crypto", label, 1, r2, "Cleartext credentials/data.", "Configure ssl_cert/ssl_key and require_secure_transport=ON.", 30, ["CWE-319"], ["A02:2021"]))
        if sample and db:
            rc, so, se = _run(base + ["SELECT CONCAT(table_name,'|',column_name) FROM information_schema.columns WHERE table_schema=" + sc + " AND column_name REGEXP '^(password|passwd|pwd|pass)$'"], env)
            for r in [x for x in so.strip().splitlines() if x] if rc == 0 else []:
                tbl, col = r.split("|")
                rc2, so2, _ = _run(base + [f"SELECT SUM(`{col}` NOT REGEXP '^(\\\\$2[aby]\\\\$|\\\\$argon2|\\\\$pbkdf2|\\\\$scrypt|\\\\$[156]\\\\$|pbkdf2_|[a-fA-F0-9]{{32,}})'), COUNT(*) FROM (SELECT `{col}` FROM `{tbl}` WHERE `{col}` IS NOT NULL LIMIT 200) s"], env)
                parts = so2.split()
                if rc2 == 0 and len(parts) == 2 and parts[0].isdigit() and int(parts[0]):
                    out.append(mk("DB-PLAINTEXT-PASSWORDS", f"{parts[0]} of {parts[1]} sampled `{tbl}.{col}` values do not look hashed", "crypto-pwd", "vulnerability", "critical", "crypto", label, 1, f"{parts[0]}/{parts[1]} sampled rows (aggregate only; no values read)", "A DB leak exposes real passwords.", "Hash with argon2id/bcrypt, force reset.", 120, ["CWE-256"], ["A02:2021"]))
        return out, "mysql OK"
    if scheme in ("redis", "rediss"):
        cli = shutil.which("redis-cli")
        if not cli: return [], "redis-cli not installed"
        host, port = u.hostname or "localhost", str(u.port or 6379)
        env["REDISCLI_AUTH"] = unquote(u.password or env.get("REDISCLI_AUTH", ""))
        base = [cli, "-h", host, "-p", port] + (["--tls"] if scheme == "rediss" else [])
        out = []
        rc, so, se = _run(base + ["PING"], {k: v for k, v in env.items() if k != "REDISCLI_AUTH"})
        if rc == 0 and "PONG" in so:
            out.append(mk("DB-REDIS-NOAUTH", "Redis accepts commands WITHOUT authentication", "srv-exposed", "vulnerability", "critical", "authn", label, 1, "PING → PONG with no password", "Anyone who can reach it can read/overwrite all data and often gain code execution (CONFIG SET dir / MODULE LOAD).", "Set `requirepass` (or ACL users), bind to private interface, protected-mode yes, firewall the port.", 20, ["CWE-306"], ["A07:2021"]))
        rc, so, se = _run(base + ["INFO", "server"], env)
        if rc != 0: return out, f"connection failed: {se.strip()[:100] or so.strip()[:100]}"
        m = re.search(r"redis_version:(\S+)", so)
        rc, so2, _ = _run(base + ["CONFIG", "GET", "protected-mode"], env)
        if "no" in so2.split() and scheme == "redis": out.append(mk("DB-REDIS-PROTECTED-OFF", "Redis protected-mode is off", "srv-exposed", "vulnerability", "medium", "misconfiguration", label, 1, "protected-mode no", "Disables the safety net for exposed instances.", "CONFIG SET protected-mode yes (and persist in redis.conf).", 5, ["CWE-1188"], ["A05:2021"]))
        return out, f"redis {m.group(1) if m else ''} OK"
    if scheme in ("mongodb", "mongodb+srv"):
        cli = shutil.which("mongosh") or shutil.which("mongo")
        if not cli: return [], "mongosh not installed"
        out = []
        js = "JSON.stringify({auth: db.adminCommand({connectionStatus:1}).authInfo.authenticatedUsers.length, ver: db.version(), dbs: db.adminCommand({listDatabases:1}).databases.map(d=>d.name)})"
        rc, so, se = _run([cli, "--quiet", "--eval", js, url], env, timeout=40)
        if rc != 0: return [], f"connection/query failed: {(se or so).strip()[:120]}"
        try: j = json.loads(so.strip().splitlines()[-1])
        except ValueError: return [], "unexpected mongosh output"
        if not u.username and j.get("dbs"): out.append(mk("DB-MONGO-NOAUTH", f"MongoDB lists databases without credentials ({len(j['dbs'])} found)", "srv-exposed", "vulnerability", "critical", "authn", label, 1, ", ".join(j["dbs"][:6]), "Unauthenticated read/write of all databases.", "Enable `security.authorization: enabled`, create least-privilege users, bind to private IPs.", 30, ["CWE-306"], ["A07:2021"]))
        return out, f"mongodb {j.get('ver','')} OK"
    if scheme in ("mssql", "sqlserver"):
        cli = shutil.which("sqlcmd")
        if not cli: return [], "sqlcmd not installed"
        env["SQLCMDPASSWORD"] = unquote(u.password or env.get("SQLCMDPASSWORD", ""))
        base = [cli, "-S", f"{u.hostname},{u.port or 1433}", "-U", unquote(u.username or "sa"), "-d", (u.path or "/master")[1:] or "master", "-h", "-1", "-W", "-b", "-Q"]
        out = []
        checks = {"xp": "SET NOCOUNT ON; SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell'", "sa": "SET NOCOUNT ON; SELECT is_disabled FROM sys.sql_logins WHERE name='sa'", "blank": "SET NOCOUNT ON; SELECT name FROM sys.sql_logins WHERE PWDCOMPARE('',password_hash)=1",
                  "nopk": "SET NOCOUNT ON; SELECT TOP 30 s.name+'.'+t.name FROM sys.tables t JOIN sys.schemas s ON s.schema_id=t.schema_id WHERE OBJECTPROPERTY(t.object_id,'TableHasPrimaryKey')=0", "trust": "SET NOCOUNT ON; SELECT name FROM sys.databases WHERE is_trustworthy_on=1 AND name NOT IN ('msdb')"}
        for k, q in checks.items():
            rc, so, se = _run(base + [q], env)
            if rc != 0:
                if k == "xp": return out, f"connection/query failed: {(se or so).strip()[:120]}"
                continue
            rows = [x.strip() for x in so.splitlines() if x.strip()]
            if k == "xp" and rows and rows[0] == "1": out.append(mk("DB-MSSQL-XPCMDSHELL", "xp_cmdshell is enabled", "sql-schema", "vulnerability", "high", "authz", label, 1, "xp_cmdshell = 1", "SQL injection or a stolen login becomes OS command execution.", "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;", 10, ["CWE-78"], ["A05:2021"]))
            elif k == "sa" and rows and rows[0] == "0": out.append(mk("DB-MSSQL-SA-ENABLED", "The `sa` login is enabled", "sql-schema", "vulnerability", "medium", "authn", label, 1, "sa enabled", "Well-known target for brute force.", "ALTER LOGIN sa DISABLE; use named least-privilege logins.", 10, ["CWE-1188"], ["A07:2021"]))
            elif k == "blank" and rows: out.append(mk("DB-MSSQL-BLANK-PWD", f"SQL login(s) with blank password: {', '.join(rows[:5])}", "sql-schema", "vulnerability", "critical", "authn", label, 1, "PWDCOMPARE('') matched", "Anyone can log in.", "Set strong passwords or disable the logins.", 10, ["CWE-258"], ["A07:2021"]))
            elif k == "nopk": [out.append(mk("SQL-NO-PK", f"Table `{r}` has no PRIMARY KEY", "sql-schema", "code_smell", "medium", "database", label, 1, r, "Duplicates, replication issues.", "Add a primary key.", 20, ["CWE-1007"])) for r in rows]
            elif k == "trust" and rows: out.append(mk("DB-MSSQL-TRUSTWORTHY", f"TRUSTWORTHY ON for: {', '.join(rows[:5])}", "sql-schema", "vulnerability", "medium", "authz", label, 1, ", ".join(rows[:5]), "Allows privilege escalation through db_owner.", "ALTER DATABASE x SET TRUSTWORTHY OFF.", 15, ["CWE-269"], ["A01:2021"]))
        return out, "mssql OK"
    return [], f"unsupported DB scheme: {scheme} (supported: sqlite file, postgres, mysql/mariadb, redis, mongodb, mssql; static: any .sql incl. T-SQL/PL-SQL)"


def audit_target(spec, sample=False):
    """spec: path to .db/.sqlite/.sqlite3 file, or a URL (postgres://, mysql://). Never raises."""
    try:
        return _audit_target(spec, sample)
    except Exception as e:  # a broken DB must not abort the whole audit
        return [], f"audit error: {type(e).__name__}: {str(e)[:120]}"


def _audit_target(spec, sample=False):
    if "://" in spec:
        return audit_url(spec, sample)
    if os.path.isfile(spec):
        return audit_sqlite(spec, sample=sample)
    return [], "not found"
