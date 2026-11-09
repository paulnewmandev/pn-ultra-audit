"""Read-only code retrieval over FTP/FTPS (ftplib) and SFTP (system `sftp`) for hosts without shell access.
Only downloads (RETR / get). Never uploads, deletes or renames. Passwords come from an environment variable - never the command line."""
import ftplib, os, re, shutil, ssl, subprocess, tempfile, urllib.parse

SKIP = {"node_modules", "vendor", ".git", "__pycache__", ".venv", "venv", "dist", "build", ".next", "cache", "logs", "tmp", "storage"}


def ftp_pull(url, pass_env="FTP_PASSWORD", allow_plain=False, max_files=5000, max_mb=300, per_file=1_500_000, max_depth=12, timeout=30):
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("ftp", "ftps") or not u.hostname: return None, "use ftp://user@host/path or ftps://user@host/path"
    user = urllib.parse.unquote(u.username or "anonymous"); pw = os.environ.get(pass_env, "anonymous@" if user == "anonymous" else "")
    if user != "anonymous" and not pw: return None, f"password not found: export {pass_env}=… (never pass it on the command line)"
    port = u.port or 21; base = u.path or "/"
    ftp = None; secure = False
    try:
        try:
            ftp = ftplib.FTP_TLS(timeout=timeout, context=ssl.create_default_context()); ftp.connect(u.hostname, port); ftp.auth(); ftp.login(user, pw); ftp.prot_p(); secure = True
        except (ftplib.all_errors, ssl.SSLError, OSError) as e:
            if not allow_plain and u.scheme == "ftps": return None, f"FTPS failed: {e}"
            if not allow_plain: return None, f"server does not offer FTPS ({str(e)[:80]}). Plain FTP sends passwords in clear text - use SFTP/FTPS, or pass --ftp-allow-plain on a trusted network"
            ftp = ftplib.FTP(timeout=timeout); ftp.connect(u.hostname, port); ftp.login(user, pw)
    except ftplib.all_errors as e: return None, f"FTP login failed: {str(e)[:120]}"
    dest = tempfile.mkdtemp(prefix="pnua-ftp-"); files = [0, 0]; skipped = [0]
    def walk(rp, lp, depth):
        if depth > max_depth or files[0] >= max_files or files[1] > max_mb * 1024 * 1024: return
        try: entries = list(ftp.mlsd(rp, facts=["type", "size"]))
        except ftplib.all_errors:
            entries = []
            lines = []
            try: ftp.retrlines(f"LIST {rp}", lines.append)
            except ftplib.all_errors: return
            for l in lines:
                m = re.match(r"^([\-dl])[rwxsStT\-]{9}\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\S+\s+\d+\s+\S+\s+(.+)$", l)
                if m: entries.append((m.group(3), {"type": {"-": "file", "d": "dir", "l": "OS.unix=symlink"}[m.group(1)], "size": m.group(2)}))
        for name, f in entries:
            if name in (".", "..") or "/" in name or "\\" in name or name.startswith(".."): continue
            t = f.get("type", "")
            if t == "dir":
                if name in SKIP: continue
                os.makedirs(os.path.join(lp, name), exist_ok=True); walk(rp.rstrip("/") + "/" + name, os.path.join(lp, name), depth + 1)
            elif t == "file":
                sz = int(f.get("size") or 0)
                if sz > per_file or files[0] >= max_files or files[1] + sz > max_mb * 1024 * 1024: skipped[0] += 1; continue
                target = os.path.realpath(os.path.join(lp, name))
                if not target.startswith(os.path.realpath(dest) + os.sep): continue
                try:
                    with open(target, "wb") as fh: ftp.retrbinary(f"RETR {rp.rstrip('/')}/{name}", fh.write)
                    files[0] += 1; files[1] += sz
                except ftplib.all_errors: skipped[0] += 1
            else: skipped[0] += 1  # symlinks/devices never followed
    try: walk(base, dest, 0)
    finally:
        try: ftp.quit()
        except Exception: pass
    if files[0] == 0: shutil.rmtree(dest, ignore_errors=True); return None, "no files retrieved (check the path and permissions)"
    return dict(path=dest, files=files[0], bytes=files[1], skipped=skipped[0], secure=secure), None


def sftp_pull(target, remote_path, key=None, port=None, opts="", accept_new=False, timeout=600, max_mb=300):
    if not shutil.which("sftp"): return None, "sftp client not installed"
    dest = tempfile.mkdtemp(prefix="pnua-sftp-")
    cmd = ["sftp", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"] + (["-o", "StrictHostKeyChecking=accept-new"] if accept_new else []) + (["-i", os.path.expanduser(key), "-o", "IdentitiesOnly=yes"] if key else []) + (["-P", str(port)] if port else [])
    if opts:
        import shlex; cmd += shlex.split(opts)
    cmd += ["-b", "-", target]
    batch = f"lcd {dest}\nget -r {remote_path} .\nbye\n"
    try: r = subprocess.run(cmd, input=batch, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e: shutil.rmtree(dest, ignore_errors=True); return None, f"sftp failed: {e}"
    if r.returncode != 0 and not os.listdir(dest): shutil.rmtree(dest, ignore_errors=True); return None, "sftp failed: " + (r.stderr.strip().splitlines() or [f"exit {r.returncode}"])[-1][:160]
    # sanitize: drop symlinks, escape attempts, huge/skipped dirs, enforce size cap
    total = n = 0; real = os.path.realpath(dest)
    for dp, dn, fn in os.walk(dest):
        dn[:] = [d for d in dn if d not in SKIP]
        for f in fn:
            p = os.path.join(dp, f)
            if os.path.islink(p) or not os.path.realpath(p).startswith(real + os.sep) or os.path.getsize(p) > 1_500_000 or total > max_mb * 1024 * 1024:
                try: os.remove(p)
                except OSError: pass
            else: total += os.path.getsize(p); n += 1
    root = dest
    kids = [d for d in os.listdir(dest) if os.path.isdir(os.path.join(dest, d))]
    if len(kids) == 1 and not [f for f in os.listdir(dest) if os.path.isfile(os.path.join(dest, f))]: root = os.path.join(dest, kids[0])
    if n == 0: shutil.rmtree(dest, ignore_errors=True); return None, "no files retrieved"
    return dict(path=root, base=dest, files=n, bytes=total, skipped=0, secure=True), None
