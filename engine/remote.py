"""SSH support (uses the system `ssh` binary; key/agent auth only, BatchMode, no passwords).

  * server_audit  - one read-only bash script over SSH -> parsed into findings
  * pull_tree     - stream the remote project dir as tar.gz into a local temp dir (validated)
  * Tunnel        - `ssh -L` port-forward so DB audits can reach private DB/RDS endpoints
Nothing is written on the server. Every remote command is listed in REMOTE_SCRIPT below."""
import datetime, io, os, re, shlex, socket, subprocess, tarfile, time

from .kb import KB

TODAY = datetime.date.today()


class SSH:
    def __init__(self, target, key=None, port=None, opts="", accept_new=False, sudo=False):
        m = re.match(r"^(.*?)(?::(\d+))?$", target)
        self.target, self.port = (m.group(1), port or (m.group(2) if m.group(2) else None))
        self.key, self.opts, self.accept_new, self.sudo = key, opts, accept_new, sudo
        self.label = self.target

    def base(self):
        c = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", "-T"]
        if self.accept_new: c += ["-o", "StrictHostKeyChecking=accept-new"]
        if self.key: c += ["-i", os.path.expanduser(self.key), "-o", "IdentitiesOnly=yes"]
        if self.port: c += ["-p", str(self.port)]
        if self.opts: c += shlex.split(self.opts)
        return c + [self.target]

    def run(self, command, timeout=90, stdin=None):
        try:
            r = subprocess.run(self.base() + [command], input=stdin, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            return 124, "", "timeout"
        except OSError as e:
            return 127, "", str(e)

    def check(self):
        rc, so, se = self.run("echo __ok__ && id -un && hostname", timeout=30)
        if rc != 0 or "__ok__" not in so:
            hint = se.strip().splitlines()[-1] if se.strip() else f"exit {rc}"
            return False, hint
        lines = so.split()
        return True, f"{lines[1]}@{lines[2]}" if len(lines) >= 3 else "ok"


# ───────────────────────── remote read-only script ─────────────────────────
REMOTE_SCRIPT = r'''
export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
SUDO="%(sudo)s"
S() { echo "### $1"; }
ROOTS="%(roots)s"
S os; cat /etc/os-release 2>/dev/null | egrep '^(ID|VERSION_ID|PRETTY_NAME)='; uname -r
S runtimes; (node -v; python3 -V; php -v | head -1; java -version 2>&1 | head -1; ruby -v) 2>/dev/null
S updates; if command -v apt >/dev/null 2>&1; then echo "mgr=apt"; apt list --upgradable 2>/dev/null | grep -ci security; [ -f /var/run/reboot-required ] && echo reboot-required; dpkg -l unattended-upgrades 2>/dev/null | grep -c '^ii'; elif command -v dnf >/dev/null 2>&1; then echo "mgr=dnf"; timeout 25 dnf -q updateinfo list security 2>/dev/null | wc -l; elif command -v yum >/dev/null 2>&1; then echo "mgr=yum"; timeout 25 yum -q updateinfo list security 2>/dev/null | wc -l; fi
S sshd; ($SUDO sshd -T 2>/dev/null || cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null) | egrep -i '^\s*(permitrootlogin|passwordauthentication|permitemptypasswords|x11forwarding|maxauthtries|pubkeyauthentication|port|challengeresponseauthentication|kbdinteractiveauthentication)\s'
S uid0; awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null
S emptypw; $SUDO awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null
S nopasswd; $SUDO grep -rhE 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^#'
S ports; (ss -H -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null)
S firewall; ($SUDO ufw status 2>/dev/null | head -3); echo "firewalld=$(systemctl is-active firewalld 2>/dev/null)"; echo "iptables_rules=$($SUDO iptables -S 2>/dev/null | wc -l)"; echo "nft_rules=$($SUDO nft list ruleset 2>/dev/null | wc -l)"
S services; echo "fail2ban=$(systemctl is-active fail2ban 2>/dev/null)"; echo "ntp=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
S procs; ps -eo user:20,comm --no-headers 2>/dev/null | egrep -w 'node|gunicorn|uwsgi|java|php-fpm|mysqld|mariadbd|redis-server|mongod|postgres|nginx|apache2|httpd|python3' | sort | uniq -c
S webfiles; for r in $ROOTS; do [ -d "$r" ] && { find "$r" -maxdepth 5 \( -name node_modules -o -name vendor \) -prune -o \( -name '.env' -o -name '.env.*' -o -name '.git' -o -name '*.sql' -o -name '*.bak' -o -name '*.dump' -o -name '*.old' -o -name '*.zip' -o -name '*.tar.gz' -o -name 'phpinfo.php' -o -name 'id_rsa' \) -print 2>/dev/null | head -60; }; done
S worldwritable; for r in $ROOTS; do [ -d "$r" ] && find "$r" -xdev \( -name node_modules -o -name vendor -o -name storage -o -name cache -o -name logs -o -name tmp -o -name uploads \) -prune -o -type f -perm -0002 -print 2>/dev/null | head -20; done
S nginx; ($SUDO nginx -T 2>/dev/null | head -600) | egrep -i 'server_tokens|ssl_protocols|limit_req|limit_conn|autoindex|client_max_body_size|add_header (X-Frame|Strict|Content-Security)'
S apache; grep -rhiE 'ServerTokens|ServerSignature|Options.*Indexes|SSLProtocol' /etc/apache2 /etc/httpd 2>/dev/null | grep -v '^\s*#' | head -20
S php; grep -hiE '^\s*(expose_php|display_errors|allow_url_include|allow_url_fopen)\s*=' /etc/php/*/fpm/php.ini /etc/php.ini 2>/dev/null | sort -u
S certs; for f in /etc/letsencrypt/live/*/cert.pem; do [ -f "$f" ] && echo "$f $($SUDO openssl x509 -enddate -noout -in "$f" 2>/dev/null)"; done
S docker; if command -v docker >/dev/null 2>&1; then docker ps --format 'C|{{.Names}}|{{.Image}}|{{.Ports}}' 2>/dev/null; docker ps -q 2>/dev/null | xargs -r docker inspect --format 'I|{{.Name}}|priv={{.HostConfig.Privileged}}|user={{.Config.User}}|net={{.HostConfig.NetworkMode}}' 2>/dev/null; ls -l /var/run/docker.sock 2>/dev/null; fi
S disk; df -P -x tmpfs -x devtmpfs 2>/dev/null | tail -n +2; free -m 2>/dev/null | sed -n 2,3p
S authfail; for f in /var/log/auth.log /var/log/secure; do [ -r "$f" ] || { $SUDO test -r "$f" 2>/dev/null; }; $SUDO grep -c 'Failed password' "$f" 2>/dev/null; $SUDO grep 'Failed password' "$f" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -rn | head -5; done
S end
'''

EOL = {  # (id, version-prefix): EOL date (verify against vendor pages)
    ("ubuntu", "16.04"): "2021-04-30", ("ubuntu", "18.04"): "2023-05-31", ("ubuntu", "20.04"): "2025-05-31", ("ubuntu", "22.04"): "2027-04-30", ("ubuntu", "24.04"): "2029-04-30",
    ("debian", "9"): "2022-06-30", ("debian", "10"): "2024-06-30", ("debian", "11"): "2026-08-31", ("debian", "12"): "2028-06-30",
    ("centos", "6"): "2020-11-30", ("centos", "7"): "2024-06-30", ("centos", "8"): "2021-12-31", ("amzn", "2"): "2026-06-30", ("rhel", "7"): "2024-06-30", ("rocky", "8"): "2029-05-31",
}
RUNTIME_EOL = {"node": {"14": "2023-04-30", "16": "2023-09-11", "18": "2025-04-30", "20": "2026-04-30", "22": "2027-04-30"},
               "python": {"3.7": "2023-06-27", "3.8": "2024-10-07", "3.9": "2025-10-31", "3.10": "2026-10-31", "3.11": "2027-10-31", "3.12": "2028-10-31"},
               "php": {"7.2": "2020-11-30", "7.3": "2021-12-06", "7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31", "8.2": "2026-12-31", "8.3": "2027-12-31"}}
SENSITIVE_PORTS = {3306: ("MySQL/MariaDB", "high"), 5432: ("PostgreSQL", "high"), 6379: ("Redis", "critical"), 27017: ("MongoDB", "critical"), 9200: ("Elasticsearch", "critical"), 9300: ("Elasticsearch transport", "high"),
                   11211: ("memcached", "critical"), 2375: ("Docker API (no TLS)", "critical"), 2379: ("etcd", "critical"), 5984: ("CouchDB", "high"), 9042: ("Cassandra", "high"), 1433: ("MS SQL Server", "high"),
                   5601: ("Kibana", "high"), 15672: ("RabbitMQ management", "medium"), 8500: ("Consul", "high"), 5900: ("VNC", "high"), 23: ("Telnet", "high"), 21: ("FTP", "medium"), 3389: ("RDP", "high"),
                   445: ("SMB", "high"), 139: ("NetBIOS", "medium"), 111: ("rpcbind", "medium"), 161: ("SNMP", "medium"), 10250: ("kubelet", "high"), 6443: ("Kubernetes API", "medium")}


def _f(rule, title, family, typ, sev, cat, label, ev, fix=None, effort=15, cwe=(), owasp=(), status="confirmed", priority=None, why=None, impact=None):
    kb = KB[family]
    return dict(rule=rule, title=title, family=family, type=typ, severity=sev if status == "confirmed" else None, category=cat, file=label, line=1, evidence=ev[:400],
                impact=impact or kb["impact"], fix=fix or "; ".join(kb["steps"][:2]), effort_min=effort, cwe=list(cwe), owasp=list(owasp), status=status, priority=priority, why=why)


def build_script(roots, sudo):
    return REMOTE_SCRIPT % dict(sudo="sudo -n" if sudo else "", roots=" ".join(shlex.quote(r) for r in roots))


def parse_sections(out):
    sec, cur = {}, None
    for line in out.splitlines():
        if line.startswith("### "): cur = line[4:].strip(); sec[cur] = []
        elif cur is not None: sec[cur].append(line.rstrip())
    return sec


def analyze(sec, label, sudo_used):
    F = []
    L = lambda k: [x for x in sec.get(k, []) if x.strip()]
    # OS
    os_kv = dict(x.split("=", 1) for x in L("os") if "=" in x)
    osid, osver = os_kv.get("ID", "").strip('"'), os_kv.get("VERSION_ID", "").strip('"')
    key = next((k for k in EOL if k[0] == osid and (osver == k[1] or osver.startswith(k[1] + "."))), None)
    pretty = os_kv.get("PRETTY_NAME", f"{osid} {osver}").strip('"')
    if key:
        eol = datetime.date.fromisoformat(EOL[key])
        if eol < TODAY:
            F.append(_f("SRV-OS-EOL", f"Operating system is end-of-life: {pretty} (EOL {eol})", "srv-patch", "vulnerability", "high", "patching", label, pretty, effort=480, cwe=["CWE-1104"], owasp=["A06:2021"],
                        why=None))
        elif (eol - TODAY).days < 180:
            F.append(_f("SRV-OS-EOL-SOON", f"Operating system reaches end-of-life soon: {pretty} (EOL {eol})", "srv-patch", "code_smell", "low", "patching", label, pretty, effort=240, owasp=["A06:2021"]))
    # runtimes
    for line in L("runtimes"):
        for name, rx in (("node", r"^v(\d+)"), ("python", r"Python (\d+\.\d+)"), ("php", r"PHP (\d+\.\d+)")):
            m = re.search(rx, line)
            if m:
                ver = m.group(1); date = RUNTIME_EOL[name].get(ver)
                if date and datetime.date.fromisoformat(date) < TODAY:
                    F.append(_f(f"SRV-RUNTIME-EOL-{name.upper()}", f"{name} {ver} is end-of-life since {date}", "srv-patch", "vulnerability", "high" if name == "php" else "medium", "patching", label, line.strip(), effort=240, cwe=["CWE-1104"], owasp=["A06:2021"]))
    # updates
    u = L("updates")
    if u:
        mgr = u[0].replace("mgr=", "")
        nums = [int(x) for x in u[1:] if x.strip().isdigit()]
        n = nums[0] if nums else 0
        if n:
            F.append(_f("SRV-PENDING-SECURITY", f"{n} pending security update(s) ({mgr})", "srv-patch", "vulnerability", "high" if n >= 10 else "medium", "patching", label, f"{n} security updates available", effort=30, cwe=["CWE-1104"], owasp=["A06:2021"]))
        if "reboot-required" in u:
            F.append(_f("SRV-REBOOT", "Reboot required to apply kernel/library updates", "srv-patch", "code_smell", "low", "patching", label, "/var/run/reboot-required exists", effort=10))
        if mgr == "apt" and len(nums) >= 2 and nums[1] == 0:
            F.append(_f("SRV-NO-AUTOUPDATE", "unattended-upgrades is not installed", "srv-patch", "security_hotspot", None, "patching", label, "dpkg: unattended-upgrades not installed", status="needs_validation", priority="medium", effort=10,
                        why="another patch mechanism (Ansible/SSM/Landscape) may handle updates"))
    # sshd
    ssh = {}
    for line in L("sshd"):
        p = line.split(None, 1)
        if len(p) == 2: ssh[p[0].lower()] = p[1].strip().lower()
    if ssh:
        if ssh.get("permitrootlogin") in ("yes", "without-password", "prohibit-password") and ssh.get("permitrootlogin") == "yes":
            F.append(_f("SRV-SSH-ROOT", "SSH allows direct root login", "srv-ssh", "vulnerability", "high", "authn", label, "PermitRootLogin yes", effort=15, cwe=["CWE-250"], owasp=["A07:2021"]))
        if ssh.get("passwordauthentication") == "yes":
            F.append(_f("SRV-SSH-PASSWORD", "SSH password authentication enabled", "srv-ssh", "vulnerability", "medium", "authn", label, "PasswordAuthentication yes", effort=15, cwe=["CWE-307"], owasp=["A07:2021"]))
        if ssh.get("permitemptypasswords") == "yes":
            F.append(_f("SRV-SSH-EMPTYPW", "SSH permits empty passwords", "srv-ssh", "vulnerability", "critical", "authn", label, "PermitEmptyPasswords yes", effort=5, cwe=["CWE-258"], owasp=["A07:2021"]))
        if ssh.get("x11forwarding") == "yes":
            F.append(_f("SRV-SSH-X11", "SSH X11 forwarding enabled", "srv-ssh", "code_smell", "low", "misconfiguration", label, "X11Forwarding yes", effort=5))
        try:
            if int(ssh.get("maxauthtries", "6")) > 4:
                F.append(_f("SRV-SSH-MAXTRIES", f"MaxAuthTries is {ssh['maxauthtries']}", "srv-ssh", "code_smell", "info", "misconfiguration", label, f"MaxAuthTries {ssh['maxauthtries']}", effort=5))
        except ValueError:
            pass
    else:
        F.append(_f("SRV-SSH-UNREAD", "sshd configuration could not be read (needs --sudo or read access)", "srv-ssh", "security_hotspot", None, "authn", label, "(empty)", status="needs_validation", priority="medium", effort=10,
                    why="re-run with --sudo to evaluate PermitRootLogin / PasswordAuthentication"))
    # users
    extra0 = [u for u in L("uid0") if u != "root"]
    if extra0: F.append(_f("SRV-UID0", f"Extra UID-0 account(s): {', '.join(extra0)}", "srv-user", "vulnerability", "high", "authz", label, "UID 0: " + ", ".join(extra0), effort=15, cwe=["CWE-250"], owasp=["A01:2021"]))
    if L("emptypw"): F.append(_f("SRV-EMPTY-PW", f"Account(s) with empty password: {', '.join(L('emptypw'))}", "srv-user", "vulnerability", "critical", "authn", label, "/etc/shadow empty hash", effort=5, cwe=["CWE-258"], owasp=["A07:2021"]))
    elif not sudo_used: F.append(_f("SRV-SHADOW-UNREAD", "Could not check /etc/shadow for empty passwords (needs --sudo)", "srv-user", "security_hotspot", None, "authn", label, "", status="needs_validation", priority="low", effort=5, why="/etc/shadow requires root"))
    nop = L("nopasswd")
    if nop: F.append(_f("SRV-SUDO-NOPASSWD", f"{len(nop)} sudoers rule(s) with NOPASSWD", "srv-user", "security_hotspot", None, "authz", label, "\n".join(nop[:5]), status="needs_validation", priority="medium", effort=20,
                        why="common for deploy/automation users; confirm each is limited to specific commands"))
    # firewall
    fw = "\n".join(sec.get("firewall", []))
    ufw_on = "Status: active" in fw; fwd_on = "firewalld=active" in fw
    ipt = re.search(r"iptables_rules=(\d+)", fw); nft = re.search(r"nft_rules=(\d+)", fw)
    rules_n = (int(ipt.group(1)) if ipt else 0) + (int(nft.group(1)) if nft else 0)
    fw_active = ufw_on or fwd_on or rules_n > 8
    fw_readable = ufw_on or fwd_on or "Status: inactive" in fw or rules_n > 0 or sudo_used
    f2b = any(x.strip() == "fail2ban=active" for x in sec.get("services", []))
    if fw_readable and not fw_active:
        F.append(_f("SRV-NO-FIREWALL", "No active host firewall detected (ufw/firewalld/iptables/nft)", "srv-fw", "security_hotspot", None, "misconfiguration", label, fw[:200] or "(no rules)", status="needs_validation", priority="high", effort=30,
                    owasp=["A05:2021"], why="a cloud security group / network ACL in front of the host may be the real perimeter - confirm its rules"))
    if not f2b and ssh.get("passwordauthentication") == "yes":
        F.append(_f("SRV-NO-FAIL2BAN", "fail2ban not active while SSH password auth is enabled", "srv-fw", "code_smell", "low", "authn", label, "fail2ban inactive", effort=20))
    # ports
    seen = set()
    for line in L("ports"):
        m = re.search(r"^(tcp|udp)\S*\s+(?:\S+\s+)?(?:\d+\s+\d+\s+)?(\S+):(\d+)\s", line + " ") or re.search(r"(tcp6?|udp6?)\s+\S*\s*\S*\s+(\S+):(\d+)\s", line + " ")
        if not m: continue
        addr, port = m.group(2), int(m.group(3))
        if addr in ("127.0.0.1", "::1", "[::1]", "127.0.0.53", "127.0.0.54") or (port, addr) in seen: continue
        seen.add((port, addr))
        if port in SENSITIVE_PORTS:
            name, sev = SENSITIVE_PORTS[port]
            proc = (re.search(r'users:\(\("([^"]+)"', line) or re.search(r"\d+/(\S+)\s*$", line))
            ev = f"{m.group(1)} {addr}:{port} {name}" + (f" ({proc.group(1)})" if proc else "")
            if fw_active:
                F.append(_f(f"SRV-PORT-{port}", f"{name} (port {port}) listens on all interfaces; firewall is active - verify it blocks the port", "srv-exposed", "security_hotspot", None, "exposure", label, ev, status="needs_validation", priority="high",
                            effort=15, cwe=["CWE-668"], owasp=["A05:2021"], why="bound to all interfaces; reachable only if the firewall/security group allows it"))
            elif fw_readable:
                F.append(_f(f"SRV-PORT-{port}", f"{name} (port {port}) listens on all interfaces and no host firewall is active", "srv-exposed", "vulnerability", sev, "exposure", label, ev, effort=20, cwe=["CWE-668"], owasp=["A05:2021"],
                            why="verify the cloud security group does not already block it"))
            else:
                F.append(_f(f"SRV-PORT-{port}", f"{name} (port {port}) listens on all interfaces", "srv-exposed", "security_hotspot", None, "exposure", label, ev, status="needs_validation", priority="high", effort=15,
                            cwe=["CWE-668"], owasp=["A05:2021"], why="firewall state unknown (re-run with --sudo)"))
    # processes as root
    by = {}
    for line in L("procs"):
        m = re.match(r"\s*(\d+)\s+(\S+)\s+(\S+)", line)
        if m: by.setdefault(m.group(3), set()).add(m.group(2))
    for comm, users in by.items():
        if users == {"root"} and comm in ("node", "gunicorn", "uwsgi", "java", "mysqld", "mariadbd", "redis-server", "mongod", "python3"):
            F.append(_f(f"SRV-ROOT-PROC-{comm}", f"`{comm}` runs only as root", "srv-user", "vulnerability", "medium", "authz", label, f"{comm}: user root", effort=30, cwe=["CWE-250"], owasp=["A05:2021"]))
    # web files
    for p in L("webfiles"):
        b = os.path.basename(p)
        in_docroot = bool(re.search(r"/(public|public_html|html|htdocs|wwwroot|web|dist)(/[^/]+){0,2}/[^/]+$", p)) and not re.search(r"/(node_modules|vendor)/", p)
        if b.startswith(".env") and not re.search(r"example|sample|dist|template", b):
            F.append(_f("SRV-ENV-" + ("DOCROOT" if in_docroot else "PRESENT"), f"Environment file on server: {p}" + (" (inside a web-served directory)" if in_docroot else ""), "srv-web", "vulnerability" if in_docroot else "security_hotspot",
                        "high" if in_docroot else None, "secrets", label, p, effort=15, cwe=["CWE-540"], owasp=["A05:2021"], status="confirmed" if in_docroot else "needs_validation", priority=None if in_docroot else "medium",
                        why=None if in_docroot else "verify the web server root does not serve this directory"))
        elif b == ".git":
            F.append(_f("SRV-GIT-DIR", f"`.git` directory on server: {p}" + (" (inside web root)" if in_docroot else ""), "srv-web", "vulnerability" if in_docroot else "security_hotspot", "high" if in_docroot else None, "exposure", label, p, effort=15, cwe=["CWE-538"], owasp=["A05:2021"],
                        status="confirmed" if in_docroot else "needs_validation", priority=None if in_docroot else "low", why=None if in_docroot else "check the web server denies dotfiles"))
        elif re.search(r"\.(sql|bak|dump|old|zip|tar\.gz)$", b) or b in ("phpinfo.php", "id_rsa"):
            F.append(_f("SRV-BACKUP-FILE", f"Backup/dump/sensitive file under project dirs: {p}", "srv-web", "vulnerability" if in_docroot else "security_hotspot", "high" if in_docroot else None, "exposure", label, p, effort=15, cwe=["CWE-530"], owasp=["A05:2021"],
                        status="confirmed" if in_docroot else "needs_validation", priority=None if in_docroot else "medium", why=None if in_docroot else "move backups off the server or outside any served directory"))
    ww = L("worldwritable")
    if ww: F.append(_f("SRV-WORLD-WRITABLE", f"{len(ww)} world-writable file(s) in project dirs", "srv-web", "vulnerability", "medium", "misconfiguration", label, "\n".join(ww[:8]), effort=15, cwe=["CWE-732"], owasp=["A05:2021"]))
    # nginx / apache / php
    ng = "\n".join(sec.get("nginx", []))
    if ng:
        if not re.search(r"server_tokens\s+off", ng): F.append(_f("SRV-NGINX-TOKENS", "nginx does not set `server_tokens off`", "srv-web", "code_smell", "info", "misconfiguration", label, "server_tokens not off", effort=5))
        if re.search(r"ssl_protocols[^;]*(TLSv1(\s|;)|TLSv1\.1|SSLv3)", ng): F.append(_f("SRV-NGINX-TLS", "nginx allows TLS 1.0/1.1", "srv-web", "vulnerability", "medium", "crypto", label, re.search(r"ssl_protocols[^;]*;", ng).group(0), effort=10, cwe=["CWE-326"], owasp=["A02:2021"]))
        if re.search(r"autoindex\s+on", ng): F.append(_f("SRV-NGINX-AUTOINDEX", "nginx directory listing enabled", "srv-web", "vulnerability", "medium", "exposure", label, "autoindex on", effort=5, cwe=["CWE-548"], owasp=["A05:2021"]))
        if not re.search(r"limit_req", ng): F.append(_f("SRV-NGINX-NO-LIMITREQ", "nginx has no `limit_req` rate limiting (DoS/brute-force)", "dos", "security_hotspot", None, "resource-exhaustion", label, "no limit_req directive", status="needs_validation", priority="high", effort=30,
                                                         cwe=["CWE-770"], owasp=["A04:2021", "API4:2023"], why="a CDN/WAF/load balancer may already rate-limit in front of nginx"))
    for line in L("php"):
        k, _, v = line.partition("="); k, v = k.strip().lower(), v.strip().lower()
        if (k == "expose_php" and v in ("on", "1")) or (k == "display_errors" and v in ("on", "1", "stdout")) or (k == "allow_url_include" and v in ("on", "1")):
            F.append(_f("SRV-PHP-" + k.upper(), f"PHP `{k} = {v}`", "srv-php", "vulnerability" if k == "allow_url_include" else "code_smell", "high" if k == "allow_url_include" else "low", "misconfiguration", label, line, effort=5, cwe=["CWE-16"], owasp=["A05:2021"]))
    # certs
    for line in L("certs"):
        m = re.search(r"(\S+)\s+notAfter=(.+)$", line)
        if m:
            try:
                d = datetime.datetime.strptime(m.group(2).strip(), "%b %d %H:%M:%S %Y %Z").date()
                days = (d - TODAY).days
                if days < 0: F.append(_f("SRV-CERT-EXPIRED", f"TLS certificate expired {-days} days ago: {m.group(1)}", "srv-cert", "bug", "high", "availability", label, m.group(0), effort=20))
                elif days < 14: F.append(_f("SRV-CERT-EXPIRING", f"TLS certificate expires in {days} days: {m.group(1)}", "srv-cert", "bug", "medium", "availability", label, m.group(0), effort=20))
            except ValueError:
                pass
    # docker
    for line in L("docker"):
        if line.startswith("I|") and "priv=true" in line:
            F.append(_f("SRV-DOCKER-PRIV", f"Privileged container: {line.split('|')[1]}", "srv-docker", "vulnerability", "high", "misconfiguration", label, line, effort=30, cwe=["CWE-250"], owasp=["A05:2021"]))
        if line.startswith("C|"):
            _, name, image, ports = (line.split("|") + ["", "", "", ""])[:4]
            if re.search(r"(postgres|mysql|mariadb|mongo|redis|elasticsearch|memcached)", image) and re.search(r"(0\.0\.0\.0|\[::\]):(3306|5432|27017|6379|9200|11211)->", ports):
                F.append(_f("SRV-DOCKER-DBPORT", f"Container `{name}` publishes a database port on all interfaces ({ports})", "srv-docker", "vulnerability", "high", "exposure", label, line, effort=10, cwe=["CWE-668"], owasp=["A05:2021"],
                            why="Docker bypasses ufw by editing iptables directly - also check the cloud security group"))
            if image.endswith(":latest") or ":" not in image:
                F.append(_f("SRV-DOCKER-LATEST", f"Container `{name}` uses floating image tag ({image})", "srv-docker", "code_smell", "low", "supply-chain", label, line, effort=10, owasp=["A08:2021"]))
        if re.match(r"^srw-rw-rw-.*docker\.sock", line): F.append(_f("SRV-DOCKER-SOCK", "Docker socket is world-writable", "srv-docker", "vulnerability", "critical", "authz", label, line, effort=5, cwe=["CWE-732"]))
    # disk / mem / brute force
    for line in L("disk"):
        m = re.search(r"(\d+)%\s+(/\S*)$", line)
        if m and int(m.group(1)) >= 90:
            F.append(_f("SRV-DISK-FULL", f"Disk {m.group(2)} is {m.group(1)}% full", "srv-resource", "bug", "high" if int(m.group(1)) >= 97 else "medium", "availability", label, line, effort=30, cwe=["CWE-400"]))
    af = [x for x in L("authfail")]
    if af and af[0].isdigit():
        n = int(af[0])
        if n >= 500:
            top = [x.strip() for x in af[1:6] if re.match(r"\s*\d+\s+\S+", x)]
            F.append(_f("SRV-SSH-BRUTEFORCE", f"{n} failed SSH password attempts in the current auth log", "srv-resource", "vulnerability" if ssh.get("passwordauthentication") == "yes" else "code_smell",
                        "medium" if ssh.get("passwordauthentication") == "yes" else "info", "authn", label, "top sources: " + "; ".join(top), effort=20, cwe=["CWE-307"], owasp=["A07:2021"]))
    return F, dict(os=pretty, listening=len(seen), firewall="active" if fw_active else ("inactive" if fw_readable else "unknown"), fail2ban=f2b)


def server_audit(ssh, roots, sudo):
    script = build_script(roots, sudo)
    rc, so, se = ssh.run("bash -s", timeout=180, stdin=script)
    if "### end" not in so:
        return None, f"remote audit incomplete (exit {rc}): {(se.strip().splitlines() or ['no output'])[-1]}"
    return analyze(parse_sections(so), f"ssh://{ssh.label}", sudo), None


# ───────────────────────── pull project tree over SSH ─────────────────────────
def pull_tree(ssh, remote_path, dest, max_mb=300, per_file=1_500_000):
    excl = ["--exclude=node_modules", "--exclude=vendor", "--exclude=.git", "--exclude=*.log", "--exclude=storage/framework", "--exclude=__pycache__", "--exclude=.venv", "--exclude=venv", "--exclude=dist", "--exclude=build", "--exclude=.next"]
    cmd = ssh.base() + ["tar -czf - " + " ".join(shlex.quote(e) for e in excl) + " -C " + shlex.quote(remote_path) + " . 2>/dev/null"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    total = files = skipped = 0
    cap = max_mb * 1024 * 1024
    dest_real = os.path.realpath(dest)
    try:
        with tarfile.open(fileobj=p.stdout, mode="r|gz") as tf:
            for m in tf:
                name = os.path.normpath(m.name).lstrip("/")
                if name.startswith("..") or "/../" in name or not (m.isfile() or m.isdir()): skipped += 1; continue
                target = os.path.realpath(os.path.join(dest, name))
                if not (target == dest_real or target.startswith(dest_real + os.sep)): skipped += 1; continue
                if m.isdir(): os.makedirs(target, exist_ok=True); continue
                if m.size > per_file: skipped += 1; continue
                total += m.size
                if total > cap: p.kill(); return files, total, skipped, f"aborted: exceeded {max_mb} MB (narrow --remote-path or add --exclude)"
                os.makedirs(os.path.dirname(target), exist_ok=True)
                fh = tf.extractfile(m)
                with open(target, "wb") as out: out.write(fh.read())
                files += 1
    except (tarfile.TarError, EOFError) as e:
        p.kill()
        return files, total, skipped, f"tar stream error: {e}"
    p.wait(timeout=30)
    err = (p.stderr.read() or b"").decode("utf-8", "ignore").strip()
    if files == 0: return files, total, skipped, err or "no files received (check --remote-path and permissions)"
    return files, total, skipped, None


# ───────────────────────── SSH tunnel for private DB / RDS ─────────────────────────
class Tunnel:
    def __init__(self, ssh, remote_host, remote_port):
        self.ssh, self.rh, self.rp, self.proc, self.port = ssh, remote_host, int(remote_port), None, None

    def __enter__(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); self.port = s.getsockname()[1]; s.close()
        self.proc = subprocess.Popen(self.ssh.base()[:-1] + ["-o", "ExitOnForwardFailure=yes", "-N", "-L", f"127.0.0.1:{self.port}:{self.rh}:{self.rp}", self.ssh.target], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(60):
            if self.proc.poll() is not None: raise RuntimeError("tunnel failed: " + (self.proc.stderr.read().decode("utf-8", "ignore").strip()[-200:]))
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.5).close(); return self
            except OSError:
                time.sleep(0.25)
        self.proc.kill(); raise RuntimeError("tunnel timeout (is the DB host/port reachable from the SSH server?)")

    def __exit__(self, *a):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try: self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired: self.proc.kill()
