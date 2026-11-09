"""Generates `server-fixes.sh`: a reviewable remediation script for the server findings.
PN-Ultra-Audit NEVER runs it. Each fix is a function; running the script with no argument only lists them.
Usage on the server (as root / with sudo, ideally with a second SSH session open):
    sudo bash server-fixes.sh list            # show available fixes
    sudo bash server-fixes.sh safe            # apply the low-risk ones
    sudo bash server-fixes.sh SRV-SSH-ROOT    # apply one fix by finding id
"""
import re

HEADER = r'''#!/usr/bin/env bash
# PN-Ultra-Audit - server remediation script (generated; REVIEW BEFORE RUNNING; never executed by the tool)
# Target: {label}   Provider: {provider}   Generated: {date}
#  * Every change makes a timestamped backup first and validates the config before reloading.
#  * Keep a SECOND SSH session open while changing SSH or firewall rules (lock-out protection).
#  * "safe" fixes are low-risk; "risky" fixes (SSH, firewall, kernel, services) must be requested by id.
set -euo pipefail
need_root() {{ [ "$(id -u)" -eq 0 ] || {{ echo "Run as root: sudo bash $0 $*"; exit 1; }}; }}
TS=$(date +%Y%m%d-%H%M%S)
backup() {{ [ -e "$1" ] && cp -a "$1" "$1.pnua-$TS" && echo "  backup: $1.pnua-$TS" || true; }}
say() {{ echo; echo "==> $*"; }}
pkg() {{ if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"; elif command -v dnf >/dev/null 2>&1; then dnf install -y "$@"; elif command -v yum >/dev/null 2>&1; then yum install -y "$@"; else echo "no supported package manager"; return 1; fi; }}
reload_ssh() {{ sshd -t && (systemctl reload sshd 2>/dev/null || systemctl reload ssh); }}
'''

SSH_DROPIN = "/etc/ssh/sshd_config.d/99-pnua-hardening.conf"


def _ssh(setting, why):
    return f'''  backup {SSH_DROPIN}
  mkdir -p /etc/ssh/sshd_config.d
  grep -q '^Include /etc/ssh/sshd_config.d' /etc/ssh/sshd_config 2>/dev/null || {{ backup /etc/ssh/sshd_config; sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config; }}
  sed -i '/^{setting.split()[0]} /d' {SSH_DROPIN} 2>/dev/null || true
  echo '{setting}' >> {SSH_DROPIN}
  reload_ssh && echo "  {why}"'''


# rule-id (or prefix ending with *) -> (risk, description, bash body or callable(finding)->body)
def _path_from(f):
    m = re.search(r":\s*(/[^\s(]+)", f.get("title", "")) or re.search(r"(/[^\s;(]+)", f.get("evidence", ""))
    return m.group(1) if m else "<path>"


FIXES = {
    "SRV-SSH-ROOT": ("risky", "Disable direct root login over SSH (make sure another sudo user can log in first)", _ssh("PermitRootLogin no", "root login disabled")),
    "SRV-SSH-PASSWORD": ("risky", "Disable SSH password login (only after confirming your key works)", _ssh("PasswordAuthentication no", "password login disabled")),
    "SRV-SSH-EMPTYPW": ("risky", "Forbid empty SSH passwords", _ssh("PermitEmptyPasswords no", "empty passwords forbidden")),
    "SRV-SSH-X11": ("safe", "Disable X11 forwarding", _ssh("X11Forwarding no", "X11 forwarding disabled")),
    "SRV-SSH-MAXTRIES": ("safe", "Limit SSH authentication attempts", _ssh("MaxAuthTries 3", "MaxAuthTries 3")),
    "SRV-SSH-TCP-FORWARD": ("risky", "Disable SSH TCP forwarding", _ssh("AllowTcpForwarding no", "TCP forwarding disabled")),
    "SRV-SSH-USERENV": ("safe", "Forbid PermitUserEnvironment", _ssh("PermitUserEnvironment no", "PermitUserEnvironment no")),
    "SRV-SSH-WEAK-CIPHERS": ("risky", "Restrict SSH ciphers to modern AEAD ones", _ssh("Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com", "modern ciphers only")),
    "SRV-SSH-WEAK-MACS": ("risky", "Restrict SSH MACs to SHA-2 ETM", _ssh("MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com", "modern MACs only")),
    "SRV-SSH-WEAK-KEX": ("risky", "Restrict SSH key exchange", _ssh("KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512", "modern KEX only")),
    "SRV-NO-FIREWALL": ("risky", "Enable ufw: deny incoming, allow SSH/HTTP/HTTPS (ALSO configure the provider firewall)", '''  command -v ufw >/dev/null 2>&1 || pkg ufw
  ufw default deny incoming; ufw default allow outgoing
  ufw allow OpenSSH 2>/dev/null || ufw allow 22/tcp
  ufw allow 80/tcp; ufw allow 443/tcp
  ufw --force enable && ufw status verbose'''),
    "SRV-NO-FAIL2BAN": ("safe", "Install and enable fail2ban (SSH jail)", '''  pkg fail2ban
  printf '[sshd]\\nenabled = true\\nmaxretry = 5\\nfindtime = 10m\\nbantime = 1h\\n' > /etc/fail2ban/jail.d/pnua-sshd.local
  systemctl enable --now fail2ban && fail2ban-client status sshd || true'''),
    "SRV-NO-AUTOUPDATE": ("safe", "Install unattended security upgrades", '''  pkg unattended-upgrades
  command -v dpkg-reconfigure >/dev/null 2>&1 && dpkg-reconfigure -f noninteractive -plow unattended-upgrades || true'''),
    "SRV-PENDING-SECURITY": ("risky", "Apply pending updates (services may restart; run in a maintenance window)", '''  if command -v apt-get >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade; else (dnf -y upgrade || yum -y update); fi'''),
    "SRV-REBOOT": ("risky", "Reboot to load the new kernel/libraries (schedule it!)", '''  echo "  Run when ready:  systemctl reboot"'''),
    "SRV-NGINX-TOKENS": ("safe", "nginx: hide version", '''  backup /etc/nginx/conf.d/pnua-security.conf
  grep -q server_tokens /etc/nginx/conf.d/pnua-security.conf 2>/dev/null || echo 'server_tokens off;' >> /etc/nginx/conf.d/pnua-security.conf
  nginx -t && systemctl reload nginx'''),
    "SRV-NGINX-TLS": ("risky", "nginx: TLS 1.2/1.3 only", '''  backup /etc/nginx/conf.d/pnua-tls.conf
  printf 'ssl_protocols TLSv1.2 TLSv1.3;\\nssl_prefer_server_ciphers off;\\n' > /etc/nginx/conf.d/pnua-tls.conf
  nginx -t && systemctl reload nginx   # if a server block overrides ssl_protocols, edit it there'''),
    "SRV-NGINX-NO-LIMITREQ": ("safe", "nginx: basic request rate limit zone (then add `limit_req zone=pnua burst=20;` to your locations)", '''  backup /etc/nginx/conf.d/pnua-limit.conf
  echo 'limit_req_zone $binary_remote_addr zone=pnua:10m rate=10r/s;' > /etc/nginx/conf.d/pnua-limit.conf
  nginx -t && systemctl reload nginx'''),
    "SRV-NGINX-AUTOINDEX": ("risky", "nginx: directory listing is enabled", '''  grep -rn 'autoindex on' /etc/nginx || true; echo "  Edit the listed files to 'autoindex off;' then: nginx -t && systemctl reload nginx"'''),
    "SRV-APACHE-TOKENS": ("safe", "Apache: hide version/signature, disable TRACE", '''  f=/etc/apache2/conf-available/pnua-security.conf; [ -d /etc/apache2 ] || f=/etc/httpd/conf.d/pnua-security.conf
  backup "$f"; printf 'ServerTokens Prod\\nServerSignature Off\\nTraceEnable Off\\n' > "$f"
  command -v a2enconf >/dev/null 2>&1 && a2enconf pnua-security || true
  (apachectl configtest && (systemctl reload apache2 2>/dev/null || systemctl reload httpd))'''),
    "SRV-APACHE-INDEXES": ("risky", "Apache: remove directory listing", '''  grep -rn 'Indexes' /etc/apache2 /etc/httpd 2>/dev/null || true; echo "  Replace 'Options Indexes' by 'Options -Indexes' in the listed files, then apachectl configtest && reload"'''),
    "SRV-APACHE-TLS": ("risky", "Apache: TLS 1.2/1.3 only", '''  f=/etc/apache2/conf-available/pnua-tls.conf; [ -d /etc/apache2 ] || f=/etc/httpd/conf.d/pnua-tls.conf
  backup "$f"; printf 'SSLProtocol -all +TLSv1.2 +TLSv1.3\\n' > "$f"; command -v a2enconf >/dev/null 2>&1 && a2enconf pnua-tls || true
  (apachectl configtest && (systemctl reload apache2 2>/dev/null || systemctl reload httpd))'''),
    "SRV-APACHE-HSTS": ("risky", "Apache: add HSTS (needs mod_headers; only if the whole site is HTTPS)", '''  command -v a2enmod >/dev/null 2>&1 && a2enmod headers || true
  f=/etc/apache2/conf-available/pnua-hsts.conf; [ -d /etc/apache2 ] || f=/etc/httpd/conf.d/pnua-hsts.conf
  printf 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"\\n' > "$f"; command -v a2enconf >/dev/null 2>&1 && a2enconf pnua-hsts || true
  apachectl configtest && (systemctl reload apache2 2>/dev/null || systemctl reload httpd)'''),
    "SRV-PHP-*": ("safe", "PHP: hide version and errors, forbid remote includes", '''  for ini in /etc/php/*/fpm/conf.d /etc/php.d; do [ -d "$ini" ] && printf 'expose_php=Off\\ndisplay_errors=Off\\nallow_url_include=Off\\n' > "$ini/99-pnua-hardening.ini"; done
  for s in $(systemctl list-units --type=service --no-legend 'php*-fpm*' 2>/dev/null | awk '{print $1}'); do systemctl reload "$s" || true; done'''),
    "SRV-REDIS-BIND": ("risky", "Redis: bind to loopback and require a password", '''  c=$(ls /etc/redis/redis.conf /etc/redis.conf 2>/dev/null | head -1); [ -n "$c" ] || { echo "redis.conf not found"; return 1; }
  backup "$c"; sed -i 's/^bind .*/bind 127.0.0.1 ::1/; s/^protected-mode .*/protected-mode yes/' "$c"
  grep -q '^requirepass' "$c" || echo "requirepass $(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 40)" >> "$c"
  echo "  >> the generated requirepass is in $c: update your apps' REDIS_URL"; systemctl restart redis-server 2>/dev/null || systemctl restart redis'''),
    "SRV-REDIS-NOAUTH": ("risky", "Redis: require a password (see SRV-REDIS-BIND)", '''  echo "  Apply SRV-REDIS-BIND (sets bind 127.0.0.1, protected-mode yes and a random requirepass)"'''),
    "SRV-MONGO-NOAUTH": ("risky", "MongoDB: enable authorization (create an admin user FIRST)", '''  echo "  1) mongosh: use admin; db.createUser({user:'admin',pwd:passwordPrompt(),roles:['root']})"
  echo "  2) add to /etc/mongod.conf:  security:\\n  authorization: enabled   then: systemctl restart mongod"'''),
    "SRV-MONGO-BIND": ("risky", "MongoDB: bind to loopback", '''  backup /etc/mongod.conf; sed -i 's/^\\( *bindIp:\\).*/\\1 127.0.0.1/; /bindIpAll/d' /etc/mongod.conf; systemctl restart mongod'''),
    "SRV-MYSQL-BIND": ("risky", "MySQL/MariaDB: bind to loopback", '''  for f in /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/mariadb.conf.d/50-server.cnf /etc/my.cnf; do [ -f "$f" ] && { backup "$f"; sed -i 's/^\\(bind[-_]address\\).*/\\1 = 127.0.0.1/' "$f"; }; done
  systemctl restart mysql 2>/dev/null || systemctl restart mariadb'''),
    "SRV-MEMCACHED-BIND": ("safe", "memcached: loopback only, no UDP", '''  backup /etc/memcached.conf; sed -i 's/^-l .*/-l 127.0.0.1/' /etc/memcached.conf; grep -q '^-U' /etc/memcached.conf || echo '-U 0' >> /etc/memcached.conf; systemctl restart memcached'''),
    "SRV-MEMCACHED-UDP": ("safe", "memcached: disable UDP", '''  grep -q '^-U' /etc/memcached.conf || echo '-U 0' >> /etc/memcached.conf; systemctl restart memcached'''),
    "SRV-RABBIT-GUEST": ("risky", "RabbitMQ: remove the default guest user (create an app user first)", '''  rabbitmqctl delete_user guest'''),
    "SRV-SYSCTL-WEAK": ("risky", "Apply a kernel hardening baseline (keep ip_forward as Docker/Kubernetes need it)", '''  backup /etc/sysctl.d/99-pnua-hardening.conf
  cat > /etc/sysctl.d/99-pnua-hardening.conf <<'EOF'
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
EOF
  sysctl --system >/dev/null && echo "  sysctl baseline applied"'''),
    "SRV-NO-PERSISTENT-LOGS": ("safe", "journald: keep logs across reboots", '''  mkdir -p /var/log/journal; backup /etc/systemd/journald.conf; sed -i 's/^#\\?Storage=.*/Storage=persistent/' /etc/systemd/journald.conf; systemctl restart systemd-journald'''),
    "SRV-NO-AUDITD": ("safe", "Install auditd", '''  pkg auditd; systemctl enable --now auditd'''),
    "SRV-NO-MAC": ("risky", "Enable AppArmor (Debian/Ubuntu)", '''  pkg apparmor apparmor-utils; systemctl enable --now apparmor; aa-status || true'''),
    "SRV-SSH-KEY-PERMS": ("safe", "Fix SSH key permissions", lambda f: f'''  chmod 600 {_path_from(f)}'''),
    "SRV-SSH-AKEYS-PERMS": ("safe", "Fix authorized_keys permissions", lambda f: f'''  chmod 600 {_path_from(f)}'''),
    "SRV-CRON-WORLD-WRITABLE": ("safe", "Remove world-write from cron files", '''  find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron -type f -perm -0002 -exec chmod o-w {} + -print'''),
    "SRV-SUID-UNUSUAL": ("risky", "Remove SUID bit from binaries in user/web/temp dirs (review the list first)", '''  find /home /tmp /var/tmp /var/www /srv /opt -xdev -perm -4000 -type f -print   # then: chmod u-s <file>'''),
    "SRV-WORLD-WRITABLE": ("risky", "Remove world-write from project files (check uploads/cache dirs separately)", '''  echo "  Review then run, per project dir:  find <dir> -xdev -type f -perm -0002 -exec chmod o-w {} +"'''),
    "SRV-ENV-*": ("risky", "Protect .env files", lambda f: f'''  p="{_path_from(f)}"; [ -e "$p" ] && chmod 600 "$p" && echo "  chmod 600 $p"; echo "  If it is inside the web root, MOVE it above the document root and deny dotfiles in the web server"'''),
    "SRV-GIT-DIR": ("risky", "Remove .git from the web root (keep it in the repo, not in the served folder)", lambda f: f'''  echo "  Deploy without .git (rsync --exclude .git / git archive) and delete: {_path_from(f)}  (after verifying it is not your only copy)"'''),
    "SRV-BACKUP-FILE": ("risky", "Move backup/dump files out of the project/web directories", lambda f: f'''  echo "  Move {_path_from(f)} to an encrypted off-host backup location and delete it from the server"'''),
    "SRV-UID0": ("risky", "Extra UID 0 accounts: lock them after review", '''  awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd | while read -r u; do echo "  review then: passwd -l $u"; done'''),
    "SRV-EMPTY-PW": ("risky", "Accounts with empty passwords: lock them", '''  awk -F: '($2==""){print $1}' /etc/shadow | while read -r u; do passwd -l "$u" && echo "  locked $u"; done'''),
    "SRV-DOCKER-UFW-BYPASS": ("risky", "Docker bypasses ufw: publish on 127.0.0.1 or filter DOCKER-USER", '''  echo "  In compose/run use  -p 127.0.0.1:HOST:CONTAINER  and expose via nginx; or add rules to the DOCKER-USER chain (iptables -I DOCKER-USER -i eth0 ! -s <allowed> -j DROP)"'''),
    "SRV-DOCKER-API-TCP": ("risky", "Docker API on TCP without TLS: remove it", '''  backup /etc/docker/daemon.json; echo "  Edit /etc/docker/daemon.json: remove the tcp:// entry from \\"hosts\\" (and the -H tcp:// flag from the systemd unit), then: systemctl restart docker"'''),
    "SRV-K8S-KUBECONFIG": ("safe", "Restrict kubeconfig permissions", '''  for f in /etc/kubernetes/admin.conf /etc/rancher/k3s/k3s.yaml /root/.kube/config /home/*/.kube/config; do [ -e "$f" ] && chmod 600 "$f" && echo "  chmod 600 $f"; done'''),
    "SRV-K8S-NO-NETPOL": ("risky", "Apply a default-deny NetworkPolicy per namespace (then allow required flows)", '''  echo "  kubectl apply -f - <<'EOF'\\napiVersion: networking.k8s.io/v1\\nkind: NetworkPolicy\\nmetadata: {name: default-deny, namespace: <ns>}\\nspec: {podSelector: {}, policyTypes: [Ingress, Egress]}\\nEOF"'''),
    "SRV-K8S-ADMIN-ANON": ("risky", "Delete cluster-admin bindings for anonymous/authenticated groups", '''  kubectl get clusterrolebindings -o json | python3 -c "import sys,json;[print(b['metadata']['name']) for b in json.load(sys.stdin)['items'] if b['roleRef']['name']=='cluster-admin' and any(s.get('name','').startswith('system:') and s['name'] in ('system:anonymous','system:unauthenticated','system:authenticated') for s in (b.get('subjects') or []))]"; echo "  then: kubectl delete clusterrolebinding <name>"'''),
    "SRV-CLOUD-IMDSV1": ("risky", "AWS: require IMDSv2 (run from a machine with the AWS CLI)", lambda f: f'''  echo "  {f.get('fix', '')}"'''),
    "SRV-NO-BACKUP-JOB": ("risky", "Install a backup tool and schedule it (example with restic)", '''  pkg restic
  echo "  Initialise a repo (restic -r <repo> init), export RESTIC_PASSWORD/credentials in /root/.restic-env, then add to /etc/cron.d/pnua-backup:"
  echo "  0 3 * * * root . /root/.restic-env && restic -r <repo> backup /var/www /var/backups && restic -r <repo> forget --keep-daily 7 --keep-weekly 4 --prune"'''),
}


def _match(rule):
    if rule in FIXES: return rule
    for k in FIXES:
        if k.endswith("*") and rule.startswith(k[:-1]): return k
    return None


def build(findings, label, provider, date):
    """-> script text, or None when no server finding has an automated/guided fix."""
    chosen, seen = [], set()
    order = ["critical", "high", "medium", "low", "info"]
    srv = [f for f in findings if str(f.get("rule", "")).startswith("SRV-") and f.get("status") in ("confirmed", "needs_validation")]
    srv.sort(key=lambda f: order.index(f["severity"]) if f.get("severity") in order else 5)
    for f in srv:
        key = _match(f["rule"])
        if not key: continue
        ident = f["rule"] if key.endswith("*") else key
        dedupe = key if (key.endswith("*") and not callable(FIXES[key][2])) else ident
        if dedupe in seen: continue
        seen.add(dedupe); chosen.append((ident, key, f))
    if not chosen: return None
    out = [HEADER.format(label=label, provider=provider or "unknown", date=date)]
    names = []
    for ident, key, f in chosen:
        risk, desc, body = FIXES[key]
        fn = "fix_" + re.sub(r"\W", "_", ident)
        code = body(f) if callable(body) else body
        out.append(f"# [{ident}] ({f.get('severity') or 'review'}, {risk}) {f.get('title', '')[:110]}\n{fn}() {{\n  say \"{ident}: {desc}\"\n{code}\n}}\n")
        names.append((ident, fn, risk, desc))
    out.append("list() {\n  echo 'Available fixes (S = safe, R = risky/needs review):'")
    for ident, fn, risk, desc in names: out.append(f"  echo '  [{'S' if risk == 'safe' else 'R'}] {ident:<28} {desc.replace(chr(39), '')[:90]}'")
    out.append("}\n")
    safe = [fn for _, fn, risk, _ in names if risk == "safe"]
    out.append("run_safe() {\n" + "".join(f"  {fn}\n" for fn in safe) + "  true\n}\n")
    out.append("run_one() {\n  case \"$1\" in\n" + "".join(f"    {i}) {fn};;\n" for i, fn, _, _ in names) + "    *) echo \"unknown fix: $1\"; list; exit 2;;\n  esac\n}\n")
    out.append('case "${1:-list}" in\n  list|"") list;;\n  safe) need_root "$@"; run_safe;;\n  *) need_root "$@"; for id in "$@"; do run_one "$id"; done;;\nesac\n')
    return "\n".join(out)
