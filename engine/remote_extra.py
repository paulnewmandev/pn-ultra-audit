"""Server (VPS) audit, part 2: Apache, Redis, Kafka/ZooKeeper, Kubernetes (k3s/kubeadm/microk8s), containers, data stores
(MySQL/PostgreSQL/MongoDB/Elasticsearch/memcached/RabbitMQ), mail, kernel/OS hardening, SSH keys, cron and backups.
Pure analysis of the read-only data collected by the remote script - nothing is changed on the server."""
import re

from .kb import KB

LOOP = ("127.0.0.1", "localhost", "::1", "[::1]", "127.0.0.0/8")


def _f(rule, title, family, typ, sev, cat, label, ev, fix=None, effort=15, cwe=(), owasp=(), status="confirmed", priority=None):
    kb = KB[family]
    return dict(rule=rule, title=title, family=family, type=typ, severity=sev if status == "confirmed" else None, category=cat, file=label, line=1, evidence=ev[:400],
                impact=kb["impact"], fix=fix or "; ".join(kb["steps"][:2]), effort_min=effort, cwe=list(cwe), owasp=list(owasp), status=status, priority=priority, why=None)


def _kv(lines, prefix):
    return [x[len(prefix):].strip() for x in lines if x.startswith(prefix)]


def _val(lines, key):
    for x in lines:
        m = re.match(r"\s*" + re.escape(key) + r"\s*[=:\s]\s*(.+)$", x, re.I)
        if m: return m.group(1).strip().strip("'\"")
    return None


def _public_bind(v):
    return bool(v) and any(t.strip() not in LOOP and t.strip() not in ("", "-") for t in re.split(r"[\s,]+", v.replace("-::", "").strip()) if t.strip())


def analyze_extra(sec, label, exposed_ports=(), ufw_active=False):
    """-> (findings, info). `exposed_ports`: ports listening on non-loopback addresses (from the main analysis)."""
    F, stack = [], []
    S = lambda k: [x.rstrip() for x in sec.get(k, []) if x.strip()]
    exp = {int(p) for p in exposed_ports if str(p).isdigit()}

    # ------------------------------------------------------------------ Apache
    ap = S("apache2")
    if ap:
        stack.append("apache")
        txt = "\n".join(ap)
        tok = re.findall(r"ServerTokens\s+(\w+)", txt, re.I)
        if tok and tok[-1].lower() not in ("prod", "productonly", "min", "minimal"):
            F.append(_f("SRV-APACHE-TOKENS", f"Apache ServerTokens is `{tok[-1]}` (version disclosure)", "srv-web", "code_smell", "low", "misconfiguration", label, f"ServerTokens {tok[-1]}", "Set `ServerTokens Prod` and `ServerSignature Off` in conf-enabled/security.conf", 5, cwe=["CWE-200"], owasp=["A05:2021"]))
        if re.search(r"ServerSignature\s+On", txt, re.I): F.append(_f("SRV-APACHE-SIGNATURE", "Apache ServerSignature is On", "srv-web", "code_smell", "low", "misconfiguration", label, "ServerSignature On", "Set `ServerSignature Off`", 5, cwe=["CWE-200"], owasp=["A05:2021"]))
        if not re.search(r"TraceEnable\s+Off", txt, re.I): F.append(_f("SRV-APACHE-TRACE", "Apache TRACE method is not disabled", "srv-web", "code_smell", "low", "misconfiguration", label, "no `TraceEnable Off` found", "Add `TraceEnable Off`", 5, cwe=["CWE-16"], owasp=["A05:2021"]))
        if any(re.search(r"Options\s+[^#\n]*(?<![-\w])\+?Indexes", x, re.I) and not re.search(r"-Indexes", x, re.I) for x in ap):
            F.append(_f("SRV-APACHE-INDEXES", "Apache directory listing enabled (Options Indexes)", "srv-web", "vulnerability", "medium", "misconfiguration", label, next(x for x in ap if "Indexes" in x), "Use `Options -Indexes`", 5, cwe=["CWE-548"], owasp=["A05:2021"]))
        if re.search(r"SSLProtocol[^\n]*(\+?TLSv1(\s|$)|TLSv1\.1|SSLv3|\ball\b(?![^\n]*-TLSv1))", txt, re.I) and not re.search(r"SSLProtocol\s+(-all\s+)?\+?TLSv1\.[23]", txt, re.I):
            F.append(_f("SRV-APACHE-TLS", "Apache allows TLS 1.0/1.1 or SSLv3", "srv-web", "vulnerability", "medium", "crypto", label, next((x for x in ap if "SSLProtocol" in x), "SSLProtocol"), "Use `SSLProtocol -all +TLSv1.2 +TLSv1.3`", 10, cwe=["CWE-327"], owasp=["A02:2021"]))
        if re.search(r"<Location\s+/server-(status|info)", txt, re.I) or re.search(r"LoadModule\s+(status|info)_module", txt, re.I):
            F.append(_f("SRV-APACHE-STATUS", "Apache server-status/server-info may be exposed", "srv-web", "security_hotspot", None, "exposure", label, "mod_status/mod_info loaded or <Location /server-status>", "Restrict with `Require local` or disable the modules (`a2dismod status info`)", 10, status="needs_validation", priority="low", cwe=["CWE-200"], owasp=["A05:2021"]))
        if not re.search(r"security2|evasive", txt, re.I): F.append(_f("SRV-APACHE-NO-WAF", "No mod_security / mod_evasive loaded (no WAF or request-rate control)", "srv-web", "code_smell", "info", "hardening", label, "no security2/evasive module", "Enable mod_security with the OWASP Core Rule Set and/or mod_evasive, or put a WAF/CDN in front", 60))
        if re.search(r"SSLProtocol|SSLCipherSuite", txt, re.I) and not re.search(r"Strict-Transport-Security", txt, re.I):
            F.append(_f("SRV-APACHE-HSTS", "HTTPS site without Strict-Transport-Security header", "srv-web", "code_smell", "low", "crypto", label, "no HSTS header", 'Add `Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"`', 5, cwe=["CWE-319"], owasp=["A05:2021"]))

    # ------------------------------------------------------------------ Redis
    rd = S("redis")
    if rd:
        stack.append("redis")
        binds = [x.split(None, 1)[1] for x in rd if re.match(r"\s*bind\s", x, re.I)]
        prot = _val(rd, "protected-mode"); req = [x for x in rd if re.match(r"\s*(requirepass|user)\s", x, re.I)]
        pong = any(x.strip() == "ping=PONG" for x in rd)
        pub = any(_public_bind(b) or re.search(r"(^|\s)(0\.0\.0\.0|\*|::)(\s|$)", b) for b in binds)
        reach = 6379 in exp
        if pub:
            F.append(_f("SRV-REDIS-BIND", "Redis is configured to listen on non-loopback interfaces", "srv-data", "vulnerability", "critical" if (reach and not req) else "high", "exposure", label, "bind " + "; ".join(binds), "Set `bind 127.0.0.1 ::1` and reach Redis through an SSH tunnel/VPN/private network", 10, cwe=["CWE-284"], owasp=["A05:2021"]))
        if pong or (not req and (pub or (prot or "").lower() == "no")):
            F.append(_f("SRV-REDIS-NOAUTH", "Redis has no authentication (answers PING without a password)" if pong else "Redis has no requirepass/ACL and protection is off", "srv-data", "vulnerability", "critical" if reach else "high", "authn", label, "ping=PONG without AUTH" if pong else "no requirepass; protected-mode " + (prot or "unset"), "Set a long random `requirepass` (or ACL users), keep `protected-mode yes` and bind to loopback", 10, cwe=["CWE-306"], owasp=["A07:2021"]))

    # ------------------------------------------------------------------ Kafka / ZooKeeper
    kf = S("kafka")
    if kf:
        stack.append("kafka")
        kc = [x for x in kf if not x.startswith(("conf=", "zoo=", "jmx="))]
        lst = _val(kc, "listeners") or ""; adv = _val(kc, "advertised.listeners") or ""
        for m in re.finditer(r"PLAINTEXT://([^,\s]*)", lst + "," + adv):
            host = m.group(1).rsplit(":", 1)[0]
            if host in ("", "0.0.0.0") or (host not in LOOP and not host.startswith(("10.", "192.168.", "172."))):
                F.append(_f("SRV-KAFKA-PLAINTEXT", "Kafka broker exposes an unauthenticated PLAINTEXT listener beyond loopback", "srv-data", "vulnerability", "high", "authn", label, f"listeners={lst or adv}", "Use SASL_SSL/SSL listeners, bind to a private interface and firewall 9092", 45, cwe=["CWE-319", "CWE-306"], owasp=["A02:2021"])); break
        if kc and not _val(kc, "authorizer.class.name") and not _val(kc, "process.roles"):
            F.append(_f("SRV-KAFKA-NO-ACL", "Kafka has no authorizer configured (any client can read/write every topic)", "srv-data", "vulnerability", "medium", "authz", label, "authorizer.class.name not set", "Set `authorizer.class.name` (StandardAuthorizer/AclAuthorizer), enable SASL and create ACLs per service", 60, cwe=["CWE-862"], owasp=["A01:2021"]))
        if (_val(kc, "allow.everyone.if.no.acl.found") or "").lower() == "true":
            F.append(_f("SRV-KAFKA-ALLOW-ALL", "Kafka `allow.everyone.if.no.acl.found=true` grants access when no ACL exists", "srv-data", "vulnerability", "high", "authz", label, "allow.everyone.if.no.acl.found=true", "Set it to false and define explicit ACLs", 15, cwe=["CWE-284"], owasp=["A01:2021"]))
        if (_val(kc, "auto.create.topics.enable") or "").lower() == "true": F.append(_f("SRV-KAFKA-AUTOTOPICS", "Kafka auto-creates topics on first use", "srv-data", "code_smell", "low", "misconfiguration", label, "auto.create.topics.enable=true", "Disable it and create topics explicitly", 5))
        zoo = [x for x in kf if not x.startswith(("conf=", "jmx=")) and re.match(r"\s*(clientPort|clientPortAddress|authProvider|admin\.enableServer|4lw)", x)]
        if any(x.startswith("zoo=") for x in kf):
            addr = _val(zoo, "clientPortAddress")
            if (not addr or addr not in LOOP) and not _val(zoo, "authProvider.1") and not any("authProvider" in x for x in zoo):
                F.append(_f("SRV-ZK-EXPOSED", "ZooKeeper client port is open on all interfaces without authentication", "srv-data", "vulnerability", "high" if 2181 in exp else "medium", "exposure", label, "; ".join(zoo)[:200], "Set `clientPortAddress=127.0.0.1`/private IP, enable SASL authProvider and firewall 2181", 30, cwe=["CWE-306"], owasp=["A05:2021"]))
            if any("4lw.commands.whitelist" in x and "*" in x for x in zoo): F.append(_f("SRV-ZK-4LW", "ZooKeeper whitelists all four-letter-word commands", "srv-data", "code_smell", "medium", "exposure", label, "4lw.commands.whitelist=*", "Whitelist only `ruok,stat` or none", 5, cwe=["CWE-200"]))
        jm = _kv(kf, "jmx=")
        if any("authenticate=false" in x for x in jm): F.append(_f("SRV-KAFKA-JMX-NOAUTH", "Kafka JMX remote is enabled without authentication (remote code execution)", "srv-data", "vulnerability", "critical", "authn", label, "; ".join(jm)[:200], "Enable JMX authentication+SSL or bind JMX to localhost", 30, cwe=["CWE-306", "CWE-94"], owasp=["A07:2021"]))
        elif any("ssl=false" in x for x in jm): F.append(_f("SRV-KAFKA-JMX-NOSSL", "Kafka JMX remote runs without SSL", "srv-data", "vulnerability", "medium", "crypto", label, "; ".join(jm)[:200], "Enable `com.sun.management.jmxremote.ssl=true`", 20, cwe=["CWE-319"]))

    # ------------------------------------------------------------------ Kubernetes
    k8 = S("k8s")
    bins = _kv(k8, "bin=")
    kube = _kv(k8, "kubeconfig=")
    if k8 and (bins or kube):
        stack.append("kubernetes")
        for x in kube:
            m = re.match(r"(\d+)\s+(\S+)", x)
            if m and len(m.group(1)) >= 3 and (m.group(1)[-1] != "0" or m.group(1)[-2] not in "04"):
                F.append(_f("SRV-K8S-KUBECONFIG", f"kubeconfig {m.group(2)} is readable by other users (mode {m.group(1)})", "srv-k8s", "vulnerability", "high" if m.group(1)[-1] != "0" else "medium", "authz", label, f"{m.group(2)} mode {m.group(1)}", f"chmod 600 {m.group(2)}", 5, cwe=["CWE-732"], owasp=["A01:2021"]))
        kl = _kv(k8, "kubelet=")
        txt = "\n".join(kl)
        if re.search(r"anonymous:\s*\n?\s*enabled:\s*true", txt.replace("kubelet=", "")) or re.search(r"anonymous:\s*enabled:\s*true", " ".join(kl)): F.append(_f("SRV-K8S-KUBELET-ANON", "Kubelet allows anonymous requests", "srv-k8s", "vulnerability", "critical", "authn", label, "kubelet authentication.anonymous.enabled: true", "Set authentication.anonymous.enabled=false and authorization.mode=Webhook", 15, cwe=["CWE-306"], owasp=["A07:2021"]))
        if re.search(r"mode:\s*AlwaysAllow", txt): F.append(_f("SRV-K8S-KUBELET-ALLOWALL", "Kubelet authorization mode is AlwaysAllow", "srv-k8s", "vulnerability", "critical", "authz", label, "authorization.mode: AlwaysAllow", "Set authorization.mode=Webhook", 15, cwe=["CWE-862"], owasp=["A01:2021"]))
        if re.search(r"readOnlyPort:\s*[1-9]", txt): F.append(_f("SRV-K8S-KUBELET-RO", "Kubelet read-only port is enabled", "srv-k8s", "vulnerability", "medium", "exposure", label, "readOnlyPort != 0", "Set readOnlyPort: 0", 5, cwe=["CWE-200"]))
        api = _kv(k8, "kube-apiserver=")
        if any(x.startswith("--anonymous-auth=true") for x in api): F.append(_f("SRV-K8S-API-ANON", "API server allows anonymous authentication", "srv-k8s", "vulnerability", "high", "authn", label, "--anonymous-auth=true", "Set --anonymous-auth=false", 10, cwe=["CWE-306"], owasp=["A07:2021"]))
        if any(re.match(r"--insecure-(port|bind-address)=(?!0$|$)", x) for x in api): F.append(_f("SRV-K8S-API-INSECURE", "API server insecure port/address is enabled", "srv-k8s", "vulnerability", "critical", "exposure", label, "; ".join(x for x in api if "insecure" in x), "Remove --insecure-port/--insecure-bind-address", 10, cwe=["CWE-306"], owasp=["A05:2021"]))
        if any("AlwaysAllow" in x for x in api): F.append(_f("SRV-K8S-API-ALLOWALL", "API server authorization-mode includes AlwaysAllow", "srv-k8s", "vulnerability", "critical", "authz", label, "--authorization-mode includes AlwaysAllow", "Use --authorization-mode=Node,RBAC", 10, cwe=["CWE-862"], owasp=["A01:2021"]))
        if api and not any(x.startswith("--audit-log-path") for x in api): F.append(_f("SRV-K8S-NO-AUDIT", "API server audit logging is not configured", "srv-k8s", "code_smell", "low", "logging", label, "no --audit-log-path", "Enable audit logging with a policy file", 30, cwe=["CWE-778"], owasp=["A09:2021"]))
        et = _kv(k8, "etcd=")
        if et and not any(x.startswith("--client-cert-auth=true") for x in et): F.append(_f("SRV-K8S-ETCD-NOAUTH", "etcd does not require client certificates", "srv-k8s", "vulnerability", "high", "authn", label, "--client-cert-auth not true", "Set --client-cert-auth=true and --peer-client-cert-auth=true", 20, cwe=["CWE-306"], owasp=["A07:2021"]))
        pods = [x.split("|") for x in k8 if x.startswith("P|")]
        def flag(p, k): return any(f == f"{k}=1" for f in p)
        names = lambda sel: ", ".join(p[1] for p in sel[:5]) + (f" (+{len(sel) - 5})" if len(sel) > 5 else "")
        pr = [p for p in pods if flag(p, "priv")]
        if pr: F.append(_f("SRV-K8S-PRIVILEGED", f"{len(pr)} privileged pod(s)", "srv-k8s", "vulnerability", "high", "misconfiguration", label, names(pr), "Remove `privileged: true`; grant only the specific capability needed", 30, cwe=["CWE-250"], owasp=["A05:2021"]))
        hn = [p for p in pods if flag(p, "hostnet") or flag(p, "hostpid")]
        if hn: F.append(_f("SRV-K8S-HOSTNS", f"{len(hn)} pod(s) share the host network/PID namespace", "srv-k8s", "vulnerability", "high", "misconfiguration", label, names(hn), "Remove hostNetwork/hostPID unless it is a node agent", 30, cwe=["CWE-653"], owasp=["A05:2021"]))
        hp = [p for p in pods if any(h and re.match(r"^(/|/etc|/var/run|/var/lib/(kubelet|docker)|/proc|/root|/sys|/run)(/|$)", h) for h in next((f[len("hostpath="):].split(",") for f in p if f.startswith("hostpath=")), []))]
        if hp: F.append(_f("SRV-K8S-HOSTPATH", f"{len(hp)} pod(s) mount sensitive host paths", "srv-k8s", "vulnerability", "high", "misconfiguration", label, names(hp), "Use PVCs/emptyDir; never mount /, /etc, docker.sock or kubelet dirs", 30, cwe=["CWE-668"], owasp=["A05:2021"]))
        ro = [p for p in pods if flag(p, "root")]
        if ro: F.append(_f("SRV-K8S-ROOT", f"{len(ro)} pod(s) may run as root (no runAsNonRoot/runAsUser)", "srv-k8s", "code_smell", "medium", "misconfiguration", label, names(ro), "Set securityContext.runAsNonRoot=true and readOnlyRootFilesystem=true", 30, cwe=["CWE-250"], owasp=["A05:2021"]))
        lt = [p for p in pods if flag(p, "latest")]
        if lt: F.append(_f("SRV-K8S-LATEST", f"{len(lt)} pod(s) use unpinned/`latest` image tags", "srv-k8s", "code_smell", "low", "supply-chain", label, names(lt), "Pin images by version or digest", 15, cwe=["CWE-1104"], owasp=["A06:2021"]))
        nl = [p for p in pods if flag(p, "nolimits")]
        if nl: F.append(_f("SRV-K8S-NO-LIMITS", f"{len(nl)} pod(s) without resource limits (noisy-neighbour/DoS risk)", "srv-k8s", "code_smell", "low", "reliability", label, names(nl), "Set requests and limits for CPU and memory", 20, cwe=["CWE-770"], owasp=["A05:2021"]))
        if pods and any(x.startswith("netpol=") and x.split("=")[1].strip() == "0" for x in k8): F.append(_f("SRV-K8S-NO-NETPOL", "No NetworkPolicy: every pod can talk to every other pod", "srv-k8s", "code_smell", "medium", "network", label, "networkpolicy count = 0", "Add default-deny NetworkPolicies and allow only required flows", 60, cwe=["CWE-923"], owasp=["A05:2021"]))
        crb = [x.split("|") for x in k8 if x.startswith("CRB|")]
        bad = [c for c in crb if re.search(r"(system:anonymous|system:unauthenticated|system:authenticated)$", c[2])]
        if bad: F.append(_f("SRV-K8S-ADMIN-ANON", "cluster-admin is bound to anonymous/all authenticated users", "srv-k8s", "vulnerability", "critical", "authz", label, "; ".join(f"{c[1]}->{c[2]}" for c in bad)[:300], "Delete those ClusterRoleBindings immediately", 10, cwe=["CWE-269"], owasp=["A01:2021"]))
        sa = [c for c in crb if c[2].startswith("ServiceAccount/") and "kube-system" not in c[1] and not c[1].startswith(("system:", "cluster-admin"))]
        if sa: F.append(_f("SRV-K8S-ADMIN-SA", f"{len(sa)} workload service account(s) hold cluster-admin", "srv-k8s", "vulnerability", "high", "authz", label, "; ".join(f"{c[2]}" for c in sa[:5]), "Replace cluster-admin with namespaced least-privilege Roles", 30, cwe=["CWE-269"], owasp=["A01:2021"]))
        svc = [x.split("|") for x in k8 if x.startswith("SVC|")]
        if svc: F.append(_f("SRV-K8S-EXPOSED-SVC", f"{len(svc)} service(s) of type NodePort/LoadBalancer", "srv-k8s", "security_hotspot", None, "exposure", label, "; ".join(f"{s[1]} ({s[2]})" for s in svc[:6]), "Confirm each is meant to be public; prefer ClusterIP behind one ingress", 15, status="needs_validation", priority="medium", cwe=["CWE-668"], owasp=["A05:2021"]))

    # ------------------------------------------------------------------ Containers
    dx = S("dockerx")
    dockers = [x.split("|") for x in dx if x.startswith("X|")]
    if dockers or any(x.startswith("dinfo=") for x in dx):
        stack.append("docker")
        nm = lambda sel: ", ".join(d[1].lstrip("/") for d in sel[:5]) + (f" (+{len(sel) - 5})" if len(sel) > 5 else "")
        fld = lambda d, k: next((f[len(k) + 1:] for f in d if f.startswith(k + "=")), "")
        hn = [d for d in dockers if fld(d, "net") == "host"]
        if hn: F.append(_f("SRV-CONTAINER-HOSTNET", f"{len(hn)} container(s) use host networking", "srv-docker", "vulnerability", "high", "misconfiguration", label, nm(hn), "Use bridge networks and publish only needed ports on 127.0.0.1", 20, cwe=["CWE-653"], owasp=["A05:2021"]))
        hp = [d for d in dockers if fld(d, "pid") == "host"]
        if hp: F.append(_f("SRV-CONTAINER-HOSTPID", f"{len(hp)} container(s) share the host PID namespace", "srv-docker", "vulnerability", "high", "misconfiguration", label, nm(hp), "Remove `--pid=host`", 10, cwe=["CWE-653"], owasp=["A05:2021"]))
        cp = [d for d in dockers if re.search(r"SYS_ADMIN|ALL|NET_ADMIN|SYS_PTRACE|DAC_READ_SEARCH", fld(d, "caps"))]
        if cp: F.append(_f("SRV-CONTAINER-CAPS", f"{len(cp)} container(s) with dangerous added capabilities", "srv-docker", "vulnerability", "high", "misconfiguration", label, "; ".join(f"{d[1].lstrip('/')}: {fld(d, 'caps')}" for d in cp[:4]), "Drop all capabilities and add only what is required", 20, cwe=["CWE-250"], owasp=["A05:2021"]))
        ms = [d for d in dockers if re.search(r"(^|,)(/var/run/docker\.sock|/run/docker\.sock|/|/etc|/root|/var/lib/docker|/proc|/sys):", fld(d, "mounts"))]
        if ms: F.append(_f("SRV-CONTAINER-SENSITIVE-MOUNT", f"{len(ms)} container(s) mount the Docker socket or sensitive host paths", "srv-docker", "vulnerability", "high", "misconfiguration", label, nm(ms), "Remove the mount; a container with docker.sock is root on the host", 30, cwe=["CWE-668"], owasp=["A05:2021"]))
        un = [d for d in dockers if re.search(r"unconfined", fld(d, "secopt"))]
        if un: F.append(_f("SRV-CONTAINER-UNCONFINED", f"{len(un)} container(s) run with seccomp/apparmor unconfined", "srv-docker", "vulnerability", "high", "misconfiguration", label, nm(un), "Remove `seccomp=unconfined` / `apparmor=unconfined`", 15, cwe=["CWE-693"], owasp=["A05:2021"]))
        ru = [d for d in dockers if not fld(d, "user") or fld(d, "user") in ("0", "root")]
        if ru: F.append(_f("SRV-CONTAINER-ROOT", f"{len(ru)} container(s) run as root inside the container", "srv-docker", "code_smell", "medium", "misconfiguration", label, nm(ru), "Add `USER app` to the image or `user:` in compose; add `--read-only`", 30, cwe=["CWE-250"], owasp=["A05:2021"]))
        nmm = [d for d in dockers if fld(d, "mem") in ("0", "")]
        if nmm: F.append(_f("SRV-CONTAINER-NO-LIMITS", f"{len(nmm)} container(s) without a memory limit (OOM can take the whole VPS down)", "srv-docker", "code_smell", "low", "reliability", label, nm(nmm), "Set `mem_limit`/`--memory` and CPU limits", 15, cwe=["CWE-770"], owasp=["A05:2021"]))
        dm = " ".join(_kv(dx, "daemon="))
        if re.search(r'"hosts":\[[^\]]*tcp://', dm) and not re.search(r'"tlsverify":true', dm): F.append(_f("SRV-DOCKER-API-TCP", "Docker daemon listens on TCP without TLS verification", "srv-docker", "vulnerability", "critical", "exposure", label, "daemon.json hosts includes tcp:// and tlsverify is not true", "Remove tcp:// or enable `tlsverify` with client certificates; never expose 2375", 20, cwe=["CWE-306"], owasp=["A05:2021"]))
        if re.search(r'"insecure-registries"', dm): F.append(_f("SRV-DOCKER-INSECURE-REG", "Docker is configured with insecure registries", "srv-docker", "vulnerability", "medium", "supply-chain", label, "insecure-registries in daemon.json", "Use TLS registries", 15, cwe=["CWE-319"], owasp=["A02:2021"]))
        di = next(iter(_kv(dx, "dinfo=")), "")
        vm = re.match(r"(\d+)\.(\d+)", di)
        if vm and (int(vm.group(1)), int(vm.group(2))) < (20, 10): F.append(_f("SRV-DOCKER-OLD", f"Docker engine {di.split('|')[0]} is outdated", "srv-patch", "vulnerability", "medium", "patching", label, di[:100], "Upgrade Docker Engine to a supported release", 30, cwe=["CWE-1104"], owasp=["A06:2021"]))
        grp = next(iter(_kv(dx, "dgroup=")), "")
        if grp: F.append(_f("SRV-DOCKER-GROUP", f"Users in the `docker` group have root-equivalent access: {grp}", "srv-docker", "security_hotspot", None, "authz", label, f"docker group: {grp}", "Keep the group minimal (or use rootless Docker)", 10, status="needs_validation", priority="low", cwe=["CWE-269"], owasp=["A01:2021"]))
        ufw_on = any("Status: active" in x for x in sec.get("firewall", []))
        pub = [m for m in re.findall(r"0\.0\.0\.0:(\d+)->", " ".join(x for x in sec.get("docker", []) if x.startswith("C|")))]
        if ufw_on and pub: F.append(_f("SRV-DOCKER-UFW-BYPASS", f"Docker-published ports bypass ufw: {', '.join(sorted(set(pub))[:8])}", "srv-docker", "vulnerability", "medium", "exposure", label, "ufw is active but containers publish on 0.0.0.0 (Docker edits iptables directly)", "Publish on 127.0.0.1 (`-p 127.0.0.1:8080:80`), put them behind a reverse proxy, or add rules to the DOCKER-USER chain", 25, cwe=["CWE-284"], owasp=["A05:2021"]))
    if any(x.startswith("podman=") for x in dx): stack.append("podman")

    # ------------------------------------------------------------------ Data stores
    db = S("dbconf")
    my = _kv(db, "mysql=")
    if my:
        stack.append("mysql/mariadb")
        t = "\n".join(my)
        if re.search(r"skip[-_]grant[-_]tables", t, re.I): F.append(_f("SRV-MYSQL-NOGRANT", "MySQL runs with skip-grant-tables (no authentication)", "srv-data", "vulnerability", "critical", "authn", label, "skip-grant-tables", "Remove it, restart and reset the root password", 15, cwe=["CWE-306"], owasp=["A07:2021"]))
        b = _val(my, "bind-address") or _val(my, "bind_address")
        if b and (b in ("0.0.0.0", "*", "::") or _public_bind(b)): F.append(_f("SRV-MYSQL-BIND", f"MySQL listens on {b}", "srv-data", "vulnerability", "high" if 3306 in exp else "medium", "exposure", label, f"bind-address = {b}", "Bind to 127.0.0.1/private IP; use SSH tunnel or VPN", 10, cwe=["CWE-284"], owasp=["A05:2021"]))
        if re.search(r"local[-_]infile\s*=\s*(1|on|true)", t, re.I): F.append(_f("SRV-MYSQL-LOCALINFILE", "MySQL local_infile is enabled", "srv-data", "vulnerability", "medium", "misconfiguration", label, "local_infile=1", "Set `local_infile=0`", 5, cwe=["CWE-73"], owasp=["A05:2021"]))
    pg, hba = _kv(db, "pgconf="), _kv(db, "pghba=")
    if pg or hba:
        stack.append("postgresql")
        la = _val(pg, "listen_addresses")
        if la and (la.strip("'\" ") == "*" or _public_bind(la)): F.append(_f("SRV-PG-LISTEN", f"PostgreSQL listen_addresses = {la}", "srv-data", "vulnerability", "high" if 5432 in exp else "medium", "exposure", label, f"listen_addresses = {la}", "Use `localhost`/private IP and restrict pg_hba.conf", 10, cwe=["CWE-284"], owasp=["A05:2021"]))
        for r in hba:
            f2 = r.split()
            if len(f2) >= 5 and f2[0].startswith("host") and f2[-1].lower() == "trust": F.append(_f("SRV-PG-TRUST", "pg_hba.conf allows `trust` (passwordless) network access", "srv-data", "vulnerability", "critical", "authn", label, r[:200], "Replace `trust` with `scram-sha-256`", 10, cwe=["CWE-306"], owasp=["A07:2021"])); break
        for r in hba:
            if re.search(r"\s(0\.0\.0\.0/0|::/0)\s", r + " "): F.append(_f("SRV-PG-WORLD", "pg_hba.conf accepts connections from any address", "srv-data", "vulnerability", "high", "exposure", label, r[:200], "Restrict to specific hosts/CIDRs", 10, cwe=["CWE-284"], owasp=["A05:2021"])); break
    mg = _kv(db, "mongo=")
    if mg:
        stack.append("mongodb")
        t = "\n".join(mg); auth = re.search(r"authorization\s*:\s*enabled", t, re.I)
        bip = _val(mg, "bindIp"); allip = re.search(r"bindIpAll\s*:\s*true", t, re.I)
        pubm = bool(allip) or (bip and (_public_bind(bip)))
        if not auth: F.append(_f("SRV-MONGO-NOAUTH", "MongoDB access control is disabled", "srv-data", "vulnerability", "critical" if (pubm or 27017 in exp) else "high", "authn", label, "security.authorization is not enabled", "Set `security: authorization: enabled` and create users", 20, cwe=["CWE-306"], owasp=["A07:2021"]))
        if pubm: F.append(_f("SRV-MONGO-BIND", f"MongoDB listens on non-loopback interfaces ({bip or 'bindIpAll'})", "srv-data", "vulnerability", "high", "exposure", label, f"bindIp: {bip or 'bindIpAll: true'}", "Bind to 127.0.0.1 or a private IP", 10, cwe=["CWE-284"], owasp=["A05:2021"]))
    es = _kv(db, "elastic=")
    if es:
        stack.append("elasticsearch")
        t = "\n".join(es); nh = _val(es, "network.host"); sec_on = re.search(r"xpack\.security\.enabled\s*:\s*true", t, re.I)
        if not sec_on and ((nh and _public_bind(nh)) or 9200 in exp): F.append(_f("SRV-ES-NOAUTH", "Elasticsearch is reachable beyond loopback without security enabled", "srv-data", "vulnerability", "critical", "authn", label, f"network.host: {nh or '?'}; xpack.security.enabled not true", "Enable `xpack.security.enabled: true` + TLS, bind to a private interface", 30, cwe=["CWE-306"], owasp=["A07:2021"]))
    mc = _kv(db, "memcached=")
    if mc:
        stack.append("memcached")
        t = " ".join(mc)
        if not re.search(r"-l\s+(127\.0\.0\.1|localhost|::1)", t): F.append(_f("SRV-MEMCACHED-BIND", "memcached is not bound to loopback", "srv-data", "vulnerability", "high", "exposure", label, t[:120], "Use `-l 127.0.0.1` and disable UDP (`-U 0`)", 10, cwe=["CWE-284"], owasp=["A05:2021"]))
        if not re.search(r"-U\s+0", t): F.append(_f("SRV-MEMCACHED-UDP", "memcached UDP is enabled (amplification DDoS)", "srv-data", "vulnerability", "medium", "dos", label, t[:120], "Add `-U 0`", 5, cwe=["CWE-406"], owasp=["A05:2021"]))
    if "guest" in _kv(db, "rabbit_user="): F.append(_f("SRV-RABBIT-GUEST", "RabbitMQ default `guest` user exists", "srv-data", "vulnerability", "medium", "authn", label, "user guest", "Delete it (`rabbitmqctl delete_user guest`) and create per-app users", 5, cwe=["CWE-1392"], owasp=["A07:2021"]))
    # mail
    pf = S("mailx")
    if pf:
        stack.append("postfix")
        if any(re.search(r"mynetworks\s*=.*(0\.0\.0\.0/0|::/0)", x) for x in pf): F.append(_f("SRV-POSTFIX-OPEN-RELAY", "Postfix mynetworks trusts the whole internet (open relay)", "srv-data", "vulnerability", "critical", "exposure", label, next(x for x in pf if "mynetworks" in x)[:150], "Restrict mynetworks to 127.0.0.0/8 and your private range", 10, cwe=["CWE-284"], owasp=["A05:2021"]))

    # ------------------------------------------------------------------ Kernel / OS hardening
    sx = S("sysctlx"); sv = {}
    for x in sx:
        if "=" in x:
            k, v = x.split("=", 1); sv[k] = v.strip()
    want = {"kernel.randomize_va_space": ("2",), "net.ipv4.conf.all.rp_filter": ("1", "2"), "net.ipv4.conf.all.accept_redirects": ("0",), "net.ipv4.conf.all.send_redirects": ("0",),
            "net.ipv4.conf.all.accept_source_route": ("0",), "net.ipv4.tcp_syncookies": ("1",), "kernel.kptr_restrict": ("1", "2"), "kernel.dmesg_restrict": ("1",), "fs.suid_dumpable": ("0",),
            "fs.protected_symlinks": ("1",), "fs.protected_hardlinks": ("1",)}
    weak = [f"{k}={sv[k]}" for k, ok in want.items() if sv.get(k) not in (None, "") and sv[k] not in ok]
    if weak: F.append(_f("SRV-SYSCTL-WEAK", f"{len(weak)} kernel parameter(s) below the hardening baseline", "srv-kernel", "code_smell", "medium" if any(w.startswith("kernel.randomize_va_space") for w in weak) else "low", "hardening", label, "; ".join(weak)[:300], "Create /etc/sysctl.d/99-hardening.conf with the recommended values and run `sysctl --system`", 20, cwe=["CWE-1188"], owasp=["A05:2021"]))
    if sx:
        apparmor = "apparmor=yes" in sx; se = next((x.split("=", 1)[1] for x in sx if x.startswith("selinux=")), "")
        if not apparmor and se.lower() not in ("enforcing",): F.append(_f("SRV-NO-MAC", "No mandatory access control is enforcing (AppArmor/SELinux)", "srv-kernel", "code_smell", "low", "hardening", label, f"apparmor=no selinux={se or 'absent'}", "Enable AppArmor (apt install apparmor apparmor-utils) or SELinux enforcing", 30, cwe=["CWE-284"], owasp=["A05:2021"]))
        if "journal_persistent=no" in sx and not any(x == "rsyslog=active" for x in sx): F.append(_f("SRV-NO-PERSISTENT-LOGS", "Logs are not persistent (journald volatile and rsyslog inactive)", "srv-kernel", "code_smell", "medium", "logging", label, "no /var/log/journal and rsyslog inactive", "Set `Storage=persistent` in /etc/systemd/journald.conf or enable rsyslog; ship logs off-host", 15, cwe=["CWE-778"], owasp=["A09:2021"]))
        if "auditd=active" not in sx: F.append(_f("SRV-NO-AUDITD", "auditd is not active (no kernel audit trail)", "srv-kernel", "code_smell", "info", "logging", label, "auditd inactive", "apt install auditd and add rules for sudo, ssh and /etc changes", 30, cwe=["CWE-778"], owasp=["A09:2021"]))
        inode = next((x.split("=", 1)[1] for x in sx if x.startswith("inode_full=")), "").strip()
        if inode: F.append(_f("SRV-INODES-FULL", f"Inode usage is high: {inode}", "srv-resource", "bug", "medium", "reliability", label, inode, "Find directories with millions of small files (sessions/cache/mail) and clean them", 30, cwe=["CWE-400"], owasp=["A05:2021"]))
    # users / ssh keys / cron / backups
    ux = S("userx")
    for x in _kv(ux, "sshfile="):
        m = re.match(r"(\d+)\s+(\S+)", x)
        if not m or m.group(2).endswith(".pub"): continue
        mode, path = m.group(1), m.group(2)
        if path.endswith("authorized_keys"):
            if mode[-1] in "2367": F.append(_f("SRV-SSH-AKEYS-PERMS", f"authorized_keys is writable by others: {path} ({mode})", "srv-kernel", "vulnerability", "high", "authz", label, f"{path} mode {mode}", f"chmod 600 {path}", 5, cwe=["CWE-732"], owasp=["A01:2021"]))
        elif mode not in ("600", "400"): F.append(_f("SRV-SSH-KEY-PERMS", f"SSH private key readable by others: {path} ({mode})", "srv-kernel", "vulnerability", "high", "authz", label, f"{path} mode {mode}", f"chmod 600 {path} (and rotate the key if the server is shared)", 10, cwe=["CWE-732"], owasp=["A01:2021"]))
    dss = [x for x in _kv(ux, "akeys=") if "ssh-dss" in x]
    if dss: F.append(_f("SRV-SSH-DSA-KEY", "authorized_keys contains obsolete ssh-dss (DSA) keys", "srv-kernel", "vulnerability", "medium", "crypto", label, dss[0][:160], "Replace them with ed25519 keys", 10, cwe=["CWE-327"], owasp=["A02:2021"]))
    ld = {}
    for x in _kv(ux, "logindefs="):
        p = x.split(None, 1)
        if len(p) == 2: ld[p[0]] = p[1].strip()
    if ld.get("PASS_MAX_DAYS", "").isdigit() and int(ld["PASS_MAX_DAYS"]) >= 99999 and any(x.startswith("shell_user=") for x in ux): F.append(_f("SRV-PASS-NO-AGING", "Passwords never expire (PASS_MAX_DAYS 99999)", "srv-kernel", "code_smell", "info", "authn", label, "PASS_MAX_DAYS 99999", "Prefer key-only SSH; otherwise set PASS_MAX_DAYS 365", 5, cwe=["CWE-262"], owasp=["A07:2021"]))
    cx = S("cronx")
    ww = _kv(cx, "cron_ww=")
    if ww: F.append(_f("SRV-CRON-WORLD-WRITABLE", f"{len(ww)} world-writable cron file(s)", "srv-kernel", "vulnerability", "high", "authz", label, "; ".join(ww[:5]), "chmod o-w on them; root executes these", 5, cwe=["CWE-732"], owasp=["A01:2021"]))
    suid = _kv(cx, "suid=")
    if suid: F.append(_f("SRV-SUID-UNUSUAL", f"{len(suid)} SUID binary(ies) in user/web/temp directories", "srv-kernel", "vulnerability", "high", "authz", label, "; ".join(suid[:5]), "Remove the SUID bit (`chmod u-s`) unless required", 10, cwe=["CWE-250"], owasp=["A01:2021"]))
    br = next((int(x.split("=", 1)[1]) for x in cx if x.startswith("backup_refs=") and x.split("=", 1)[1].strip().isdigit()), None)
    if br == 0: F.append(_f("SRV-NO-BACKUP-JOB", "No backup job detected in cron/systemd timers", "srv-backup", "security_hotspot", None, "resilience", label, "no restic/borg/rsync/mysqldump/pg_dump/rclone reference found", "Add encrypted off-host backups and enable provider snapshots; test a restore", 90, status="needs_validation", priority="medium", cwe=["CWE-693"], owasp=["A04:2021"]))
    # sshd crypto
    s2 = _kv(S("sshx"), "sshd2=")
    if s2:
        txt = " ".join(s2).lower()
        if re.search(r"\bciphers [^ ]*(-cbc|arcfour|3des)", txt): F.append(_f("SRV-SSH-WEAK-CIPHERS", "sshd allows weak ciphers (CBC/3DES/RC4)", "srv-ssh", "vulnerability", "medium", "crypto", label, next(x for x in s2 if x.lower().startswith("ciphers"))[:200], "Set `Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com`", 10, cwe=["CWE-327"], owasp=["A02:2021"]))
        if re.search(r"\bmacs [^ ]*(hmac-md5|umac-64@|hmac-sha1(,|$| ))", txt): F.append(_f("SRV-SSH-WEAK-MACS", "sshd allows weak MACs (MD5/SHA-1/64-bit)", "srv-ssh", "vulnerability", "low", "crypto", label, next(x for x in s2 if x.lower().startswith("macs"))[:200], "Use `MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com`", 10, cwe=["CWE-328"], owasp=["A02:2021"]))
        if re.search(r"kexalgorithms [^ ]*diffie-hellman-group1-sha1|kexalgorithms [^ ]*diffie-hellman-group14-sha1", txt): F.append(_f("SRV-SSH-WEAK-KEX", "sshd allows SHA-1 Diffie-Hellman key exchange", "srv-ssh", "vulnerability", "low", "crypto", label, "KexAlgorithms includes *-sha1", "Use curve25519-sha256 and DH group16/18 SHA-512", 10, cwe=["CWE-327"], owasp=["A02:2021"]))
        if re.search(r"permituserenvironment yes", txt): F.append(_f("SRV-SSH-USERENV", "sshd PermitUserEnvironment is yes", "srv-ssh", "vulnerability", "medium", "authz", label, "PermitUserEnvironment yes", "Set `PermitUserEnvironment no`", 5, cwe=["CWE-15"], owasp=["A05:2021"]))
        if re.search(r"allowtcpforwarding yes", txt) and not re.search(r"allowusers|allowgroups", txt): F.append(_f("SRV-SSH-TCP-FORWARD", "sshd allows TCP forwarding for every user", "srv-ssh", "code_smell", "low", "authz", label, "AllowTcpForwarding yes", "Set `AllowTcpForwarding no` (or `local`) unless tunnels are needed", 5, cwe=["CWE-284"], owasp=["A05:2021"]))
    return F, dict(stack=sorted(set(stack)))
