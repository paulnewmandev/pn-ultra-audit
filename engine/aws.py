"""Read-only AWS RDS review through the installed `aws` CLI (describe-* calls only)."""
import json, shutil, subprocess

from .kb import KB

DBPORTS = {"postgres": 5432, "mysql": 3306, "mariadb": 3306, "aurora-postgresql": 5432, "aurora-mysql": 3306, "oracle-ee": 1521, "sqlserver-se": 1433}


def _aws(args, profile, region, timeout=60):
    cmd = ["aws"] + args + ["--output", "json"] + (["--profile", profile] if profile else []) + (["--region", region] if region else [])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, str(e)
    if r.returncode != 0: return None, r.stderr.strip().splitlines()[-1] if r.stderr.strip() else f"exit {r.returncode}"
    try: return json.loads(r.stdout), None
    except ValueError: return None, "invalid JSON from aws cli"


def _f(rule, title, sev, label, ev, fix, effort, cat="cloud", cwe=(), owasp=("A05:2021",), status="confirmed", priority=None, why=None, typ="vulnerability"):
    return dict(rule=rule, title=title, family="cloud-db", type=typ, severity=sev if status == "confirmed" else None, category=cat, file=label, line=1, evidence=ev, impact=KB["cloud-db"]["impact"],
                fix=fix, effort_min=effort, cwe=list(cwe), owasp=list(owasp), status=status, priority=priority, why=why)


def audit_rds(profile=None, region=None, only=None):
    if not shutil.which("aws"): return [], "aws CLI not installed (https://aws.amazon.com/cli/)"
    data, err = _aws(["rds", "describe-db-instances"], profile, region)
    if data is None: return [], f"aws rds describe-db-instances failed: {err}"
    out, n = [], 0
    for db in data.get("DBInstances", []):
        ident = db["DBInstanceIdentifier"]
        if only and only not in (ident, (db.get("Endpoint") or {}).get("Address")): continue
        n += 1; lab = f"aws:rds/{ident}"; eng = db.get("Engine", "")
        port = (db.get("Endpoint") or {}).get("Port") or DBPORTS.get(eng, 0)
        sgs = [g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups", []) if g.get("Status") == "active"]
        open_world = []
        if sgs:
            sg, _ = _aws(["ec2", "describe-security-groups", "--group-ids"] + sgs, profile, region)
            for g in (sg or {}).get("SecurityGroups", []):
                for p in g.get("IpPermissions", []):
                    lo, hi = p.get("FromPort", 0), p.get("ToPort", 65535)
                    if p.get("IpProtocol") in ("-1", "tcp") and lo <= port <= hi and any(r.get("CidrIp") in ("0.0.0.0/0",) for r in p.get("IpRanges", [])) or \
                       any(r.get("CidrIpv6") == "::/0" for r in p.get("Ipv6Ranges", [])) and lo <= port <= hi:
                        open_world.append(g["GroupId"])
        pub = db.get("PubliclyAccessible")
        if pub and open_world:
            out.append(_f("RDS-PUBLIC-OPEN", f"RDS `{ident}` is publicly accessible AND security group allows 0.0.0.0/0 on {port}", "critical", lab, f"PubliclyAccessible=true; SG {', '.join(open_world)} open to the world",
                          "Set PubliclyAccessible=false, remove the 0.0.0.0/0 rule; allow only the application's security group", 30, cwe=["CWE-668"], owasp=["A05:2021", "A01:2021"]))
        elif pub:
            out.append(_f("RDS-PUBLIC", f"RDS `{ident}` is PubliclyAccessible", "high", lab, "PubliclyAccessible=true", "Modify instance: PubliclyAccessible=false; access via bastion/VPN/SSM tunnel", 30, cwe=["CWE-668"]))
        elif open_world:
            out.append(_f("RDS-SG-OPEN", f"RDS `{ident}` security group allows 0.0.0.0/0 on port {port} (not publicly addressable now)", "medium", lab, ", ".join(open_world),
                          "Restrict ingress to the application SG; a later PubliclyAccessible change would expose it", 15, cwe=["CWE-284"]))
        if not db.get("StorageEncrypted"):
            out.append(_f("RDS-NOT-ENCRYPTED", f"RDS `{ident}` storage is not encrypted", "high", lab, "StorageEncrypted=false", "Snapshot → copy snapshot with KMS encryption → restore → switch endpoint", 120, cwe=["CWE-311"], owasp=["A02:2021"]))
        brp = db.get("BackupRetentionPeriod", 0)
        if brp == 0: out.append(_f("RDS-NO-BACKUP", f"RDS `{ident}` has automated backups disabled", "high", lab, "BackupRetentionPeriod=0", "Set BackupRetentionPeriod ≥ 7 (14+ for production)", 10, cat="availability", cwe=["CWE-693"], typ="bug"))
        elif brp < 7: out.append(_f("RDS-SHORT-BACKUP", f"RDS `{ident}` backup retention is only {brp} day(s)", "low", lab, f"BackupRetentionPeriod={brp}", "Raise to ≥ 7 days", 5, cat="availability", typ="code_smell"))
        if not db.get("DeletionProtection"): out.append(_f("RDS-NO-DELPROT", f"RDS `{ident}` has no deletion protection", "low", lab, "DeletionProtection=false", "Enable DeletionProtection", 5, cat="availability", typ="code_smell"))
        if not db.get("MultiAZ"): out.append(_f("RDS-SINGLE-AZ", f"RDS `{ident}` is single-AZ", "info", lab, "MultiAZ=false", "Enable Multi-AZ if this is production", 15, cat="availability", typ="code_smell"))
        if not db.get("AutoMinorVersionUpgrade"): out.append(_f("RDS-NO-AUTOMINOR", f"RDS `{ident}` AutoMinorVersionUpgrade disabled", "low", lab, f"engine {eng} {db.get('EngineVersion')}", "Enable AutoMinorVersionUpgrade; schedule maintenance window", 5, cat="patching", cwe=["CWE-1104"], owasp=["A06:2021"], typ="code_smell"))
        if not db.get("EnabledCloudwatchLogsExports"): out.append(_f("RDS-NO-LOGS", f"RDS `{ident}` exports no logs to CloudWatch", "low", lab, "EnabledCloudwatchLogsExports=[]", "Enable error/slowquery (MySQL) or postgresql log exports", 10, cat="logging", owasp=["A09:2021"], typ="code_smell"))
        ca = db.get("CACertificateIdentifier", "")
        if ca == "rds-ca-2019": out.append(_f("RDS-OLD-CA", f"RDS `{ident}` still uses expired CA {ca}", "high", lab, f"CACertificateIdentifier={ca}", "Modify instance to rds-ca-rsa2048-g1 (or ecc384) and update client trust stores", 30, cwe=["CWE-295"], owasp=["A02:2021"]))
        # TLS enforcement via parameter group
        pname = next((g["DBParameterGroupName"] for g in db.get("DBParameterGroups", [])), None)
        key = "rds.force_ssl" if "postgres" in eng else ("require_secure_transport" if "mysql" in eng or "mariadb" in eng else None)
        if pname and key:
            pr, _ = _aws(["rds", "describe-db-parameters", "--db-parameter-group-name", pname, "--query", f"Parameters[?ParameterName=='{key}']"], profile, region)
            val = (pr[0].get("ParameterValue") if pr else None)
            if val not in ("1", "ON", "on", "true"):
                out.append(_f("RDS-NO-FORCE-TLS", f"RDS `{ident}` does not enforce TLS ({key}={val})", "medium", lab, f"{key}={val} in {pname}", f"Set {key}=1 in a custom parameter group and reboot", 20, cwe=["CWE-319"], owasp=["A02:2021"],
                              status="confirmed"))
    return out, f"{n} instance(s)"
