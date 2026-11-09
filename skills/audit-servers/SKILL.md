---
name: audit-servers
description: VPS and cloud server auditor (read-only over SSH). Detects the provider (AWS, Azure, Google Cloud, DigitalOcean, Hostinger, Hetzner, Vultr, Linode, OVH, Oracle...) and audits OS patching, SSH, users, firewall, kernel hardening, nginx/Apache/PHP, Docker and containers, Kubernetes (k3s/kubeadm/microk8s), Redis, Kafka/ZooKeeper, MySQL/PostgreSQL/MongoDB/Elasticsearch/memcached/RabbitMQ, mail, cron, backups, certificates and disk. Generates a reviewable server-fixes.sh. Use when the user gives an SSH target or says VPS, server, droplet, EC2, hardening.
---

# audit-servers

Goal: audit the **server** (not only the code) and hand over a safe path to fix it. Strictly read-only; the generated `server-fixes.sh` is **never executed by the tool**.

## 0. Authorisation and access
Only servers the user owns or is allowed to assess. Run: `python3 <suite>/audit.py --ssh user@host --authorized [--sudo] [--remote-path /var/www/app] --strictness <basic|standard|strict>` (ask which strictness; default standard). Key/agent auth only; `--sudo` needs passwordless `sudo -n` for complete results (sshd -T, shadow, firewall, logs).

## 1. What is covered
- **Provider layer:** auto-detected from DMI/metadata (never reads credentials): IMDSv1 on AWS, instance role present, GCP service-account scopes and OS Login, Azure agent, DO agent, secrets in cloud-init user-data, and the exact CLI command to verify the provider firewall (security group / NSG / VPC firewall / DO Cloud Firewall / Hostinger hPanel).
- **OS:** EOL, pending security updates, unattended-upgrades, reboot required, sysctl baseline, AppArmor/SELinux, auditd, persistent logs, inodes, disk.
- **Access:** sshd settings and crypto, root login, password auth, extra UID 0, empty passwords, NOPASSWD sudo, key/authorized_keys permissions, DSA keys, fail2ban, brute-force noise.
- **Network:** listening ports vs host firewall, Docker bypassing ufw.
- **Web:** nginx, Apache, PHP, certificates, `.env`/`.git`/backups in web roots, world-writable files.
- **Containers & orchestration:** privileged/host-network/host-PID containers, docker.sock mounts, root users, no limits, Docker API on TCP, Kubernetes kubeconfig/kubelet/API server/etcd, privileged pods, hostPath, cluster-admin bindings, NetworkPolicy.
- **Data stores & brokers:** Redis, Kafka/ZooKeeper (+JMX), MySQL/MariaDB, PostgreSQL (`pg_hba`), MongoDB, Elasticsearch, memcached, RabbitMQ, Postfix open relay.
- **Resilience:** cron hygiene, SUID in odd places, backup jobs.

## 2. Fix path
Read `server-fixes.sh` in the run folder. `sudo bash server-fixes.sh list` shows fixes marked `[S]` safe or `[R]` risky; `... safe` applies the safe group; risky ones are applied by id, after keeping a second SSH session open. Each fix backs up the file and validates the config before reloading. Re-run the audit to confirm.

## 3. Reporting
Group by layer (provider, OS, access, network, web, containers, data stores). For each: evidence (never secrets), risk in one sentence, the exact fix, verification command.
