"""What to do when a key is exposed: provider-specific rotation steps, attached to every secret finding."""
import re

# regex on rule id -> (provider, rotate URL/command, steps EN, steps ES)
PLAYBOOK = [
    (r"AWS", "AWS", "https://console.aws.amazon.com/iam/home#/security_credentials",
     ["AWS: IAM > Users > Security credentials > make the exposed access key Inactive, then Delete; create a new key (or move to IAM roles / OIDC).", "Check CloudTrail for the key's activity since the exposure (`aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<AKIA...>`) and for new users, roles or EC2/GPU instances."],
     ["AWS: IAM > Usuarios > Credenciales de seguridad > desactiva y borra la clave expuesta; crea una nueva (o usa roles IAM / OIDC).", "Revisa CloudTrail por actividad de esa clave desde la exposición y por usuarios, roles o instancias EC2/GPU nuevos."]),
    (r"GITHUB", "GitHub", "https://github.com/settings/tokens",
     ["GitHub: Settings > Developer settings > Personal access tokens (or the app/installation) > Revoke the token and create a fine-grained one with minimal scopes.", "Review the audit log (Settings > Security log / org Audit log) for pushes, new deploy keys or webhooks made with it."],
     ["GitHub: Settings > Developer settings > Personal access tokens > Revoke y crea uno fine-grained con permisos mínimos.", "Revisa el registro de auditoría por pushes, deploy keys o webhooks nuevos hechos con ese token."]),
    (r"SLACK", "Slack", "https://api.slack.com/apps",
     ["Slack: api.slack.com/apps > your app > OAuth & Permissions > Revoke tokens / Regenerate; for incoming webhooks create a new webhook URL.", "Check recent messages posted and apps installed by that token."],
     ["Slack: api.slack.com/apps > tu app > OAuth & Permissions > revoca/regenera tokens; para webhooks crea una URL nueva.", "Revisa mensajes y apps instaladas con ese token."]),
    (r"STRIPE", "Stripe", "https://dashboard.stripe.com/apikeys",
     ["Stripe: Dashboard > Developers > API keys > Roll the exposed secret key (set a short expiry for the old one) and update your servers.", "Review recent API requests/logs and webhook endpoints; consider restricted keys per service."],
     ["Stripe: Dashboard > Developers > API keys > Roll de la clave expuesta (con caducidad corta de la anterior) y actualiza tus servidores.", "Revisa logs de API y endpoints de webhook; usa claves restringidas por servicio."]),
    (r"GOOGLE|FIREBASE|GCP", "Google Cloud", "https://console.cloud.google.com/apis/credentials",
     ["Google Cloud: APIs & Services > Credentials > delete or regenerate the key, then restrict the new one (HTTP referrers / IP / API list). For service-account keys: IAM > Service accounts > Keys > Delete.", "Check billing and Cloud Audit Logs for unexpected usage."],
     ["Google Cloud: APIs y servicios > Credenciales > borra o regenera la clave y restríngela (referrers/IP/APIs). Para claves de cuenta de servicio: IAM > Cuentas de servicio > Claves > Eliminar.", "Revisa facturación y Cloud Audit Logs."]),
    (r"DB-URL|DATABASE|MYSQL|POSTGRES|MONGO|REDIS|SQL", "Database", "your database/provider console",
     ["Database: change the password/user NOW (`ALTER USER ... PASSWORD ...`), update the app's secret store, and restrict network access (private network / IP allow-list).", "Review connections and recent queries/audit logs; if data may have been read, follow your breach process."],
     ["Base de datos: cambia la contraseña/usuario YA (`ALTER USER ...`), actualiza el gestor de secretos y restringe el acceso de red.", "Revisa conexiones y logs de auditoría; si pudieron leer datos, sigue tu proceso de brechas."]),
    (r"JWT", "JWT", "your auth service",
     ["JWT: generate a new signing secret/key pair, deploy it, and invalidate sessions (all tokens signed with the old secret are forgeable).", "Use asymmetric keys (RS256/ES256) or a KMS and load the key from the environment."],
     ["JWT: genera un nuevo secreto/par de claves, despliégalo e invalida las sesiones (los tokens firmados con el secreto viejo son falsificables).", "Usa claves asimétricas (RS256/ES256) o KMS y cárgalas desde el entorno."]),
    (r"PRIVATE-KEY|PRIVATE_KEY|PEM|KEY-FILE|SSH", "Private key", "wherever the key is trusted",
     ["Private key: generate a new key pair, replace the public key everywhere it is trusted (authorized_keys, deploy keys, TLS certificate, JWT/JWKS) and revoke the old one (for TLS: revoke the certificate with your CA).", "Remove the key from git history and keep keys outside the repo (secret manager / mounted volume)."],
     ["Clave privada: genera un par nuevo, reemplaza la pública donde se confía (authorized_keys, deploy keys, certificado TLS, JWKS) y revoca la anterior (TLS: revoca el certificado con tu CA).", "Quita la clave del historial de git y guárdala fuera del repo."]),
    (r"WALLET|MNEMONIC|WEB3|RPC", "Crypto wallet", "move funds immediately",
     ["Wallet: treat it as stolen - create a new wallet and move all funds/approvals NOW (revoke token approvals on the old address); never reuse the seed phrase.", "RPC/provider keys (Infura/Alchemy/QuickNode): regenerate in the provider dashboard and add domain/IP allow-lists."],
     ["Wallet: considérala robada: crea otra, mueve fondos y revoca aprobaciones YA; nunca reutilices la frase semilla.", "Claves RPC (Infura/Alchemy/QuickNode): regenera en el panel y añade listas de dominios/IP."]),
    (r"VERCEL", "Vercel", "https://vercel.com/account/tokens",
     ["Vercel: Account > Tokens > delete the exposed token; rotate the project's environment variables that were exposed (Project > Settings > Environment Variables) and redeploy.", "Review Team > Activity log for unexpected deployments or env changes."],
     ["Vercel: Account > Tokens > elimina el token expuesto; rota las variables de entorno expuestas (Project > Settings > Environment Variables) y vuelve a desplegar.", "Revisa el Activity log del equipo."]),
    (r"NPM|TOKEN-FILE|PYPI|REGISTRY|DOCKER", "Package registry", "npmjs.com / pypi.org / your registry",
     ["Registry: revoke the token in the registry (npm: Access Tokens; PyPI: Account settings > API tokens; Docker Hub: Security) and create a scoped, read-only or publish-only token; prefer trusted publishing (OIDC).", "Check the published versions for unexpected releases."],
     ["Registro: revoca el token (npm: Access Tokens; PyPI: API tokens; Docker Hub: Security) y crea uno con alcance mínimo; usa trusted publishing (OIDC).", "Revisa si hay versiones publicadas inesperadas."]),
    (r"TFSTATE|TFVARS|KUBECONFIG|CLOUD-CRED|SERVICE", "Cloud credentials", "your cloud console",
     ["Cloud credentials: rotate every credential contained in the file (state files and kubeconfigs embed keys, passwords and tokens), then move state to a remote encrypted backend (S3+KMS, Terraform Cloud) and kubeconfigs to short-lived auth (OIDC/exec plugins).", "Audit cloud activity logs since the file was first committed."],
     ["Credenciales cloud: rota todas las del archivo (tfstate y kubeconfig incluyen claves, contraseñas y tokens); mueve el state a un backend remoto cifrado (S3+KMS, Terraform Cloud) y usa autenticación de corta duración.", "Revisa los logs de actividad desde el primer commit del archivo."]),
    (r"HARDCODED|CREDENTIAL|SECRET|PASSWORD|ENV", "Generic secret", "the service that issued it",
     ["Generic secret: identify which service issues it, rotate it there, and load the new value from the environment or a secret manager.", "Search the codebase and history for the same value (`git grep`, `gitleaks detect`) - it may be duplicated."],
     ["Secreto genérico: identifica qué servicio lo emite, rótalo ahí y carga el valor nuevo desde el entorno o un gestor de secretos.", "Busca el mismo valor en el código e historial (`git grep`, `gitleaks detect`)."]),
]


def for_rule(rule_id, lang="en"):
    """-> (provider, url, steps) or None"""
    r = (rule_id or "").upper()
    if not (r.startswith(("SEC-", "HIST-SEC", "REPO-PRIVATE", "REPO-CLOUD", "REPO-TOKEN", "REPO-TFSTATE", "REPO-TFVARS", "REPO-KUBECONFIG", "REPO-APP-CONFIG", "REPO-HIST", "REPO-REMOTE", "JWT-HARDCODED", "WEB3-HARDHAT", "MOB-ANDROID-SIGNING", "VERCEL-SECRET", "VERCEL-PUBLIC", "REPO-CI-LITERAL"))): return None
    for rx, prov, url, en, es in PLAYBOOK:
        if re.search(rx, r): return prov, url, (es if lang == "es" else en)
    return None
