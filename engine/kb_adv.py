"""Knowledge base for version advisories (dependencies, runtimes, frameworks): English + Spanish overlay. Read-only."""
KB_ADV = {
"dep-vuln": dict(
    title="Dependency with known vulnerabilities (version-matched)",
    explain="The exact version locked in your lockfile is listed in a public vulnerability database (OSV / GitHub Advisories / NVD). Findings are version-matched, so the package really is in the affected range; whether the vulnerable code path is reachable in your app still needs a look.",
    impact="Known, public exploits against software you ship: remote code execution, injection, denial of service or data exposure depending on the advisory. Bots scan for these versions.",
    steps=["Read the advisory ids in the finding (the CVE / GHSA page lists the vulnerable function and the fixed version).", "Upgrade to the fixed version shown (the finding includes the exact command) and re-install from the lockfile; check the changelog for breaking changes.",
           "Run your tests and re-run the audit: the finding should disappear. If no fixed version exists, replace the package, pin a patched fork or add a mitigation.", "Automate it: Dependabot/Renovate with auto-merge for patch updates, and `npm audit` / `pip-audit` / `composer audit` in CI.",
           "Transitive dependency? Update the parent package or force a resolution (`overrides` in npm, `resolutions` in yarn, constraints in pip/composer)."],
    bad="\"lodash\": \"4.17.15\"   // CVE-2021-23337 command injection", safe="\"lodash\": \"^4.17.21\"", verify="`npm ls <pkg>` / `composer show <pkg>` / `pip show <pkg>` prints the fixed version; `npm audit` / `composer audit` / `pip-audit` report nothing for it; tests pass."),
"runtime-eol": dict(
    title="Runtime or framework version is end-of-life (no security patches)",
    explain="The language runtime or framework line you declare is no longer supported by its maintainers, so new vulnerabilities are not fixed for it (source: endoflife.date).",
    impact="Every new CVE stays unpatched on your stack, compliance audits (PCI, SOC 2, ISO 27001) flag unsupported software, and libraries drop support for it.",
    steps=["Pick the target: the newest supported release of the same product (see endoflife.date), preferring LTS.", "Read the migration guide, upgrade in a branch, run the test suite and fix deprecations; update Dockerfile / .nvmrc / runtime.txt / composer.json / CI matrix.",
           "Pin the new version everywhere it is declared so dev, CI and production agree.", "If you cannot upgrade now, document the exception and isolate the service (network restrictions, WAF) while you plan it."],
    bad="FROM php:7.4-apache", safe="FROM php:8.4-apache", verify="`php -v` / `node -v` / `python --version` in production shows a supported release; the audit no longer reports RUNTIME-EOL."),
"runtime-vuln": dict(
    title="Known CVEs for the exact runtime version",
    explain="The NVD lists high-severity CVEs (or CISA lists actively exploited ones) for the exact language runtime version your deployment declares.",
    impact="Vulnerabilities in the runtime itself (interpreter, standard library, HTTP/TLS stack) affect every application running on it, independent of your own code.",
    steps=["Upgrade to the latest patch release of the same line (or a newer supported line); patch releases are drop-in in most cases.", "Rebuild and redeploy images: pin the base image digest and rebuild regularly.", "Check the CVEs in the finding for mitigations if you cannot upgrade immediately (disable the affected feature, WAF rule).", "Subscribe to the project's security announcements."],
    bad="FROM node:18.17.0", safe="FROM node:22-alpine   # latest patch of a supported line", verify="The deployed runtime version equals the patched one; the audit reports no RUNTIME-VULN."),
"adv-kev": dict(
    title="Recently exploited vulnerabilities in your stack (CISA KEV)",
    explain="The CISA Known Exploited Vulnerabilities catalogue lists bugs of a product you use that attackers are exploiting in the wild and that were added recently. The audit cannot always know your exact patch level, so this is a prompt to verify.",
    impact="Actively exploited bugs are attacked within days of disclosure; an unpatched system is a likely target.",
    steps=["Open each CVE (nvd.nist.gov) and read the fixed versions for your line.", "Check your real version in production (`php -v`, `node -v`, `composer show`, `npm ls`).", "Patch to a fixed release immediately; if impossible, apply the vendor mitigation and restrict exposure.", "Add the product to your patch watch (Dependabot, vendor advisories)."],
    bad="php 8.3.4 in production while CVE-2024-4577 is exploited", safe="php 8.3.8+ (fixed)", verify="Production runs a version listed as fixed in each CVE; the audit finding is marked reviewed or suppressed with that evidence."),
}
KB_ADV_ES = {
"dep-vuln": dict(title="Dependencia con vulnerabilidades conocidas (según su versión)",
    explain="La versión exacta fijada en tu lockfile aparece en una base pública de vulnerabilidades (OSV / GitHub Advisories / NVD). El hallazgo coincide por versión, así que el paquete sí está en el rango afectado; falta revisar si el código vulnerable es alcanzable en tu app.",
    impact="Exploits públicos y conocidos contra software que distribuyes: ejecución remota de código, inyección, denegación de servicio o exposición de datos según el aviso. Hay bots que buscan esas versiones.",
    steps=["Lee los ids del aviso (la página CVE/GHSA indica la función vulnerable y la versión corregida).", "Actualiza a la versión corregida indicada (el hallazgo trae el comando exacto) y reinstala desde el lockfile; revisa el changelog por cambios incompatibles.",
           "Ejecuta tus pruebas y vuelve a auditar: el hallazgo debe desaparecer. Si no hay versión corregida, reemplaza el paquete, fija un fork parcheado o añade una mitigación.", "Automatízalo: Dependabot/Renovate con auto-merge de parches y `npm audit` / `pip-audit` / `composer audit` en CI.",
           "¿Dependencia transitiva? Actualiza el paquete padre o fuerza una resolución (`overrides` en npm, `resolutions` en yarn, constraints en pip/composer)."],
    verify="`npm ls <paquete>` / `composer show <paquete>` / `pip show <paquete>` muestra la versión corregida; `npm audit` / `composer audit` / `pip-audit` no reportan nada para él; las pruebas pasan."),
"runtime-eol": dict(title="La versión del runtime o framework está fuera de soporte (sin parches de seguridad)",
    explain="La línea del lenguaje o framework que declaras ya no tiene soporte de sus mantenedores, así que las vulnerabilidades nuevas no se corrigen para ella (fuente: endoflife.date).",
    impact="Cada CVE nuevo queda sin parche en tu stack, las auditorías (PCI, SOC 2, ISO 27001) marcan el software sin soporte y las librerías dejan de soportarlo.",
    steps=["Elige el destino: la versión soportada más reciente del mismo producto (ver endoflife.date), preferible LTS.", "Lee la guía de migración, actualiza en una rama, ejecuta las pruebas y corrige las deprecaciones; actualiza Dockerfile / .nvmrc / runtime.txt / composer.json / matriz de CI.",
           "Fija la nueva versión en todos los sitios donde se declara para que dev, CI y producción coincidan.", "Si no puedes actualizar ya, documenta la excepción y aísla el servicio (restricciones de red, WAF) mientras lo planeas."],
    verify="`php -v` / `node -v` / `python --version` en producción muestra una versión soportada; la auditoría ya no reporta RUNTIME-EOL."),
"runtime-vuln": dict(title="CVEs conocidos para la versión exacta del runtime",
    explain="La NVD lista CVEs de severidad alta (o CISA los lista como explotados) para la versión exacta del runtime que declara tu despliegue.",
    impact="Las vulnerabilidades del propio runtime (intérprete, biblioteca estándar, pila HTTP/TLS) afectan a toda aplicación que corre sobre él, independientemente de tu código.",
    steps=["Actualiza al último parche de la misma línea (o a una línea más nueva con soporte); los parches suelen ser reemplazos directos.", "Reconstruye y vuelve a desplegar las imágenes: fija el digest de la imagen base y reconstruye con regularidad.", "Revisa en los CVE del hallazgo si hay mitigaciones por si no puedes actualizar ya (desactivar la función afectada, regla WAF).", "Suscríbete a los avisos de seguridad del proyecto."],
    verify="La versión desplegada del runtime es la parcheada; la auditoría no reporta RUNTIME-VULN."),
"adv-kev": dict(title="Vulnerabilidades explotadas recientemente en tu stack (CISA KEV)",
    explain="El catálogo CISA de Vulnerabilidades Explotadas Conocidas lista bugs recientes de un producto que usas y que los atacantes explotan en la naturaleza. La auditoría no siempre conoce tu nivel de parche exacto, por eso es un aviso para verificar.",
    impact="Los bugs explotados activamente se atacan a los pocos días de divulgarse; un sistema sin parchar es un objetivo probable.",
    steps=["Abre cada CVE (nvd.nist.gov) y lee las versiones corregidas para tu línea.", "Comprueba tu versión real en producción (`php -v`, `node -v`, `composer show`, `npm ls`).", "Parchea de inmediato a una versión corregida; si es imposible, aplica la mitigación del proveedor y restringe la exposición.", "Añade el producto a tu vigilancia de parches (Dependabot, avisos del proveedor)."],
    verify="Producción corre una versión listada como corregida en cada CVE; el hallazgo se marca como revisado o suprimido con esa evidencia."),
}
try:
    from .kb_es import KB_ES
    KB_ES.update(KB_ADV_ES)
except ImportError:  # pragma: no cover
    pass
