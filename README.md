# Starter Security

**English** · [Italiano](#italiano)

Basic hardening for sites built with Starter Theme. Every measure can be switched on and off from **Settings > Starter Security**. Deactivating the plugin puts everything back as it was (the PHP block in `uploads/` is removed).

| Measure | What it does |
|---|---|
| Security headers | nosniff, X-Frame-Options (same site), Referrer-Policy, Permissions-Policy. Optional HSTS (off by default). |
| CSP | Report-only: it blocks nothing. Reports are shown in the settings page. The policy can be changed with the `starter_security_csp` filter. |
| XML-RPC | `xmlrpc.php` answers 403. |
| WP version | Hidden in the page source. |
| Users | `/?author=N`, `/wp-json/wp/v2/users` and the users sitemap do not reveal usernames to visitors who are not logged in. |
| Login | Generic error message; IP block after 5 failed attempts in 15 minutes (wp-login and WooCommerce). |
| File editor | Removed from the admin; updates keep working. |
| PHP in uploads | `.htaccess` rule (Apache/LiteSpeed only; on nginx it has to be set in the server). |
| API limits | Search 90/min, wishlist 90/min, Contact Form 7 submissions 10 every 10 min per IP. Filter `starter_security_rate_limits`. |

Behind Cloudflare or a proxy, choose in the settings where to read the IP from, otherwise the limits count all visitors as one.

## Updates

The plugin checks the latest release of [StarterSecurityWP](https://github.com/BurOrub/StarterSecurityWP) on GitHub (every 6 hours) and WordPress shows the usual update notice. This is the plugin's only contact with the outside. To turn it off: `define( 'STARTER_SECURITY_UPDATE_REPO', '' );` in `wp-config.php`. On a development copy (folder with `.git`) no notice is shown. For a private repository, define `STARTER_GITHUB_TOKEN` (read-only token).

Publishing a version: raise `Version:` in `starter-security.php` (and `STARTER_SECURITY_VERSION`), commit, `git tag vX.Y.Z`, `git push origin main vX.Y.Z`. The workflow in `.github/workflows/release.yml` builds `starter-security.zip` and attaches it to the release.

---

## Italiano

Protezioni di base per i siti con il Tema Starter. Ogni misura si accende e spegne da **Impostazioni > Starter Security**. Disattivando il plugin tutto torna come prima (il blocco PHP in `uploads/` viene tolto).

| Misura | Cosa fa |
|---|---|
| Header di sicurezza | nosniff, X-Frame-Options (stesso sito), Referrer-Policy, Permissions-Policy. HSTS facoltativo (spento di default). |
| CSP | Solo report: non blocca nulla. Le segnalazioni compaiono nella pagina delle impostazioni. Policy modificabile con il filtro `starter_security_csp`. |
| XML-RPC | xmlrpc.php risponde 403. |
| Versione WP | Nascosta nel codice. |
| Utenti | `/?author=N`, `/wp-json/wp/v2/users` e sitemap utenti non rivelano gli username a chi non è collegato. |
| Login | Errore generico; blocco IP dopo 5 tentativi falliti in 15 minuti (wp-login e WooCommerce). |
| Editor file | Tolto dall'admin; gli aggiornamenti restano. |
| PHP in uploads | Regola `.htaccess` (solo Apache/LiteSpeed; su nginx va messa nel server). |
| Limiti API | Ricerca 90/min, preferiti 90/min, invio moduli CF7 10 ogni 10 min per IP. Filtro `starter_security_rate_limits`. |

Dietro Cloudflare o un proxy, scegli nelle impostazioni da dove leggere l'IP, altrimenti i limiti contano tutti i visitatori come uno.

### Aggiornamenti

Il plugin controlla l'ultima release di [StarterSecurityWP](https://github.com/BurOrub/StarterSecurityWP) su GitHub (ogni 6 ore) e WordPress mostra la notifica normale di aggiornamento. È l'unico contatto del plugin con l'esterno. Per spegnerlo: `define( 'STARTER_SECURITY_UPDATE_REPO', '' );` in `wp-config.php`. Sulle copie di sviluppo (cartella con `.git`) la notifica non compare. Per un repository privato definisci `STARTER_GITHUB_TOKEN` (token di sola lettura).

Pubblicare una versione: alza `Version:` in `starter-security.php` (e `STARTER_SECURITY_VERSION`), commit, `git tag vX.Y.Z`, `git push origin main vX.Y.Z`. L'automazione in `.github/workflows/release.yml` crea `starter-security.zip` e lo allega alla release.
