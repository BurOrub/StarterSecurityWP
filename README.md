# Starter Security

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
