<?php
/**
 * Pagina Impostazioni > Starter Security: interruttori per ogni misura, stato e segnalazioni della CSP.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Starter_Security_Admin {

	const PAGE = 'starter-security';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register' ) );
		add_action( 'admin_post_starter_security_clear_csp', array( __CLASS__, 'clear_log' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( STARTER_SECURITY_FILE ), array( __CLASS__, 'links' ) );
	}

	public static function links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( admin_url( 'options-general.php?page=' . self::PAGE ) ) . '">' . esc_html__( 'Impostazioni', 'starter-security' ) . '</a>' );

		return $links;
	}

	public static function menu() {
		add_options_page( __( 'Starter Security', 'starter-security' ), __( 'Starter Security', 'starter-security' ), 'manage_options', self::PAGE, array( __CLASS__, 'render' ) );
	}

	public static function register() {
		register_setting(
			'starter_security',
			Starter_Security::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( __CLASS__, 'sanitize' ),
			)
		);
	}

	public static function sanitize( $input ) {
		$input = is_array( $input ) ? $input : array();
		$out   = array();

		foreach ( Starter_Security::defaults() as $key => $default ) {
			if ( 'csp' === $key ) {
				$out[ $key ] = isset( $input[ $key ] ) && 'report' === $input[ $key ] ? 'report' : 'off';
			} elseif ( 'ip_header' === $key ) {
				$out[ $key ] = isset( $input[ $key ] ) && in_array( $input[ $key ], array( 'REMOTE_ADDR', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR' ), true ) ? $input[ $key ] : 'REMOTE_ADDR';
			} else {
				$out[ $key ] = empty( $input[ $key ] ) ? 0 : 1;
			}
		}

		// Applica subito la regola sulla cartella dei caricamenti.
		update_option( Starter_Security::OPTION, $out );
		delete_option( Starter_Security_Uploads::SIG );
		Starter_Security_Uploads::sync();

		return $out;
	}

	public static function clear_log() {
		check_admin_referer( 'starter_security_clear_csp' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Non hai i permessi per farlo.', 'starter-security' ) );
		}

		delete_option( Starter_Security_Headers::LOG );
		wp_safe_redirect( admin_url( 'options-general.php?page=' . self::PAGE ) );
		exit;
	}

	private static function checkbox( $key, $label, $help ) {
		printf(
			'<tr><th scope="row">%1$s</th><td><label><input type="checkbox" name="%2$s[%3$s]" value="1" %4$s> %5$s</label></td></tr>',
			esc_html( $label ),
			esc_attr( Starter_Security::OPTION ),
			esc_attr( $key ),
			checked( Starter_Security::on( $key ), true, false ),
			esc_html( $help )
		);
	}

	public static function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$o      = Starter_Security::opts();
		$name   = Starter_Security::OPTION;
		$status = Starter_Security_Uploads::status();
		$log    = get_option( Starter_Security_Headers::LOG, array() );
		$log    = is_array( $log ) ? $log : array();

		uasort(
			$log,
			static function ( $a, $b ) {
				return $b['count'] <=> $a['count'];
			}
		);
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Starter Security', 'starter-security' ); ?></h1>
			<form method="post" action="options.php">
				<?php settings_fields( 'starter_security' ); ?>
				<table class="form-table" role="presentation">
					<?php
					self::checkbox( 'headers', __( 'Header di sicurezza', 'starter-security' ), __( 'nosniff, anti-iframe (stesso sito), referrer e permessi del browser.', 'starter-security' ) );
					self::checkbox( 'hsts', __( 'HSTS', 'starter-security' ), __( 'Obbliga il browser a usare HTTPS (un anno). Attivalo solo su siti già interamente in HTTPS: il browser lo ricorda a lungo.', 'starter-security' ) );
					?>
					<tr>
						<th scope="row"><?php esc_html_e( 'Content Security Policy', 'starter-security' ); ?></th>
						<td>
							<select name="<?php echo esc_attr( $name ); ?>[csp]">
								<option value="report" <?php selected( $o['csp'], 'report' ); ?>><?php esc_html_e( 'Solo report (non blocca nulla)', 'starter-security' ); ?></option>
								<option value="off" <?php selected( $o['csp'], 'off' ); ?>><?php esc_html_e( 'Disattivata', 'starter-security' ); ?></option>
							</select>
							<p class="description"><?php esc_html_e( 'Il browser segnala cosa verrebbe bloccato, qui sotto. Non blocca niente.', 'starter-security' ); ?></p>
						</td>
					</tr>
					<?php
					self::checkbox( 'xmlrpc', __( 'XML-RPC', 'starter-security' ), __( 'Disattivato. Da riattivare se il cliente usa Jetpack o l\'app WordPress per telefono.', 'starter-security' ) );
					self::checkbox( 'version', __( 'Versione di WordPress', 'starter-security' ), __( 'Nascosta nel codice delle pagine.', 'starter-security' ) );
					self::checkbox( 'users', __( 'Utenti non enumerabili', 'starter-security' ), __( '/?author=N, elenco utenti REST e sitemap utenti non rivelano gli username a chi non è collegato.', 'starter-security' ) );
					self::checkbox( 'login_msg', __( 'Errore di login generico', 'starter-security' ), __( 'Stesso messaggio per username inesistente e password sbagliata.', 'starter-security' ) );
					self::checkbox( 'login_limit', __( 'Limite ai tentativi di login', 'starter-security' ), __( 'Dopo 5 tentativi falliti in 15 minuti l\'indirizzo IP viene bloccato per il resto dei 15 minuti.', 'starter-security' ) );
					?>
					<tr>
						<th scope="row"><?php esc_html_e( 'Come leggere l\'IP', 'starter-security' ); ?></th>
						<td>
							<select name="<?php echo esc_attr( $name ); ?>[ip_header]">
								<option value="REMOTE_ADDR" <?php selected( $o['ip_header'], 'REMOTE_ADDR' ); ?>><?php esc_html_e( 'Diretto (predefinito)', 'starter-security' ); ?></option>
								<option value="HTTP_CF_CONNECTING_IP" <?php selected( $o['ip_header'], 'HTTP_CF_CONNECTING_IP' ); ?>><?php esc_html_e( 'Dietro Cloudflare', 'starter-security' ); ?></option>
								<option value="HTTP_X_FORWARDED_FOR" <?php selected( $o['ip_header'], 'HTTP_X_FORWARDED_FOR' ); ?>><?php esc_html_e( 'Dietro un proxy (X-Forwarded-For)', 'starter-security' ); ?></option>
							</select>
							<p class="description"><?php esc_html_e( 'Da cambiare solo se il sito è dietro Cloudflare o un proxy: altrimenti i limiti contano tutti i visitatori come un solo indirizzo.', 'starter-security' ); ?></p>
						</td>
					</tr>
					<?php
					self::checkbox( 'file_edit', __( 'Editor dei file', 'starter-security' ), __( 'Disattivato (Aspetto > Editor e Plugin > Editor). Gli aggiornamenti restano attivi.', 'starter-security' ) );
					self::checkbox( 'uploads', __( 'PHP bloccato nei caricamenti', 'starter-security' ), __( 'Impedisce di eseguire PHP in wp-content/uploads.', 'starter-security' ) );
					?>
					<tr>
						<th scope="row"><?php esc_html_e( 'Stato blocco PHP', 'starter-security' ); ?></th>
						<td>
							<?php
							if ( 'on' === $status ) {
								esc_html_e( 'Attivo.', 'starter-security' );
							} elseif ( 'unsupported' === $status ) {
								esc_html_e( 'Non applicabile: il server non è Apache o LiteSpeed (nginx ignora .htaccess; serve una regola sul server).', 'starter-security' );
							} else {
								esc_html_e( 'Non attivo.', 'starter-security' );
							}
							?>
						</td>
					</tr>
					<?php self::checkbox( 'rate_limit', __( 'Limiti alle API pubbliche', 'starter-security' ), __( 'Ricerca, preferiti e invio moduli: oltre la soglia il visitatore riceve un errore 429.', 'starter-security' ) ); ?>
				</table>
				<?php submit_button(); ?>
			</form>

			<h2><?php esc_html_e( 'Segnalazioni della CSP', 'starter-security' ); ?></h2>
			<?php if ( ! $log ) : ?>
				<p><?php esc_html_e( 'Nessuna segnalazione. Naviga il sito e riapri questa pagina.', 'starter-security' ); ?></p>
			<?php else : ?>
				<table class="widefat striped" style="max-width:900px">
					<thead><tr><th><?php esc_html_e( 'Direttiva', 'starter-security' ); ?></th><th><?php esc_html_e( 'Origine', 'starter-security' ); ?></th><th><?php esc_html_e( 'Pagina', 'starter-security' ); ?></th><th><?php esc_html_e( 'Volte', 'starter-security' ); ?></th></tr></thead>
					<tbody>
					<?php foreach ( $log as $row ) : ?>
						<tr>
							<td><?php echo esc_html( $row['directive'] ); ?></td>
							<td><?php echo esc_html( $row['blocked'] ? $row['blocked'] : '(inline)' ); ?></td>
							<td><?php echo esc_html( $row['page'] ); ?></td>
							<td><?php echo esc_html( (string) (int) $row['count'] ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:12px">
					<input type="hidden" name="action" value="starter_security_clear_csp">
					<?php wp_nonce_field( 'starter_security_clear_csp' ); ?>
					<?php submit_button( __( 'Svuota segnalazioni', 'starter-security' ), 'secondary', 'submit', false ); ?>
				</form>
			<?php endif; ?>
		</div>
		<?php
	}
}
