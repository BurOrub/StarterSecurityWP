<?php
/**
 * Blocca l'esecuzione di PHP nella cartella dei caricamenti (solo server Apache/LiteSpeed: nginx ignora .htaccess).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Starter_Security_Uploads {

	const MARKER = 'STARTER_SECURITY';
	const SIG    = 'starter_security_uploads_sig';

	public static function init() {
		add_action( 'admin_init', array( __CLASS__, 'sync' ) );
	}

	/** True se il server legge i file .htaccess. */
	public static function supported() {
		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';

		return false !== strpos( $software, 'apache' ) || false !== strpos( $software, 'litespeed' );
	}

	private static function file() {
		$dir = wp_upload_dir( null, false );

		return trailingslashit( $dir['basedir'] ) . '.htaccess';
	}

	private static function rules() {
		return array(
			'<FilesMatch "\.(php|php[0-9]|phtml|phar|pl|py|cgi)$">',
			'<IfModule mod_authz_core.c>',
			'Require all denied',
			'</IfModule>',
			'<IfModule !mod_authz_core.c>',
			'Order allow,deny',
			'Deny from all',
			'</IfModule>',
			'</FilesMatch>',
		);
	}

	/** Scrive o toglie il blocco secondo l'impostazione; riscrive solo se cambia qualcosa. */
	public static function sync() {
		$want = Starter_Security::on( 'uploads' ) && self::supported();
		$sig  = $want ? md5( implode( "\n", self::rules() ) ) : 'off';

		if ( get_option( self::SIG ) === $sig ) {
			return;
		}

		self::write( $want ? self::rules() : array() );
		update_option( self::SIG, $sig, false );
	}

	public static function remove() {
		self::write( array() );
		delete_option( self::SIG );
	}

	private static function write( $lines ) {
		$file = self::file();

		if ( ! $lines && ! file_exists( $file ) ) {
			return;
		}

		require_once ABSPATH . 'wp-admin/includes/misc.php';

		if ( wp_is_writable( dirname( $file ) ) ) {
			insert_with_markers( $file, self::MARKER, $lines );

			// Tolto il blocco, se resta solo un file di commenti lo si elimina.
			if ( ! $lines && file_exists( $file ) && '' === trim( preg_replace( '/^\s*#.*$/m', '', (string) file_get_contents( $file ) ) ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
				wp_delete_file( $file );
			}
		}
	}

	/** Stato per la pagina delle impostazioni. */
	public static function status() {
		if ( ! self::supported() ) {
			return 'unsupported';
		}

		$file = self::file();

		return file_exists( $file ) && false !== strpos( (string) file_get_contents( $file ), 'Require all denied' ) ? 'on' : 'off'; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
	}
}
