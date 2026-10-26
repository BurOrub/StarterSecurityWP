<?php
/**
 * Login: messaggio di errore generico e blocco temporaneo dopo troppi tentativi falliti (wp-login e WooCommerce).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Starter_Security_Login {

	const MAX_FAILS = 5;
	const WINDOW    = 900; // 15 minuti.

	public static function init() {
		add_filter( 'authenticate', array( __CLASS__, 'lock_check' ), 5, 3 );
		add_filter( 'authenticate', array( __CLASS__, 'generic_error' ), 100, 3 );
		add_action( 'wp_login_failed', array( __CLASS__, 'failed' ) );
		add_action( 'wp_login', array( __CLASS__, 'success' ) );
	}

	private static function key() {
		return 'ss_login_' . md5( Starter_Security::ip() );
	}

	private static function state() {
		$data = get_transient( self::key() );

		return is_array( $data ) ? $data : array(
			'n' => 0,
			't' => time(),
		);
	}

	private static function locked() {
		if ( ! Starter_Security::on( 'login_limit' ) ) {
			return false;
		}

		$data = self::state();

		return $data['n'] >= self::MAX_FAILS && time() - (int) $data['t'] < self::WINDOW;
	}

	/** Bloccato: si saltano i controlli di password, così nemmeno quella giusta passa finché dura il blocco. */
	public static function lock_check( $user ) {
		if ( ! self::locked() ) {
			return $user;
		}

		remove_filter( 'authenticate', 'wp_authenticate_username_password', 20 );
		remove_filter( 'authenticate', 'wp_authenticate_email_password', 20 );
		remove_filter( 'authenticate', 'wp_authenticate_application_password', 20 );
		remove_filter( 'authenticate', 'wp_authenticate_cookie', 30 );

		$data    = self::state();
		$minutes = max( 1, (int) ceil( ( self::WINDOW - ( time() - (int) $data['t'] ) ) / 60 ) );

		/* translators: %d: minuti di attesa. */
		return new WP_Error( 'starter_locked', sprintf( _n( 'Troppi tentativi di accesso. Riprova tra %d minuto.', 'Troppi tentativi di accesso. Riprova tra %d minuti.', $minutes, 'starter-security' ), $minutes ) );
	}

	/** Stesso messaggio per username inesistente e password sbagliata. */
	public static function generic_error( $user ) {
		if ( Starter_Security::on( 'login_msg' ) && is_wp_error( $user ) && array_intersect( $user->get_error_codes(), array( 'invalid_username', 'incorrect_password', 'invalid_email' ) ) ) {
			return new WP_Error( 'invalid_credentials', __( 'Credenziali non corrette.', 'starter-security' ) );
		}

		return $user;
	}

	public static function failed() {
		if ( ! Starter_Security::on( 'login_limit' ) || self::locked() ) {
			return;
		}

		$data = self::state();

		if ( time() - (int) $data['t'] >= self::WINDOW ) {
			$data = array(
				'n' => 0,
				't' => time(),
			);
		}

		++$data['n'];
		set_transient( self::key(), $data, self::WINDOW );
	}

	public static function success() {
		delete_transient( self::key() );
	}
}
