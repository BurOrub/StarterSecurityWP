<?php
/**
 * Impostazioni condivise e utilità (IP del visitatore, contatori a finestra).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Starter_Security {

	const OPTION = 'starter_security';

	/** Valori predefiniti: tutto attivo tranne HSTS; la CSP parte in solo report. */
	public static function defaults() {
		return array(
			'headers'     => 1,
			'hsts'        => 0,
			'csp'         => 'report',
			'xmlrpc'      => 1,
			'version'     => 1,
			'users'       => 1,
			'login_msg'   => 1,
			'login_limit' => 1,
			'file_edit'   => 1,
			'uploads'     => 1,
			'rate_limit'  => 1,
			'ip_header'   => 'REMOTE_ADDR',
		);
	}

	public static function opts() {
		$saved = get_option( self::OPTION, array() );

		return wp_parse_args( is_array( $saved ) ? $saved : array(), self::defaults() );
	}

	public static function on( $key ) {
		return ! empty( self::opts()[ $key ] );
	}

	/** IP del visitatore. Dietro proxy/Cloudflare si sceglie l'intestazione nelle impostazioni. */
	public static function ip() {
		$header = self::opts()['ip_header'];
		$allowed = array( 'REMOTE_ADDR', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR' );

		if ( ! in_array( $header, $allowed, true ) ) {
			$header = 'REMOTE_ADDR';
		}

		$raw = isset( $_SERVER[ $header ] ) ? sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) ) : '';

		// X-Forwarded-For può contenere più indirizzi: vale il primo.
		$raw = trim( explode( ',', $raw )[0] );
		$ip  = filter_var( $raw, FILTER_VALIDATE_IP );

		if ( ! $ip && 'REMOTE_ADDR' !== $header ) {
			$ip = filter_var( isset( $_SERVER['REMOTE_ADDR'] ) ? wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '', FILTER_VALIDATE_IP );
		}

		return $ip ? $ip : '0.0.0.0';
	}

	/** Contatore a finestra fissa: restituisce il numero di richieste nella finestra corrente (già incrementato). */
	public static function hit( $bucket, $window ) {
		$key  = 'ss_' . md5( $bucket . '|' . self::ip() );
		$data = get_transient( $key );
		$now  = time();

		if ( ! is_array( $data ) || $now - (int) $data['t'] >= $window ) {
			$data = array(
				'n' => 0,
				't' => $now,
			);
		}

		++$data['n'];
		set_transient( $key, $data, max( 1, $window - ( $now - (int) $data['t'] ) ) );

		return $data['n'];
	}
}
