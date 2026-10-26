<?php
/**
 * Limiti alle API pubbliche: ricerca, preferiti, invio dei moduli Contact Form 7.
 * Soglie larghe: un utente normale non le raggiunge. Modificabili con il filtro starter_security_rate_limits.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Starter_Security_RateLimit {

	/** Richieste massime per finestra (secondi). */
	private static function limits() {
		return apply_filters(
			'starter_security_rate_limits',
			array(
				'search'   => array( 90, 60 ),
				'wishlist' => array( 90, 60 ),
				'cf7'      => array( 10, 600 ),
			)
		);
	}

	public static function init() {
		add_filter( 'rest_pre_dispatch', array( __CLASS__, 'rest' ), 10, 3 );
		add_action( 'wp_ajax_nopriv_starter_wishlist', array( __CLASS__, 'ajax' ), 1 );
		add_action( 'wp_ajax_starter_wishlist', array( __CLASS__, 'ajax' ), 1 );
		add_action( 'wp_ajax_nopriv_starter_wishlist_tip', array( __CLASS__, 'ajax' ), 1 );
		add_action( 'wp_ajax_starter_wishlist_tip', array( __CLASS__, 'ajax' ), 1 );
	}

	private static function over( $bucket ) {
		$limits = self::limits();

		if ( ! Starter_Security::on( 'rate_limit' ) || empty( $limits[ $bucket ] ) ) {
			return false;
		}

		return Starter_Security::hit( $bucket, (int) $limits[ $bucket ][1] ) > (int) $limits[ $bucket ][0];
	}

	public static function rest( $result, $server, $request ) {
		$route  = $request->get_route();
		$bucket = '';

		if ( '/starter/v1/search' === $route ) {
			$bucket = 'search';
		} elseif ( 'POST' === $request->get_method() && preg_match( '#^/contact-form-7/v1/contact-forms/\d+/feedback$#', $route ) ) {
			$bucket = 'cf7';
		}

		if ( $bucket && self::over( $bucket ) ) {
			return new WP_Error( 'starter_rate_limited', __( 'Troppe richieste. Riprova tra poco.', 'starter-security' ), array( 'status' => 429 ) );
		}

		return $result;
	}

	public static function ajax() {
		if ( self::over( 'wishlist' ) ) {
			status_header( 429 );
			wp_send_json_error( array( 'message' => __( 'Troppe richieste. Riprova tra poco.', 'starter-security' ) ), 429 );
		}
	}
}
