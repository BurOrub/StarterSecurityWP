<?php
/**
 * Header di sicurezza HTTP e Content Security Policy in solo report.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Starter_Security_Headers {

	const LOG = 'starter_security_csp_log';

	public static function init() {
		add_action( 'send_headers', array( __CLASS__, 'send' ) );
		add_action( 'rest_api_init', array( __CLASS__, 'routes' ) );
	}

	public static function send() {
		if ( is_admin() || headers_sent() ) {
			return;
		}

		if ( Starter_Security::on( 'headers' ) ) {
			header( 'X-Content-Type-Options: nosniff' );
			header( 'X-Frame-Options: SAMEORIGIN' );
			header( 'Referrer-Policy: strict-origin-when-cross-origin' );
			header( 'Permissions-Policy: camera=(), microphone=(), geolocation=()' );

			if ( Starter_Security::on( 'hsts' ) && is_ssl() ) {
				header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
			}
		}

		if ( 'report' === Starter_Security::opts()['csp'] ) {
			header( 'Content-Security-Policy-Report-Only: ' . self::policy() );
		}
	}

	/** Policy di partenza: cosa usa il tema (Google Fonts, GSAP/Lenis da CDN, YouTube/Vimeo, mappe, CookieYes, analytics). Modificabile con il filtro. */
	public static function policy() {
		$sources = apply_filters(
			'starter_security_csp',
			array(
				'default-src'     => array( "'self'" ),
				'script-src'      => array( "'self'", "'unsafe-inline'", 'https://cdn-cookieyes.com', 'https://www.googletagmanager.com', 'https://www.google-analytics.com', 'https://www.youtube.com', 'https://player.vimeo.com' ),
				'style-src'       => array( "'self'", "'unsafe-inline'", 'https://fonts.googleapis.com' ),
				'font-src'        => array( "'self'", 'data:', 'https://fonts.gstatic.com' ),
				'img-src'         => array( "'self'", 'data:', 'blob:', 'https:' ),
				'media-src'       => array( "'self'", 'blob:', 'https:' ),
				'frame-src'       => array( "'self'", 'https://www.youtube.com', 'https://www.youtube-nocookie.com', 'https://player.vimeo.com', 'https://www.google.com', 'https://maps.google.com' ),
				'connect-src'     => array( "'self'", 'https://www.google-analytics.com', 'https://region1.google-analytics.com', 'https://log.cookieyes.com', 'https://cdn-cookieyes.com' ),
				'object-src'      => array( "'none'" ),
				'base-uri'        => array( "'self'" ),
				'form-action'     => array( "'self'" ),
				'frame-ancestors' => array( "'self'" ),
			)
		);

		$parts = array();

		foreach ( $sources as $directive => $values ) {
			$parts[] = $directive . ' ' . implode( ' ', $values );
		}

		$parts[] = 'report-uri ' . esc_url_raw( rest_url( 'starter-security/v1/csp-report' ) );

		return implode( '; ', $parts );
	}

	public static function routes() {
		register_rest_route(
			'starter-security/v1',
			'/csp-report',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'collect' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/** Riceve le segnalazioni del browser: poche, brevi e raggruppate per direttiva + origine bloccata. */
	public static function collect( WP_REST_Request $request ) {
		if ( 'report' !== Starter_Security::opts()['csp'] || Starter_Security::hit( 'csp', 600 ) > 30 ) {
			return new WP_REST_Response( null, 204 );
		}

		$body = $request->get_body();

		if ( strlen( $body ) > 8192 ) {
			return new WP_REST_Response( null, 204 );
		}

		$data   = json_decode( $body, true );
		$report = is_array( $data ) && isset( $data['csp-report'] ) && is_array( $data['csp-report'] ) ? $data['csp-report'] : array();

		if ( ! $report ) {
			return new WP_REST_Response( null, 204 );
		}

		$directive = isset( $report['effective-directive'] ) ? $report['effective-directive'] : ( isset( $report['violated-directive'] ) ? $report['violated-directive'] : '' );
		$blocked   = isset( $report['blocked-uri'] ) ? (string) $report['blocked-uri'] : '';
		$parts     = wp_parse_url( $blocked );

		// Di un indirizzo si tiene solo l'origine (niente percorsi o parametri).
		if ( ! empty( $parts['host'] ) ) {
			$blocked = ( isset( $parts['scheme'] ) ? $parts['scheme'] . '://' : '' ) . $parts['host'];
		}

		$directive = substr( sanitize_text_field( (string) $directive ), 0, 60 );
		$blocked   = substr( sanitize_text_field( $blocked ), 0, 120 );
		$page      = isset( $report['document-uri'] ) ? wp_parse_url( (string) $report['document-uri'], PHP_URL_PATH ) : '';
		$page      = substr( sanitize_text_field( (string) $page ), 0, 120 );

		if ( '' === $directive ) {
			return new WP_REST_Response( null, 204 );
		}

		$log = get_option( self::LOG, array() );
		$log = is_array( $log ) ? $log : array();
		$key = md5( $directive . '|' . $blocked );

		if ( isset( $log[ $key ] ) ) {
			++$log[ $key ]['count'];
			$log[ $key ]['last'] = time();
			$log[ $key ]['page'] = $page;
		} elseif ( count( $log ) < 60 ) {
			$log[ $key ] = array(
				'directive' => $directive,
				'blocked'   => $blocked,
				'page'      => $page,
				'count'     => 1,
				'last'      => time(),
			);
		}

		update_option( self::LOG, $log, false );

		return new WP_REST_Response( null, 204 );
	}
}
