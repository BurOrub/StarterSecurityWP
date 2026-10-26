<?php
/**
 * XML-RPC disattivato, versione di WordPress nascosta, utenti non enumerabili, editor dei file disattivato.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Starter_Security_Hardening {

	public static function init() {
		add_action( 'init', array( __CLASS__, 'boot' ) );
		add_filter( 'map_meta_cap', array( __CLASS__, 'file_editor' ), 10, 2 );
	}

	public static function boot() {
		if ( Starter_Security::on( 'xmlrpc' ) ) {
			// Richiesta a xmlrpc.php: si chiude subito (anche system.multicall, usato per provare molte password in una richiesta).
			if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
				status_header( 403 );
				header( 'Content-Type: text/plain; charset=utf-8' );
				exit( 'XML-RPC disabilitato.' );
			}

			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array' );
			add_filter(
				'wp_headers',
				static function ( $headers ) {
					unset( $headers['X-Pingback'] );

					return $headers;
				}
			);
			remove_action( 'wp_head', 'rsd_link' );
		}

		if ( Starter_Security::on( 'version' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}

		if ( Starter_Security::on( 'users' ) ) {
			add_action( 'template_redirect', array( __CLASS__, 'block_author_query' ), 1 );
			add_filter( 'rest_endpoints', array( __CLASS__, 'hide_rest_users' ) );
			add_filter(
				'wp_sitemaps_add_provider',
				static function ( $provider, $name ) {
					return 'users' === $name ? false : $provider;
				},
				10,
				2
			);
		}
	}

	/** /?author=1 non deve rivelare lo username (di solito reindirizza a /author/nome/). */
	public static function block_author_query() {
		if ( is_user_logged_in() || ! isset( $_GET['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		global $wp_query;

		$wp_query->set_404();
		status_header( 404 );
		nocache_headers();
		include get_404_template();
		exit;
	}

	/** L'elenco utenti REST è per chi è collegato. */
	public static function hide_rest_users( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}

		foreach ( array_keys( $endpoints ) as $route ) {
			if ( 0 === strpos( $route, '/wp/v2/users' ) ) {
				unset( $endpoints[ $route ] );
			}
		}

		return $endpoints;
	}

	/** Niente editor di file di temi e plugin dall'admin. Gli aggiornamenti restano attivi. */
	public static function file_editor( $caps, $cap ) {
		if ( Starter_Security::on( 'file_edit' ) && in_array( $cap, array( 'edit_themes', 'edit_plugins', 'edit_files' ), true ) ) {
			return array( 'do_not_allow' );
		}

		return $caps;
	}
}
