<?php
/**
 * Plugin Name: Starter Security
 * Description: Protezioni di base per i siti costruiti con il Tema Starter: header di sicurezza, CSP in solo report, XML-RPC e utenti nascosti, login protetto, limiti alle API pubbliche. Ogni misura si attiva e disattiva da Impostazioni > Starter Security.
 * Version: 0.1.0
 * Requires at least: 6.4
 * Requires PHP: 7.4
 * Author: Denis Burani
 * License: GPL-2.0-or-later
 * Text Domain: starter-security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'STARTER_SECURITY_VERSION', '0.1.0' );
define( 'STARTER_SECURITY_FILE', __FILE__ );

require_once __DIR__ . '/includes/class-core.php';
require_once __DIR__ . '/includes/class-headers.php';
require_once __DIR__ . '/includes/class-hardening.php';
require_once __DIR__ . '/includes/class-login.php';
require_once __DIR__ . '/includes/class-uploads.php';
require_once __DIR__ . '/includes/class-ratelimit.php';
require_once __DIR__ . '/includes/class-admin.php';

Starter_Security_Headers::init();
Starter_Security_Hardening::init();
Starter_Security_Login::init();
Starter_Security_Uploads::init();
Starter_Security_RateLimit::init();
Starter_Security_Admin::init();

register_deactivation_hook( __FILE__, array( 'Starter_Security_Uploads', 'remove' ) );
