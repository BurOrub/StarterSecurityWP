<?php
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once __DIR__ . '/includes/class-core.php';
require_once __DIR__ . '/includes/class-uploads.php';

Starter_Security_Uploads::remove();
delete_option( 'starter_security' );
delete_option( 'starter_security_csp_log' );
delete_option( 'starter_security_uploads_sig' );
