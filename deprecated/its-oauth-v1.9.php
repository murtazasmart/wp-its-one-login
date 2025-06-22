<?php
/*
Plugin Name:  ITS OneLogin Auth for WordPress V1.1.0
Description:  Minimal ITS OneLogin authentication for WordPress. Only checks for authentication state, does not process user data.
Version:      1.1.0
Author:       Umoor Dakheliyah, Colombo
*/

// === CONFIGURATION ===
// define('ONLGN_TOKEN', 'AU68vf26spwX'); // Set your actual token here
define('ONLGN_SALT', 'ADD_THE_SALT_VALUE_HERE');

define('ONLGN_QUERY_VAR', 'onlgn_auth'); // Change this if you want a different query var

define('ONLGN_ALLOWED_REFERRERS', [
    'https://www.its52.com/',
    'https://its52.com/'
]);

// === GET ENDPOINT FROM DB OR DEFAULT ===
function onlgn_get_endpoint() {
    $endpoint = get_option('onlgn_endpoint', 'auth-ITS');
    // Sanitize: only allow alphanumeric, dashes, underscores
    $endpoint = preg_replace('/[^a-zA-Z0-9\-_]/', '', $endpoint);
    // If blank, use default
    return ($endpoint === '' || $endpoint === false) ? 'auth-ITS' : $endpoint;
}

// === GET TOKEN FROM DB OR DEFAULT ===
function onlgn_get_token() {
    $token = get_option('onlgn_token', 'AU68vf26spwX');
    $token = sanitize_text_field($token);
    return $token ? $token : 'AU68vf26spwX';
}

// === GET CODE FROM DB OR DEFAULT ===
function onlgn_get_code() {
    $code = get_option('onlgn_code', 'ABCDEF');
    $code = sanitize_text_field($code);
    return $code ? $code : 'ABCDEF';
}

// === DECRYPTION FUNCTION ===
function oneLoginDecryptData($cipherText) {
// Mcrypt is UNSECURE and depecated since PHP 7.1, using OpenSSL is recommended as it is resistant to time-replay and side-channel attacks
// Libsodium, the new defacto PHP cryptography library, does not support AES128 (as it is considerably weak), so we are stuck with OpenSSL

$token = 'B2Okawm9UKg4sF6RndzLXN7Ieq3PEbx0huGS1CZlJVrtcoAMYv8Tf'; // Change to the token issued to your domain

$key = openssl_pbkdf2($token, 'ADD_THE_SALT_VALUE_HERE', 32, 1000);
// 	$cipherText = urlencode($cipherText);
$cipherText = isUrlEncoded($cipherText) ? $cipherText : urlencode($cipherText);
// $key = hash_pbkdf2('SHA1', $key, 'ADD_THE_SALT_VALUE_HERE', 1000, 32, true);

return rtrim(mb_convert_encoding(openssl_decrypt(($cipherText), 'AES-128-CBC', substr($key, 0, 16), OPENSSL_ZERO_PADDING, substr($key, 16, 16)),'UTF-8', 'UTF-16LE'), "\0");
// return utf8_decode(trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_128, substr($key, 0, 16), base64_decode(urldecode($cipherText)), MCRYPT_MODE_CBC, substr($key, 16, 16))));
}

//TESTS - try on http://phptester.net/
$cipherText1 = 'R0%2fN7p96AX%2f6L9Uok8eUzlWtzmWntWNnCNE5SRlYACKJNGWCpNUYotmqkLt5NCpFIUDk2k3lbfbVKPiG8XSEoGhcvnqjP3RXaU8yBNs1WPyK%2ffLIlAMHk8%2bpPVKa2ejKi%2f1wRdL9denitCP9AetRua043syUwHBtSQf%2b3OZ2IUevmy%2bITzMOsP3nbh%2bxWfW7k6BwrT4SqSHJtmYbsIBtMQ%3d%3d';

function removeUnknownCharacters($text) {
    return preg_replace('/[\x{0A00}-\x{0AFF}]/u', '', $text);
}

function isUrlEncoded($str) {
    return urldecode($str) !== $str || preg_match('/%[0-9A-Fa-f]{2}/', $str);
}

function parseDecryptedToObject($plaintext) {
    $fields = explode(',', $plaintext);

    if (count($fields) !== 7) {
        return [
            'error' => 'Invalid field count',
            'raw' => $plaintext
        ];
    }

    return [
        'its_no'   => trim($fields[0]),
        'name'     => trim($fields[1]),
        'gender'   => trim($fields[2]),
        'age'      => trim($fields[3]),
        'city'     => trim($fields[4]),
        'jamiat'   => trim($fields[5]),
        'num'      => trim($fields[6]),
    ];
}

// === SESSION AUTH CHECK ===
function is_its_authenticated() {
    if (!session_id()) session_start();
    if (!empty($_SESSION['its_authenticated'])) {
        return true;
    }
    // Allow logged-in WP admins
    if (is_user_logged_in() && current_user_can('manage_options')) {
        return true;
    }
    return false;
}

function onlgn_sitewide_auth_check() {
    if (is_admin() || defined('DOING_AJAX') && DOING_AJAX) return; // Don't block admin or AJAX
    if (is_its_authenticated()) return;
    $endpoint = onlgn_get_endpoint();
    $req_uri = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');
    // If endpoint is blank, treat homepage as callback
    if ($endpoint === '' || $endpoint === false) {
        // Only skip redirect if all required params are present (i.e., it's a callback)
        if (isset($_GET['Token'], $_GET['DT'], $_GET['App']) && $_GET['App'] === 'ITSOnelogin') {
            return;
        }
        // Otherwise, this is a normal homepage visit, so continue with auth check
        if ($req_uri === '' || $req_uri === false) {
            if (!session_id()) session_start();
            $_SESSION['onlgn_redirect'] = (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
            $code = urlencode(onlgn_get_code());
            wp_redirect('https://www.its52.com/Login.aspx?OneLogin=' . $code);
            exit;
        }
    } else {
        // Don't block the auth endpoint itself
        if ($req_uri === $endpoint) return;
        if (!session_id()) session_start();
        $_SESSION['onlgn_redirect'] = (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        $code = urlencode(onlgn_get_code());
        wp_redirect('https://www.its52.com/Login.aspx?OneLogin=' . $code);
        exit;
    }
}
add_action('template_redirect', 'onlgn_sitewide_auth_check', 0);

// === AUTH CALLBACK HANDLER (MINIMAL, v1.1.0) ===
function onlgn_auth_callback() {
    // Only process if all required params are present
    if (!isset($_GET['Token'], $_GET['DT'], $_GET['App']) || $_GET['App'] !== 'ITSOnelogin') {
        onlgn_debug_log('Missing required parameters or invalid App value');
        return; // Let the homepage or endpoint load as normal
    }
    
    // Check referrer is from its52.com or colombo-relay
    $ref = isset($_SERVER['HTTP_REFERER']) ? strtolower($_SERVER['HTTP_REFERER']) : '';
    onlgn_debug_log('Referrer: ' . $ref);
    
    // Allow both its52.com and colombo-relay domains
    $allowed_domains = ['its52.com', 'colombo-relay.asharamubaraka.net'];
    $is_allowed = false;
    foreach ($allowed_domains as $domain) {
        if (strpos($ref, $domain) !== false) {
            $is_allowed = true;
            break;
        }
    }
    
    if (!$is_allowed) {
        onlgn_debug_log('Invalid referrer detected: ' . $ref);
        wp_die('Invalid referrer. Authentication must come from ITS52.com or Colombo Relay.', 'ITS OneLogin Error', ['response' => 403]);
    }
    
    if (!session_id()) session_start();
    $_SESSION['its_authenticated'] = true;
	error_log('IM HEREE' . print_r($_GET['DT'], true));
	$decryptedVal = parseDecryptedToObject(removeUnknownCharacters(oneLoginDecryptData($_GET['DT'])));
	error_log('Decrypted user: ' . print_r($decryptedVal, true));
	onlgn_debug_log('Encrypted DT is ', $_GET['DT']);
    onlgn_debug_log('Authentication successful, session set');
    
    // Redirect to original URL if available
    $redirect_url = isset($_SESSION['onlgn_redirect']) ? $_SESSION['onlgn_redirect'] : home_url();
    onlgn_debug_log('Redirecting to: ' . $redirect_url);
    unset($_SESSION['onlgn_redirect']);
    wp_redirect($redirect_url);
    exit;
}

// === REGISTER ENDPOINT ===
function onlgn_register_auth_endpoint() {
    // Add rewrite rule for both the configured endpoint and auth-ITS
    add_rewrite_rule('^' . onlgn_get_endpoint() . '/?$', 'index.php?' . ONLGN_QUERY_VAR . '=1', 'top');
    // Also add a specific rule for auth-ITS to ensure it works
    if (onlgn_get_endpoint() !== 'auth-ITS') {
        add_rewrite_rule('^auth-ITS/?$', 'index.php?' . ONLGN_QUERY_VAR . '=1', 'top');
    }
}
add_action('init', 'onlgn_register_auth_endpoint');

function onlgn_query_vars($vars) {
    $vars[] = ONLGN_QUERY_VAR;
    return $vars;
}
add_filter('query_vars', 'onlgn_query_vars');

function onlgn_parse_request($wp) {
    if (array_key_exists(ONLGN_QUERY_VAR, $wp->query_vars)) {
        onlgn_auth_callback();
    }
}
add_action('parse_request', 'onlgn_parse_request');

// === SETTINGS PAGE ===
function onlgn_settings_menu() {
    add_options_page('ITS OneLogin Settings', 'ITS OneLogin', 'manage_options', 'onlgn-settings', 'onlgn_settings_page');
}
add_action('admin_menu', 'onlgn_settings_menu');

function onlgn_settings_page() {
    if (!current_user_can('manage_options')) return;
    $notice = '';
    if (isset($_POST['onlgn_endpoint']) || isset($_POST['onlgn_token']) || isset($_POST['onlgn_code'])) {
        $endpoint = isset($_POST['onlgn_endpoint']) ? sanitize_text_field($_POST['onlgn_endpoint']) : onlgn_get_endpoint();
        $endpoint = preg_replace('/[^a-zA-Z0-9\-_]/', '', $endpoint);
        $token = isset($_POST['onlgn_token']) ? sanitize_text_field($_POST['onlgn_token']) : onlgn_get_token();
        $code = isset($_POST['onlgn_code']) ? sanitize_text_field($_POST['onlgn_code']) : onlgn_get_code();
        // Allow blank endpoint, but use default internally
        if (!$token) {
            $notice = '<div class="notice notice-error"><p>Token cannot be empty.</p></div>';
        } elseif (!$code) {
            $notice = '<div class="notice notice-error"><p>OneLogin code cannot be empty.</p></div>';
        } else {
            update_option('onlgn_endpoint', $endpoint);
            update_option('onlgn_token', $token);
            update_option('onlgn_code', $code);
            flush_rewrite_rules();
            $notice = '<div class="notice notice-success is-dismissible"><p>Settings updated! New endpoint: <code>' . esc_html(($endpoint === '' ? 'onlgn-auth (default)' : $endpoint)) . '</code> &mdash; Token and code updated.</p></div>';
        }
    }
    $current = esc_attr(get_option('onlgn_endpoint', 'onelogin-auth'));
    $current_token = esc_attr(onlgn_get_token());
    $current_code = esc_attr(onlgn_get_code());
    echo '<div class="wrap"><h1>ITS OneLogin Settings</h1>';
    echo $notice;
    echo '<form method="post">';
    echo '<table class="form-table">';
    echo '<tr><th scope="row"><label for="onlgn_endpoint">Authentication Endpoint Slug</label></th>';
    echo '<td><input name="onlgn_endpoint" id="onlgn_endpoint" type="text" value="' . $current . '" class="regular-text" />';
    echo '<p class="description">This will be the URL slug for the authentication endpoint (e.g., <code>' . home_url('/') . ($current === '' ? 'onelogin-auth' : $current) . '</code>). Leave blank to use the default (<code>onelogin-auth</code>).</p></td></tr>';
    echo '<tr><th scope="row"><label for="onlgn_token">OneLogin Token</label></th>';
    echo '<td><input name="onlgn_token" id="onlgn_token" type="text" value="' . $current_token . '" class="regular-text" />';
    echo '<p class="description">This is the secret token used for decryption. Keep it safe!</p></td></tr>';
    echo '<tr><th scope="row"><label for="onlgn_code">OneLogin Code</label></th>';
    echo '<td><input name="onlgn_code" id="onlgn_code" type="text" value="' . $current_code . '" class="regular-text" />';
    echo '<p class="description">This is the code passed to its52.com via Variable OneLogin.</p></td></tr>';
    echo '</table>';
    submit_button('Save Changes');
    echo '</form></div>';
}

// === ADMIN NOTICE FOR PERMALINKS ===
function onlgn_admin_notice() {
    if (!get_option('onlgn_permalinks_flushed')) {
        echo '<div class="notice notice-warning is-dismissible"><p><strong>ITS OneLogin Clean Auth:</strong> Please go to <a href="/wp-admin/options-permalink.php">Settings > Permalinks</a> and click "Save Changes" to activate the authentication endpoint.</p></div>';
        update_option('onlgn_permalinks_flushed', 1);
    }
}
add_action('admin_notices', 'onlgn_admin_notice');

function onlgn_debug_log($msg) {
    if (get_option('onlgn_debug', false)) {
        if (is_array($msg) || is_object($msg)) {
            $msg = print_r($msg, true);
        }
        error_log('[ITS OneLogin] ' . $msg);
    }
    
    // Always log critical errors regardless of debug setting
    if (strpos($msg, 'ERROR:') === 0) {
        error_log('[ITS OneLogin CRITICAL] ' . $msg);
    }
}

?>