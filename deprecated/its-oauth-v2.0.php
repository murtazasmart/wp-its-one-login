<?php
/*
Plugin Name:  ITS OneLogin Auth for WordPress V1.1.0
Description:  Integrates the ITS OneLogin authentication system with WordPress, providing secure user authentication via ITS52 OAuth services. Securely processes user data fields returned from ITS52 and stores them encrypted in session and browser storage. Features include configurable endpoints, secure data encryption, and seamless user verification. Ideal for organizations seeking to implement single sign-on capabilities while maintaining security and compliance.
Version:      2.2.0
Author:       Umoor Dakheliyah, Colombo
*/

// === CONFIGURATION ===
define('ONLGN_SALT', 'ADD_THE_SALT_VALUE_HERE');
// Encryption key now stored in database and retrieved via function

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

// === GET ENCRYPTION KEY FROM DB OR GENERATE ===
function onlgn_get_encryption_key() {
    $key = get_option('onlgn_encryption_key', '');
    
    // If no key exists, generate a secure random one and save it
    if (empty($key)) {
        // Generate a secure random key (64 chars = 384 bits, more than enough for AES-256)
        $key = bin2hex(openssl_random_pseudo_bytes(32));
        update_option('onlgn_encryption_key', $key);
    }
    
    return $key;
}

// === DECRYPTION FUNCTION ===
function oneLoginDecryptData($cipherText) {
    // Using OpenSSL for decryption (safer than deprecated Mcrypt)
    // Note: Libsodium doesn't support AES128, so we're using OpenSSL which handles time-replay and side-channel attacks
    
    // Get token from database instead of hardcoding
    $token = onlgn_get_token();
    
    // Use the salt constant defined at the top of the file
    $salt = ONLGN_SALT;
    
    // Generate the key using PBKDF2
    $key = openssl_pbkdf2($token, $salt, 32, 1000);
    
    // Ensure the cipher text is URL encoded
    $cipherText = isUrlEncoded($cipherText) ? $cipherText : urlencode($cipherText);
    
    // Decrypt using AES-128-CBC, then convert from UTF-16LE to UTF-8 and trim null bytes
    return rtrim(mb_convert_encoding(
        openssl_decrypt(
            ($cipherText), 
            'AES-128-CBC', 
            substr($key, 0, 16), 
            OPENSSL_ZERO_PADDING, 
            substr($key, 16, 16)
        ),
        'UTF-8', 
        'UTF-16LE'
    ), "\0");
}

/**
 * Remove specific Unicode character ranges that could cause issues
 * 
 * @param string $text Text to clean
 * @return string Cleaned text
 */
function removeUnknownCharacters($text) {
    return preg_replace('/[\x{0A00}-\x{0AFF}]/u', '', $text);
}

/**
 * Check if a string is URL encoded
 * 
 * @param string $str String to check
 * @return bool True if URL encoded
 */
function isUrlEncoded($str) {
    return urldecode($str) !== $str || preg_match('/%[0-9A-Fa-f]{2}/', $str);
}

/**
 * Parse decrypted data into a structured object
 * 
 * @param string $plaintext Decrypted comma-separated data
 * @return array Structured data object with user details or error information
 */
function parseDecryptedToObject($plaintext) {
    $fields = explode(',', $plaintext);

    // Verify data format - should have 7 fields
    if (count($fields) !== 7) {
        return [
            'error' => 'Invalid field count',
            'raw'   => $plaintext
        ];
    }

    // Map fields to a structured object
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
/**
 * Check if a user is authenticated through ITS login or is a WordPress admin
 * 
 * @return bool True if user is authenticated
 */
function is_its_authenticated() {
    // Start session if not already started
    if (!session_id()) {
        session_start();
    }
    
    // Check if session has authenticated flag
    if (!empty($_SESSION['its_authenticated2'])) {
        return true;
    }
    
    // Allow WordPress admins to bypass authentication
    if (function_exists('is_user_logged_in') && function_exists('current_user_can')) {
        if (is_user_logged_in() && current_user_can('manage_options')) {
            return true;
        }
    }
    
    // Also check if we have user data as a secondary authentication method
    return has_user_data('its_authenticated2');
}

/**
 * Check authentication status and redirect to login if not authenticated
 * Runs on every page load via template_redirect action hook
 */
function onlgn_sitewide_auth_check() {
    // Skip check for admin pages and AJAX requests
    if (is_admin() || defined('DOING_AJAX') && DOING_AJAX) {
        return;
    }
    
    // Allow if already authenticated
    if (is_its_authenticated()) {
        return;
    }
    
    $endpoint = onlgn_get_endpoint();
    $req_uri = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');
    // If endpoint is blank, treat homepage as callback
    if ($endpoint === '' || $endpoint === false) {
        // Skip redirect if this request appears to be a callback from OneLogin
        if (isset($_GET['Token'], $_GET['DT'], $_GET['App']) && $_GET['App'] === 'ITSOnelogin') {
            return;
        }
        // Otherwise, this is a normal homepage visit, so continue with auth check
        if ($req_uri === '' || $req_uri === false) {
            if (!session_id()) {
                session_start();
            }
            
            // Store current URL for post-login redirect
            $_SESSION['onlgn_redirect'] = (is_ssl() ? 'https://' : 'http://') . 
                                          $_SERVER['HTTP_HOST'] . 
                                          $_SERVER['REQUEST_URI'];
            
            // Redirect to ITS52 login with site code
            $code = urlencode(onlgn_get_code());
            wp_redirect('https://www.its52.com/Login.aspx?OneLogin=' . $code);
            exit;
        }
    } else {
        // Don't block access to the auth endpoint itself
        if ($req_uri === $endpoint) {
            return;
        }
        
        // Start session if needed
        if (!session_id()) {
            session_start();
        }
        
        // Store current URL for post-login redirect
        $_SESSION['onlgn_redirect'] = (is_ssl() ? 'https://' : 'http://') . 
                                      $_SERVER['HTTP_HOST'] . 
                                      $_SERVER['REQUEST_URI'];
        
        // Redirect to ITS52 login
        $code = urlencode(onlgn_get_code());
        wp_redirect('https://www.its52.com/Login.aspx?OneLogin=' . $code);
        exit;
    }
}
// Action and filter hooks moved to the bottom of the file for better organization

// === AUTH CALLBACK HANDLER (MINIMAL, v1.1.0) ===
/**
 * Process authentication callback from ITS52.com
 * Validates the request, sets authentication session, and redirects to original URL
 */
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
    
    // Reject requests from unauthorized domains
    if (!$is_allowed) {
        onlgn_debug_log('Invalid referrer detected: ' . $ref);
        wp_die('Invalid referrer. Authentication must come from ITS52.com or Colombo Relay.', 'ITS OneLogin Error', ['response' => 403]);
    }
    
    if (!session_id()) session_start();
    $_SESSION['its_authenticated2'] = true;
    
    // Process and log the encrypted data
    $decryptedVal = parseDecryptedToObject(
        removeUnknownCharacters(
            oneLoginDecryptData($_GET['DT'])
        )
    );
    onlgn_debug_log('Encrypted DT is ', $_GET['DT']);
    onlgn_debug_log('Decrypted DT is ', $decryptedVal);
    
    // Store decrypted values in PHP session and cookies for persistence
    if (!isset($decryptedVal['error'])) {
        // Store in session for server-side access during this session
        $_SESSION['its_user_data'] = encrypt($decryptedVal);
        $_SESSION['its_no'] = encrypt($decryptedVal['its_no']);
        $_SESSION['its_name'] = encrypt($decryptedVal['name']);
        $_SESSION['its_gender'] = encrypt($decryptedVal['gender']);
        $_SESSION['its_age'] = encrypt($decryptedVal['age']);
        $_SESSION['its_city'] = encrypt($decryptedVal['city']);
        $_SESSION['its_jamiat'] = encrypt($decryptedVal['jamiat']);
        $_SESSION['its_num'] = encrypt($decryptedVal['num']);
        $_SESSION['user'] = $decryptedVal['its_no'];
        $_SESSION['profile'] = $decryptedVal['its_no'];
        
        // Set cookies to persist user data
        $cookie_expire = time() + (86400 * 30); // 30 days
        $cookie_path = '/';
        $cookie_domain = onlgn_get_root_domain(); // Will now include leading dot for domain-wide sharing
        // Check for HTTPS - using both is_ssl() WordPress function and manual check
        $cookie_secure = (function_exists('is_ssl') && is_ssl()) || 
                        (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') || 
                        (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);
        $cookie_httponly = true; // Not accessible via JavaScript
        
        onlgn_debug_log('Setting cookies with domain-wide sharing: ' . $cookie_domain);
        
        // Set individual cookies for each field
        setcookie('its_no', encrypt($decryptedVal['its_no']), $cookie_expire, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly);
        setcookie('its_name', encrypt($decryptedVal['name']), $cookie_expire, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly);
        setcookie('its_gender', encrypt($decryptedVal['gender']), $cookie_expire, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly);
        setcookie('its_age', encrypt($decryptedVal['age']), $cookie_expire, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly);
        setcookie('its_city', encrypt($decryptedVal['city']), $cookie_expire, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly);
        setcookie('its_jamiat', encrypt($decryptedVal['jamiat']), $cookie_expire, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly);
        setcookie('its_num', encrypt($decryptedVal['num']), $cookie_expire, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly);
        setcookie('user', $decryptedVal['its_no'], $cookie_expire, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly);
        setcookie('profile', $decryptedVal['its_no'], $cookie_expire, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly);
        
        // Save the full user data in a JSON-encoded cookie
        setcookie('its_user_data', json_encode($decryptedVal), $cookie_expire, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly);
        
        onlgn_debug_log('User data stored in session and cookies with domain-level sharing');
    } else {
        onlgn_debug_log('ERROR: Failed to parse user data: ' . print_r($decryptedVal, true));
    }
    
    onlgn_debug_log('Authentication successful, session set');
    
    // Redirect to original URL if available
    $redirect_url = isset($_SESSION['onlgn_redirect']) ? $_SESSION['onlgn_redirect'] : home_url();
    onlgn_debug_log('Redirecting to: ' . $redirect_url);
    unset($_SESSION['onlgn_redirect']);
    wp_redirect($redirect_url);
    exit;
}

// === REGISTER ENDPOINT ===
/**
 * Register the authentication endpoint URLs with WordPress
 * Creates rewrite rules for both the custom and default endpoints
 */
function onlgn_register_auth_endpoint() {
    // Add rewrite rule for configured endpoint
    add_rewrite_rule(
        '^' . onlgn_get_endpoint() . '/?$', 
        'index.php?' . ONLGN_QUERY_VAR . '=1', 
        'top'
    );
    
    // Also add a fallback rule for the default auth-ITS endpoint
    if (onlgn_get_endpoint() !== 'auth-ITS') {
        add_rewrite_rule(
            '^auth-ITS/?$', 
            'index.php?' . ONLGN_QUERY_VAR . '=1', 
            'top'
        );
    }
}
// Action hooks moved to bottom of file

function onlgn_query_vars($vars) {
    $vars[] = ONLGN_QUERY_VAR;
    return $vars;
}
// Filter hooks moved to bottom of file

function onlgn_parse_request($wp) {
    // Check if this is a direct request to our auth endpoint
    if (array_key_exists(ONLGN_QUERY_VAR, $wp->query_vars)) {
        onlgn_auth_callback();
        return;
    }
    
    // Also check if this is a homepage request with the OneLogin parameters
    // This allows the auth callback to work on the homepage
    if (
        // Check if we're on the homepage
        (empty($wp->request) || $wp->request === '/') &&
        // Check if we have all required auth parameters
        isset($_GET['Token'], $_GET['DT'], $_GET['App']) && 
        $_GET['App'] === 'ITSOnelogin'
    ) {
        onlgn_debug_log('Homepage auth callback detected');
        onlgn_auth_callback();
    }
}
// Action hooks moved to bottom of file

// === SETTINGS PAGE ===
// Admin menu registration moved to onlgn_register_admin_menu function

/**
 * Renders the settings page for ITS OneLogin
 * Includes endpoint configuration and security settings
 */
function onlgn_settings_page() {
    // Check if user has permission to access settings
    if (function_exists('current_user_can') && !current_user_can('manage_options')) return;
    
    $notice = '';
    
    // Process general settings form submission
    if (isset($_POST['onlgn_endpoint']) || isset($_POST['onlgn_token']) || isset($_POST['onlgn_code'])) {
        $endpoint = isset($_POST['onlgn_endpoint']) ? (function_exists('sanitize_text_field') ? sanitize_text_field($_POST['onlgn_endpoint']) : $_POST['onlgn_endpoint']) : onlgn_get_endpoint();
        $endpoint = preg_replace('/[^a-zA-Z0-9\-_]/', '', $endpoint);
        $token = isset($_POST['onlgn_token']) ? (function_exists('sanitize_text_field') ? sanitize_text_field($_POST['onlgn_token']) : $_POST['onlgn_token']) : onlgn_get_token();
        $code = isset($_POST['onlgn_code']) ? (function_exists('sanitize_text_field') ? sanitize_text_field($_POST['onlgn_code']) : $_POST['onlgn_code']) : onlgn_get_code();
        $debug_mode = isset($_POST['onlgn_debug']) ? (bool)$_POST['onlgn_debug'] : false;
        
        // Allow blank endpoint, but use default internally
        if (!$token) {
            $notice = '<div class="notice notice-error"><p>Token cannot be empty.</p></div>';
        } elseif (!$code) {
            $notice = '<div class="notice notice-error"><p>OneLogin code cannot be empty.</p></div>';
        } else {
            if (function_exists('update_option')) {
                update_option('onlgn_endpoint', $endpoint);
                update_option('onlgn_token', $token);
                update_option('onlgn_code', $code);
                update_option('onlgn_debug', $debug_mode);
                
                // Flush rewrite rules if available
                if (function_exists('flush_rewrite_rules')) {
                    flush_rewrite_rules();
                }
            }
            
            $endpoint_display = $endpoint === '' ? 'onlgn-auth (default)' : $endpoint;
            $notice = '<div class="notice notice-success is-dismissible"><p>Settings updated! New endpoint: <code>' . 
                (function_exists('esc_html') ? esc_html($endpoint_display) : $endpoint_display) . 
                '</code> &mdash; Token and code updated.</p></div>';
        }
    }
    
    // Get current values
    $endpoint = onlgn_get_endpoint();
    $token = onlgn_get_token();
    $code = onlgn_get_code();
    $encryption_key = onlgn_get_encryption_key();
    $debug_mode = function_exists('get_option') ? get_option('onlgn_debug', false) : false;
    
    // Removed duplicate key generation code since we only use the Reset Key functionality
    
    // Handle key reset confirmation and action
    if (isset($_GET['confirm_reset']) && $_GET['confirm_reset'] == '1') {
        $reset_url = function_exists('admin_url') && function_exists('wp_create_nonce') ? 
            admin_url('options-general.php?page=its-onelogin-settings&reset_key=1&_wpnonce=' . wp_create_nonce('reset_encryption_key')) : 
            '?page=its-onelogin-settings&reset_key=1';
        
        $cancel_url = function_exists('admin_url') ? 
            admin_url('options-general.php?page=its-onelogin-settings') : 
            '?page=its-onelogin-settings';
        
        $notice = '<div class="error"><p>Warning: Resetting the encryption key will make all currently encrypted data inaccessible. This cannot be undone.<br>' . 
            '<a href="' . $reset_url . '" class="button button-primary">Yes, Reset Encryption Key</a> ' . 
            '<a href="' . $cancel_url . '" class="button">Cancel</a></p></div>';
    }
    
    // Reset encryption key if confirmed
    if (isset($_GET['reset_key']) && $_GET['reset_key'] == '1' && 
        ((function_exists('wp_verify_nonce') && isset($_GET['_wpnonce']) && wp_verify_nonce($_GET['_wpnonce'], 'reset_encryption_key')) || !function_exists('wp_verify_nonce'))) {
        if (function_exists('delete_option')) {
            delete_option('onlgn_encryption_key');
        }
        $encryption_key = onlgn_get_encryption_key(); // This will generate a new key
        
        // Set a transient to show the success message after redirect
        if (function_exists('set_transient')) {
            set_transient('onlgn_key_reset', true, 30); // 30 seconds expiration
        }
        
        // Redirect to clean URL
        if (function_exists('wp_redirect') && function_exists('admin_url')) {
            wp_redirect(admin_url('options-general.php?page=its-onelogin-settings'));
            exit();
        } else {
            // Fallback for environments where wp_redirect isn't available
            $notice = '<div class="updated"><p>Encryption key has been reset. A new key has been generated.</p></div>';
        }
    }
    
    // Check for transient indicating a successful key reset
    if (function_exists('get_transient') && get_transient('onlgn_key_reset')) {
        delete_transient('onlgn_key_reset');
        $notice = '<div class="updated"><p>Encryption key has been reset. A new key has been generated.</p></div>';
    }
    
    // Escape attributes safely if the function exists
    $esc_endpoint = function_exists('esc_attr') ? esc_attr($endpoint) : $endpoint;
    $esc_token = function_exists('esc_attr') ? esc_attr($token) : $token;
    $esc_code = function_exists('esc_attr') ? esc_attr($code) : $code;
    $esc_encryption_key = function_exists('esc_attr') ? esc_attr($encryption_key) : $encryption_key;
    
    // Display the settings form
    ?>
    <div class="wrap">
        <h1>ITS OneLogin Settings</h1>
        <div class="about-description" style="margin: 15px 0;">
            <p>Integrates the ITS OneLogin authentication system with WordPress, providing secure user authentication via ITS52 OAuth services.</p>
            <p>Securely processes user data fields returned from ITS52 and stores them encrypted in session and browser storage.</p>
            <p><strong>Version:</strong> 2.2.0 | <strong>Author:</strong> Umoor Dakheliyah, Colombo</p>
        </div>
        <?php echo $notice; ?>
        <form method="post" action="">
            <?php if (function_exists('settings_fields')) settings_fields('onlgn_settings'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="onlgn_endpoint">ITS OneLogin Auth Endpoint</label></th>
                    <td>
                        <input type="text" name="onlgn_endpoint" id="onlgn_endpoint" value="<?php echo $esc_endpoint; ?>" class="regular-text">
                        <p class="description">The endpoint slug for authentication callbacks (e.g., "auth-ITS")</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="onlgn_token">ITS OneLogin API Token</label></th>
                    <td>
                        <input type="text" name="onlgn_token" id="onlgn_token" value="<?php echo $esc_token; ?>" class="regular-text">
                        <p class="description">The token for ITS OneLogin API authentication</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="onlgn_code">ITS OneLogin App Code</label></th>
                    <td>
                        <input type="text" name="onlgn_code" id="onlgn_code" value="<?php echo $esc_code; ?>" class="regular-text">
                        <p class="description">The application code</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="onlgn_encryption_key">Encryption Key for User Data</label></th>
                    <td>
                        <input type="text" name="onlgn_encryption_key" id="onlgn_encryption_key" value="<?php echo $esc_encryption_key; ?>" class="regular-text" readonly>
                        <p class="description">The encryption key used for storing user data securely. <strong>This is automatically generated and should not be changed manually.</strong></p>
                        <div style="margin-top: 10px;">
                            <a href="<?php echo function_exists('admin_url') ? admin_url('options-general.php?page=its-onelogin-settings&confirm_reset=1') : '?page=its-onelogin-settings&confirm_reset=1'; ?>" class="button button-secondary">Reset Encryption Key</a>
                        </div>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="onlgn_debug">Debug Mode</label></th>
                    <td>
                        <label>
                            <input type="checkbox" name="onlgn_debug" id="onlgn_debug" value="1" <?php if (function_exists('checked')) checked($debug_mode, true); ?>>
                            Enable debug logging
                        </label>
                        <p class="description">If enabled, debug information will be logged to the error log</p>
                    </td>
                </tr>
            </table>
            <?php if (function_exists('submit_button')) submit_button(); else echo '<input type="submit" class="button button-primary" value="Save Changes">'; ?>
        </form>
        
        <div class="card" style="max-width: 100%; margin-top: 20px; padding: 0 20px 20px;">
            <h2>Developer Guide - Using Encryption Functions</h2>
            <p>The following encryption and decryption functions are available to securely handle user data from ITS52:</p>
            
            <div class="ide-container" style="position: relative; border-radius: 6px; box-shadow: 0 3px 10px rgba(0,0,0,0.15); margin: 20px 0; overflow: hidden;">
                <div class="ide-header" style="background: #1e1e1e; color: white; padding: 8px 15px; font-size: 14px; font-weight: bold; display: flex; justify-content: space-between; align-items: center;">
                    <div>encryption-functions.php</div>
                    <div style="display: flex; gap: 8px;">
                        <span style="height: 12px; width: 12px; background-color: #ff5f56; border-radius: 50%; display: inline-block;"></span>
                        <span style="height: 12px; width: 12px; background-color: #ffbd2e; border-radius: 50%; display: inline-block;"></span>
                        <span style="height: 12px; width: 12px; background-color: #27c93f; border-radius: 50%; display: inline-block;"></span>
                    </div>
                </div>
                <div class="code-content" style="display: flex; height: 400px;">
                    <div class="line-numbers" style="user-select: none; text-align: right; padding: 10px 8px; color: #858585; background: #252525; min-width: 30px; font-family: 'Consolas', 'Monaco', 'Courier New', monospace; font-size: 13px; line-height: 1.5;">
                        <?php for($i=1; $i<=65; $i++) echo $i . "<br>"; ?>
                    </div>
                    <div class="code-area" style="background: #1e1e1e; flex-grow: 1; overflow: auto; padding: 10px 0;">
                        <pre style="margin: 0; padding: 0 15px; font-family: 'Consolas', 'Monaco', 'Source Code Pro', monospace; font-size: 13px; line-height: 1.5; tab-size: 4; color: #d4d4d4;"><code>

<span style="color: #569cd6;">/**
 * Decrypt data from secure storage
 * 
 * @param string $encrypted Base64 encoded encrypted string
 * @param bool $json_decode Whether to JSON decode result if valid JSON
 * @return mixed Decrypted data, potentially JSON decoded if requested
 */</span>
<span style="color: #569cd6;">function</span> <span style="color: #dcdcaa;">decrypt</span>(<span style="color: #9cdcfe;">$encrypted</span>, <span style="color: #9cdcfe;">$json_decode</span> = <span style="color: #569cd6;">false</span>) {
    <span style="color: #6a9955;">// Handle empty input</span>
    <span style="color: #c586c0;">if</span> (<span style="color: #dcdcaa;">empty</span>(<span style="color: #9cdcfe;">$encrypted</span>)) {
        <span style="color: #c586c0;">return</span> <span style="color: #569cd6;">null</span>;
    }
    
    <span style="color: #6a9955;">// Set encryption key</span>
    <span style="color: #9cdcfe;">$key</span> = <span style="color: #ce9178;">"YOUR_ENCRYPTION_KEY"</span>;
    
    <span style="color: #6a9955;">// Decode base64 string</span>
    <span style="color: #9cdcfe;">$decoded</span> = <span style="color: #dcdcaa;">base64_decode</span>(<span style="color: #9cdcfe;">$encrypted</span>);
    <span style="color: #c586c0;">if</span> (<span style="color: #9cdcfe;">$decoded</span> === <span style="color: #569cd6;">false</span>) {
        <span style="color: #dcdcaa;">error_log</span>(<span style="color: #ce9178;">'[ITS OneLogin] Decryption failed: Invalid base64 encoding'</span>);
        <span style="color: #c586c0;">return</span> <span style="color: #569cd6;">null</span>;
    }
    
    <span style="color: #9cdcfe;">$ivLength</span> = <span style="color: #dcdcaa;">openssl_cipher_iv_length</span>(<span style="color: #ce9178;">'AES-256-CBC'</span>);
    
    <span style="color: #6a9955;">// Check if the string is long enough to contain IV</span>
    <span style="color: #c586c0;">if</span> (<span style="color: #dcdcaa;">strlen</span>(<span style="color: #9cdcfe;">$decoded</span>) <= <span style="color: #9cdcfe;">$ivLength</span>) {
        <span style="color: #dcdcaa;">error_log</span>(<span style="color: #ce9178;">'[ITS OneLogin] Decryption failed: Data too short'</span>);
        <span style="color: #c586c0;">return</span> <span style="color: #569cd6;">null</span>;
    }
    
    <span style="color: #6a9955;">// Extract IV and ciphertext</span>
    <span style="color: #9cdcfe;">$iv</span> = <span style="color: #dcdcaa;">substr</span>(<span style="color: #9cdcfe;">$decoded</span>, <span style="color: #b5cea8;">0</span>, <span style="color: #9cdcfe;">$ivLength</span>);
    <span style="color: #9cdcfe;">$cipherText</span> = <span style="color: #dcdcaa;">substr</span>(<span style="color: #9cdcfe;">$decoded</span>, <span style="color: #9cdcfe;">$ivLength</span>);

    <span style="color: #6a9955;">// Decrypt the data</span>
    <span style="color: #9cdcfe;">$decrypted</span> = <span style="color: #dcdcaa;">openssl_decrypt</span>(<span style="color: #9cdcfe;">$cipherText</span>, <span style="color: #ce9178;">'AES-256-CBC'</span>, <span style="color: #9cdcfe;">$key</span>, <span style="color: #4fc1ff;">OPENSSL_RAW_DATA</span>, <span style="color: #9cdcfe;">$iv</span>);
    <span style="color: #c586c0;">if</span> (<span style="color: #9cdcfe;">$decrypted</span> === <span style="color: #569cd6;">false</span>) {
        <span style="color: #dcdcaa;">error_log</span>(<span style="color: #ce9178;">'[ITS OneLogin] Decryption failed: '</span> . <span style="color: #dcdcaa;">openssl_error_string</span>());
        <span style="color: #c586c0;">return</span> <span style="color: #569cd6;">null</span>;
    }
    
    <span style="color: #6a9955;">// If JSON decode requested and result looks like JSON, attempt to decode</span>
    <span style="color: #c586c0;">if</span> (<span style="color: #9cdcfe;">$json_decode</span> && !<span style="color: #dcdcaa;">empty</span>(<span style="color: #9cdcfe;">$decrypted</span>) && <span style="color: #9cdcfe;">$decrypted</span>[<span style="color: #b5cea8;">0</span>] === <span style="color: #ce9178;">'{'</span> || <span style="color: #9cdcfe;">$decrypted</span>[<span style="color: #b5cea8;">0</span>] === <span style="color: #ce9178;">'['</span>) {
        <span style="color: #9cdcfe;">$json_data</span> = <span style="color: #dcdcaa;">json_decode</span>(<span style="color: #9cdcfe;">$decrypted</span>, <span style="color: #569cd6;">true</span>);
        <span style="color: #c586c0;">if</span> (<span style="color: #dcdcaa;">json_last_error</span>() === <span style="color: #4fc1ff;">JSON_ERROR_NONE</span>) {
            <span style="color: #c586c0;">return</span> <span style="color: #9cdcfe;">$json_data</span>;
        }
    }
    
    <span style="color: #c586c0;">return</span> <span style="color: #9cdcfe;">$decrypted</span>;
}


/**
 * Set encrypted user data in session and cookie
 *
 * @param string $key The key to store the data under
 * @param mixed $value The value to store (will be encrypted)
 * @param bool $set_cookie Whether to also set a cookie (true) or just session (false)
 * @return bool Success status
 */
function set_user_data($key, $value, $set_cookie = true) {
    if (!session_id()) {
        session_start();
    }
    
    // Encrypt and store in session
    $_SESSION[$key] = encrypt($value);
    
    // If cookie requested, set it
    if ($set_cookie) {
        $cookie_expire = time() + (86400 * 30); // 30 days
        $cookie_path = '/';
        $cookie_domain = ''; // Current domain
        $cookie_secure = (function_exists('is_ssl') && is_ssl()) || 
                        (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') || 
                        (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);
        $cookie_httponly = true; // Not accessible via JavaScript
        
        return setcookie($key, encrypt($value), $cookie_expire, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly);
    }
    
    return true;
}

/**
 * Get decrypted user data from session or cookie
 *
 * @param string $key The key to retrieve data from
 * @param mixed $default Default value if key doesn't exist
 * @param bool $json_decode Whether to attempt JSON decoding of value
 * @return mixed Decrypted data or default value
 */
function get_user_data($key, $default = '', $json_decode = false) {
    if (!session_id()) {
        session_start();
    }
    
    // First check session
    if (isset($_SESSION[$key])) {
        return decrypt($_SESSION[$key], $json_decode);
    }
    
    // Then check cookie
    if (isset($_COOKIE[$key])) {
        return decrypt($_COOKIE[$key], $json_decode);
    }
    
    return $default;
}

                        </code></pre>
                    </div>
                </div>
            </div>
            
            <h3>How to Use These Functions</h3>
            
            <p><strong>Decrypting User Data:</strong></p>
            <ol>
                <li>For simple string decryption: <code>$decrypted = decrypt($encrypted_data);</code></li>
                <li>For JSON data decryption: <code>$decrypted = decrypt($encrypted_data, true);</code> (The second parameter automatically converts JSON back to array)</li>
                <li>Always check for null return values which indicate decryption failure</li>
            </ol>
            
            <p><strong>Working with ITS52 User Data:</strong></p>
            <ol>
                <li>Use <code>get_user_data($key, $default = null, $json_decode = true)</code> to retrieve the data later</li>
                <li>Example: <code>$user_info = get_user_data('user_profile');</code></li>
            </ol>
            
            <p class="description"><strong>Note:</strong> Changing or resetting the encryption key will make all previously encrypted data inaccessible. Only reset the key when necessary.</p>
        </div>
    </div>
    <?php
}

// === ADMIN NOTICE FOR PERMALINKS ===
function onlgn_admin_notice() {
    if (!get_option('onlgn_permalinks_flushed')) {
        echo '<div class="notice notice-warning is-dismissible"><p><strong>ITS OneLogin Clean Auth:</strong> Please go to <a href="/wp-admin/options-permalink.php">Settings > Permalinks</a> and click "Save Changes" to activate the authentication endpoint.</p></div>';
        update_option('onlgn_permalinks_flushed', 1);
    }
}
// Action hooks moved to bottom of file

/**
 * Log debug messages to WordPress error log
 * Only logs when debug mode is enabled, except for critical errors
 *
 * @param mixed $msg Message to log (string, array, or object)
 */
function onlgn_debug_log($msg) {
    // Only log if debug mode is enabled
    if (get_option('onlgn_debug', false)) {
        // Convert arrays and objects to strings
        if (is_array($msg) || is_object($msg)) {
            $msg = print_r($msg, true);
        }
        error_log('[ITS OneLogin] ' . $msg);
    }
    
    // Always log critical errors regardless of debug setting
    if (is_string($msg) && strpos($msg, 'ERROR:') === 0) {
        error_log('[ITS OneLogin CRITICAL] ' . $msg);
    }
}

/**
 * Encrypt data for secure storage
 * 
 * @param mixed $data Data to encrypt (string, array or object)
 * @return string Base64 encoded encrypted string
 */
function encrypt($data) {
    // If data is an array or object, convert to JSON string first
    if (is_array($data) || is_object($data)) {
        $data = json_encode($data);
    }
    
    // Handle null and empty values
    if (empty($data)) {
        return '';
    }
    
    // Get encryption key from database
    $key = onlgn_get_encryption_key();
    $ivLength = openssl_cipher_iv_length('AES-256-CBC');
    $iv = openssl_random_pseudo_bytes($ivLength);
    
    $cipherText = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    if ($cipherText === false) {
        error_log('[ITS OneLogin] Encryption failed: ' . openssl_error_string());
        return '';
    }
    
    // Return base64 encoded string with IV prepended
    return base64_encode($iv . $cipherText);
}

/**
 * Decrypt data from secure storage
 * 
 * @param string $encrypted Base64 encoded encrypted string
 * @param bool $json_decode Whether to JSON decode result if valid JSON
 * @return mixed Decrypted data, potentially JSON decoded if requested
 */
function decrypt($encrypted, $json_decode = false) {
    // Handle empty input
    if (empty($encrypted)) {
        return null;
    }
    
    // Get encryption key from database
    $key = onlgn_get_encryption_key();
    
    // Decode base64 string
    $decoded = base64_decode($encrypted);
    if ($decoded === false) {
        error_log('[ITS OneLogin] Decryption failed: Invalid base64 encoding');
        return null;
    }
    
    $ivLength = openssl_cipher_iv_length('AES-256-CBC');
    
    // Check if the string is long enough to contain IV
    if (strlen($decoded) <= $ivLength) {
        error_log('[ITS OneLogin] Decryption failed: Data too short');
        return null;
    }
    
    // Extract IV and ciphertext
    $iv = substr($decoded, 0, $ivLength);
    $cipherText = substr($decoded, $ivLength);

    // Decrypt the data
    $decrypted = openssl_decrypt($cipherText, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    if ($decrypted === false) {
        error_log('[ITS OneLogin] Decryption failed: ' . openssl_error_string());
        return null;
    }
    
    // If JSON decode requested and result looks like JSON, attempt to decode
    if ($json_decode && !empty($decrypted) && $decrypted[0] === '{' || $decrypted[0] === '[') {
        $json_data = json_decode($decrypted, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            return $json_data;
        }
    }
    
    return $decrypted;
}

/**
 * Set encrypted user data in session and cookie
 *
 * @param string $key The key to store the data under
 * @param mixed $value The value to store (will be encrypted)
 * @param bool $set_cookie Whether to also set a cookie (true) or just session (false)
 * @return bool Success status
 */
function set_user_data($key, $value, $set_cookie = true) {
    if (!session_id()) {
        session_start();
    }
    
    // Encrypt and store in session
    $_SESSION[$key] = encrypt($value);
    
    // If cookie requested, set it
    if ($set_cookie) {
        $cookie_expire = time() + (86400 * 30); // 30 days
        $cookie_path = '/';
        $cookie_domain = ''; // Current domain
        $cookie_secure = (function_exists('is_ssl') && is_ssl()) || 
                        (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') || 
                        (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);
        $cookie_httponly = true; // Not accessible via JavaScript
        
        return setcookie($key, encrypt($value), $cookie_expire, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly);
    }
    
    return true;
}

/**
 * Get decrypted user data from session or cookie
 *
 * @param string $key The key to retrieve data from
 * @param mixed $default Default value if key doesn't exist
 * @param bool $json_decode Whether to attempt JSON decoding of value
 * @return mixed Decrypted data or default value
 */
function get_user_data($key, $default = '', $json_decode = false) {
    if (!session_id()) {
        session_start();
    }
    
    // First check session
    if (isset($_SESSION[$key])) {
        return decrypt($_SESSION[$key], $json_decode);
    }
    
    // Then check cookie
    if (isset($_COOKIE[$key])) {
        return decrypt($_COOKIE[$key], $json_decode);
    }
    
    return $default;
}

/**
 * Check if user data exists in session or cookie
 *
 * @param string $key Specific key to check, or empty to check for any user data
 * @return bool True if data exists
 */
function has_user_data($key = '') {
    if (!session_id()) {
        session_start();
    }
    
    if (!empty($key)) {
        return isset($_SESSION[$key]) || isset($_COOKIE[$key]);
    }
    
    // Check for key indicators of user data
    return isset($_SESSION['its_user_data']) || isset($_COOKIE['its_user_data']) || 
           isset($_SESSION['its_no']) || isset($_COOKIE['its_no']);
}

// ===================================================================
// Admin Settings for ITS OneLogin
// ===================================================================

/**
 * Register admin menu item for ITS OneLogin settings
 */
function onlgn_register_admin_menu() {
    add_options_page(
        'ITS OneLogin Settings', // Page title
        'ITS OneLogin', // Menu title
        'manage_options', // Capability required
        'its-onelogin-settings', // Menu slug
        'onlgn_settings_page' // Callback function
    );
}

/**
 * Register settings for ITS OneLogin
 */
function onlgn_register_settings() {
    // Register settings
    register_setting('onlgn_settings', 'onlgn_endpoint');
    register_setting('onlgn_settings', 'onlgn_token');
    register_setting('onlgn_settings', 'onlgn_code');
    register_setting('onlgn_settings', 'onlgn_encryption_key');
    register_setting('onlgn_settings', 'onlgn_debug');
}


// ===================================================================
// Action and Filter Hook Registrations - Grouped at the bottom for clarity
// ===================================================================

// Check auth status on every page load
add_action('template_redirect', 'onlgn_sitewide_auth_check', 0);

// Register the endpoint for authentication
add_action('init', 'onlgn_register_auth_endpoint');

// Admin settings
add_action('admin_menu', 'onlgn_register_admin_menu');
add_action('admin_init', 'onlgn_register_settings');

// Add the query var to WordPress
add_filter('query_vars', 'onlgn_query_vars');

// Parse the request to check for our custom query var
add_action('parse_request', 'onlgn_parse_request');

// Admin menu registration is handled by onlgn_register_admin_menu

// Display admin notice for permalink flush
add_action('admin_notices', 'onlgn_admin_notice');

/**
 * Get the root domain from the current hostname
 * Always includes a leading dot to ensure cookies are shared across all subdomains
 * 
 * @return string The root domain with leading dot (e.g., '.example.com' from 'sub.example.com')
 */
function onlgn_get_root_domain() {
    $host = $_SERVER['HTTP_HOST'];
    
    // If it's an IP address, return as is (no leading dot for IPs)
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return $host;
    }
    
    // Split the hostname into parts
    $parts = explode('.', $host);
    
    // If we have less than 2 parts, return the host as is (no leading dot for localhost)
    if (count($parts) < 2) {
        return $host;
    }
    
    // For domains like example.com
    if (count($parts) === 2) {
        return '.' . $host; // Add leading dot for domain-wide sharing
    }
    
    // For domains like sub.example.com
    // Get the last two parts
    $root_domain = $parts[count($parts)-2] . '.' . $parts[count($parts)-1];
    
    // Special case for .co.uk, .com.au, etc.
    $special_tlds = ['co.uk', 'com.au', 'org.uk', 'net.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'sch.uk', 'ac.uk', 'gov.uk', 'nhs.uk', 'police.uk', 'mod.uk', 'mil.uk', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au', 'csiro.au'];
    
    foreach ($special_tlds as $tld) {
        if (strpos($host, '.' . $tld) !== false) {
            // Get the parts before the special TLD
            $parts = explode('.' . $tld, $host);
            // Return the last part before the TLD + the TLD
            $parts = explode('.', $parts[0]);
            return '.' . end($parts) . '.' . $tld; // Add leading dot for domain-wide sharing
        }
    }
    
    return '.' . $root_domain; // Add leading dot for domain-wide sharing
}

?>