<?php
/*
Plugin Name:  ITS OAuth 2.0 Plugin
Plugin URI:   https://developer.wordpress.org/plugins/the-basics/
Description:  Implements OAuth Basic Login for ITS
Version:      20180902
Author:       Murtaza Anverali
Author URI:   https://murtazasmart.com
License:      GPL2
License URI:  https://www.gnu.org/licenses/gpl-2.0.html
Text Domain:  wporg
Domain Path:  /languages
*/

// define('BASEURL', 'https://www.medanits.net');

function start_session() {
  if(!session_id()) {
    session_start();
  }
}

function end_session() {
  session_destroy ();
}

/**
 * This OAuth function is a slightly dirty method, not sure though,
 * What is does - 
 * It reads the URL during every request and checks if it matches a given criteria and then executes relevant commands
 * Criteria 1 - checks if the URL contains wp-json, wp-admin, wp-login, if it does then does nothing
 * Criteria 2 - if the URL contains 'auth/callback' then performs the OAuth 2 processing
 * Criteria 3 - if the URL contains 'logout' then performs the OAuth 2 logout
 * Criteria 4 - if the URL contains 'loggedin' then performs the OAuth 2 login. To be noted that the callback send parameters
 * in fragments therefore 
 */
function oAuth() {
  $current_url = "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
  if (strpos($current_url, 'wp') !== false || strpos($current_url, 'wp-json') !== false || strpos($current_url, 'wp-login') !== false ) {
  } 
  else if ( strpos($current_url, 'auth') !== false ) {
    end_session();
    start_session();
    $_SESSION['encoded_its_token'] = $_GET['Token'];
    // $payload = decode($_GET['id_token']);
    // $_SESSION['its_token'] = $payload;
    // exit(wp_redirect(urldecode($_GET['state'])));
    // exit(wp_redirect("https://itsmedan.net"));
    // exit(wp_redirect($_GET['state']));
  } 
  else if (!isset($_SESSION['encoded_its_token'])) {
    $_SESSION['myurl'] = $current_url;
    exit(wp_redirect("https://www.its52.com/Login.aspx?OneLogin=ASHARACOL"));
  }
}
add_action( 'init', 'start_session', 1);
add_action( 'init', 'oAuth');
// add_action('wp_logout', 'end_session');
// add_action(‘wp_login’, ‘end_session’);
add_action('end_session_action', 'end_session');

/*
  Short codes for Login, Logout, Dashboard
*/
// function wporg_shortcodes_init()
// {
//     function loggin_btn($atts = [], $content = null)
//     {
//       return '<a href="https://auth.its52.com/connect/authorize?client_id=FA6AFE99F01D0417034852E0354E2B09DB0EF24F.apps.its52.com&response_type=code id_token&scope=openid profile&redirect_uri=https://www.itsmedan.net/loggedin&state=helloworld&nonce=foo"> <button class="wpcf7-form-control wpcf7-submit">Login</button></a>';
//     }
//     add_shortcode('loggin_btn', 'loggin_btn');
//     function logout_btn($atts = [], $content = null)
//     {
//         // return '<a href="https://itsmedan.net/logout/"> <button class="wpcf7-form-control wpcf7-submit">Logout</button></a>';
//         return '<div id="main-menu" class="collapse navbar-collapse navbar-right"><ul id="menu-menu" class="nav navbar-nav"><li id="menu-item-221" class="menu-item menu-item-type-custom menu-item-object-custom primary menu-item-221"><a href="https://www.itsmedan.net/logout">Logout</a></li></ul></div>';
//     }
//     add_shortcode('logout_btn', 'logout_btn');
// }
// add_action('init', 'wporg_shortcodes_init');

/*
  Additional functions used in above WP shortcodes and hooks
*/
// $encoded = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkIwQ0NCQzJCMkE5MjFBNzExMDlGM0NFM0IxMTYxNkExMTg5RURCRTUiLCJ0eXAiOiJKV1QiLCJ4NXQiOiJzTXk4S3lxU0duRVFuenpqc1JZV29SaWUyLVUifQ.eyJuYmYiOjE1MzYwMzQ2NzYsImV4cCI6MTUzNjAzNDk3NiwiaXNzIjoiaHR0cHM6Ly9hdXRoLml0czUyLmNvbSIsImF1ZCI6IkZBNkFGRTk5RjAxRDA0MTcwMzQ4NTJFMDM1NEUyQjA5REIwRUYyNEYuYXBwcy5pdHM1Mi5jb20iLCJub25jZSI6ImZvbyIsImlhdCI6MTUzNjAzNDY3NiwiY19oYXNoIjoiWUVZTWVTaXFsOEJjMEktaVIwUmZyUSIsInNpZCI6ImZjMDA0YTk5MTc5ZGQ2NDFjODQ4MmYyMGI1YmI3NGNiIiwic3ViIjoiMzAzNjExMTQiLCJhdXRoX3RpbWUiOjE1MzYwMzQ2NzUsImlkcCI6ImxvY2FsIiwiYW1yIjpbInB3ZCJdfQ.LvYTgfPukcdkh_ZE9ujGtgkYYTbOA31oq5Aoq1DD0DBdpA_E9T3Rx88VcmicKZdzDB2B1Gslm6_a9knQAIdfgWqTIAp-v3Jy3yjpf-I3HrH4d1_5UbAHklplIaQEk96hsiJFxiilEUWX5h49uHlaE8751mQ6eShnwt1nC68wHZtTiWFuZF5Jbd5hFocj3VJf2C6aFOPWAL7EicjOlkhLeU4ne8d0S_7jo65V1cSX-DgQ30IinnLsytvWoLJqFLO-0n--R00fPGPalDy8IxxH-b-nDkiz-1g_NA-njTTbWNtNqB-bTGf4OHFlHHON_VPKEv-N78GPX3s3c0-zfjprpA";
function decode($jwt) {
  $tks = explode('.', $jwt);
  list($headb64, $bodyb64, $cryptob64) = $tks;
  $payload = json_decode(base64_decode($bodyb64));
  $payload = (array)$payload;
  return $payload;
}

function checkDashboardAuthorization() {
  // $response = json_decode(wp_remote_get( 'http://www.mocky.io/v2/5b8f504c32000042317b3c15' )['body']);
  $itsNos = get_option('its-oauth-dashboard-no');
  $token = $_SESSION['its_token'];
  $itsNo = $token['sub'];
  if (in_array($itsNo, $itsNos)) {
    return true;;
  } else {
    return false;
  }
  
}

function checkStringExists() {

}

// wp_db, clean data before using it.

?>
<!-- 
https://www.its52.com/Login.aspx?OneLogin=ZENINFOSYS
http://zeninfosys.net/zen/auth-its?SID=so411pjz45zpjfs2s1jcjs5y&Lan=en&App=ITSOnelogin&API=3.0&Token=zvegdX2XdHvaD7UUc%2bhBmvcBVb30XZ8l%2bmri9MUdi5k%3d&DT=RfXaWYn284vceRZxPwHDTbyaAlmgLSiZoGeLc4UYgIOS7kcaj98S%2bHdML2PIcx8L%2b%2fNYzdf8%2fMLKOOUUZZt4gWJoiVX4oUWz%2fkJxHxGmTbpeGabWFFkMYOpadwhTKbWKDw2s%2bNGQIQO86bfYnpWzvG2WpmegPt5B78%2fVLooiFCcGJ%2fpZ39NSY5DS9PuSv3Sf9NAMlHqSZqbYZ4LH5GIPrK1MNPrGAWSuVp3iNSLEEKQ%3d&OneLogin=ZENINFOSYS -->
