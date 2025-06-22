<?php

/*
Plugin Name:  ITS OAuth 2.0 Plugin
Description:  Implements OAuth Basic Login for ITS
Version:      20190802
Author:       Murtaza Anverali
Author URI:   https://murtazasmart.com
Author Email: murtaza.esufali@gmail.com
License:      GPL2
License URI:  https://www.gnu.org/licenses/gpl-2.0.html
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
 * Criteria 2 - if the URL contains 'its-login' then does nothing and shows the option to login via ITS
 * Criteria 3 - if the URL contains 'auth/callback' then performs the OAuth 2 processing and saves the token
 * Criteria 4 - if the URL is anything from the above then checks for token if it isnt present it it redirected to ITS
 */
function oAuth() {
  $current_url = "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
  if (strpos($current_url, 'wp') !== false || strpos($current_url, 'wp-json') !== false || strpos($current_url, 'wp-login') !== false ) {
  } 
  else if ( strpos($current_url, 'its-login') !== false ) {
  }
  else if ( strpos($current_url, 'auth') !== false ) {
    end_session();
    start_session();
    $_SESSION['encoded_its_token'] = $_GET['Token'];
    exit(wp_redirect("https://asharamubaraka.net"));
  } 
  else if (!isset($_SESSION['encoded_its_token'])) {
    $_SESSION['myurl'] = $current_url;
    // exit(wp_redirect("https://www.its52.com/Login.aspx?OneLogin=ASHARA1443"));
    exit(wp_redirect("https://asharamubaraka.net/its-login"));
  }
}
add_action( 'init', 'start_session', 1);
add_action( 'init', 'oAuth');
// add_action('wp_logout', 'end_session');
// add_action(‘wp_login’, ‘end_session’);
add_action('end_session_action', 'end_session');

// wp_db, clean data before using it.

?>