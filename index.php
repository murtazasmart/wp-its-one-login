<?php

/**
* @author Murtaza Anverali
* @email <murtaza.esufali@gmail.com>
*/

$current_url = "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

if (!strcmp($current_url, 'homepage-2')) {
} else if (!isset($_COOKIE['user'])) {
    header("Location: https://www.its52.com/Login.aspx?OneLogin=ASHARACOL");
}

/**
 * Front to the WordPress application. This file doesn't do anything, but loads
 * wp-blog-header.php which does and tells WordPress to load the theme.
 *
 * @package WordPress
 */

/**
 * Tells WordPress to load the WordPress theme and output it.
 *
 * @var bool
 */
define( 'WP_USE_THEMES', true );

/** Loads the WordPress Environment and Template */
require( dirname( __FILE__ ) . '/wp-blog-header.php' );
