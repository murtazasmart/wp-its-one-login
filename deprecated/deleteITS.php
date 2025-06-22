<?php

/**
* @author Murtaza Anverali
* @email <murtaza.esufali@gmail.com>
*/

  // include_once('wp-includes\option.php');
  require_once('../../../wp-load.php');
  if (isset($_POST["itsNo"])) {
  $itsNos = get_option('its-oauth-dashboard-no');
  $index = array_search( $_POST["itsNo"], $itsNos );
  print_r($index);
  if ($index || $index == 0) {
    unset($itsNos[$index]);
  }
  update_option('its-oauth-dashboard-no', $itsNos);
  $itsNos = get_option('its-oauth-dashboard-no');
  // print_r($itsNos);
  }
  wp_redirect($_SERVER['HTTP_REFERER']);

?>