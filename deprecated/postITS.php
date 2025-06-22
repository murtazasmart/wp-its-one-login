<?php 
  // include_once('wp-includes\option.php');
  // require('its-oauth.php');
  require_once('../../../wp-load.php');
  if (isset($_POST["itsNo"])) {
  $itsNos = get_option('its-oauth-dashboard-no');
  if (!(array_search( $_POST["itsNo"], $itsNos ) >= 0) ) {
    array_push($itsNos,$_POST["itsNo"]);
    update_option('its-oauth-dashboard-no', $itsNos);
  }
  $itsNos = get_option('its-oauth-dashboard-no');
  wp_redirect($_SERVER['HTTP_REFERER']);
}
?>