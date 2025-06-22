<?php
/**
* @author Murtaza Anverali
* @email <murtaza.esufali@gmail.com>
*/

    require_once('../../../wp-load.php');
  if (isset($_POST["clean"])) {
    delete_option('its-oauth-dashboard-no');
    wp_redirect($_SERVER['HTTP_REFERER']);
}
?>