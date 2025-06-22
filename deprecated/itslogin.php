<?php

$caller = parse_url($_SERVER['HTTP_REFERER']);

if (strpos($caller['host'], 'www.its52.com') !== false) {
	$its = (isset($_GET['Token']) && $_GET['Token'] != '') ? $_GET['Token'] : '';
	//echo $its . '<br />';
	if ($its != '')
	{
        setcookie("user", $its, time()+10800, "/", "asharamubaraka.net");  /* expire in 1 hour */
		header("Location: https://asharamubaraka.net/");
	}
	else {
	   exit("Something went wrong during authentication. Please go back and try again!");
	}
}
else echo 'You have arrived at this page without passing authentication!';

?>