<?php

function oneLoginDecryptData($cipherText) {
// Mcrypt is UNSECURE and depecated since PHP 7.1, using OpenSSL is recommended as it is resistant to time-replay and side-channel attacks
// Libsodium, the new defacto PHP cryptography library, does not support AES128 (as it is considerably weak), so we are stuck with OpenSSL

$token = 'AU68vf26spwX'; // Change to the token issued to your domain

$key = openssl_pbkdf2($token, 'ADD_THE_SALT_VALUE_HERE', 32, 1000);
// $key = hash_pbkdf2('SHA1', $key, 'ADD_THE_SALT_VALUE_HERE', 1000, 32, true);

return utf8_decode(openssl_decrypt((urldecode($cipherText)), 'AES-128-CBC', substr($key, 0, 16), OPENSSL_ZERO_PADDING, substr($key, 16, 16)));
// return utf8_decode(trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_128, substr($key, 0, 16), base64_decode(urldecode($cipherText)), MCRYPT_MODE_CBC, substr($key, 16, 16))));
}

//TESTS - try on http://phptester.net/
$cipherText1 = 'GtxuyQqOIivJd3M3ObXUczE8uMFUp1vG%2fyI26Xq1%2bD3%2blIL4sNXdbvoxZ%2bXT6hcMeJKWZI0VcNGHZHQhN9kBc1M7s4XDXQ3AUQPaZfCbVd7E6oJdlu6N6b1zWvGwwXcwPRqOZZY%2b1wCShxD4MN30qxoqi3%2b8G3aB78bY60kATghITx7widsImdrm3mC0TJOvCKmy83uF6DHfEPQko4FICQ%3d%3d';
$cipherText2 = '82nhDZoGQH9wp3sie1icIsW2popTDYCNUYSifGB2H8uZcxUYBWqRrruWyIPWMuvuONLinQ3OfWOKolrNqW6s6JeRKM6nFTneTdgPhCIUzeDTSiRGKWWcl8PMUsYe4oWHnzD9mVErMiRSaBiRsAarEQiZVzRC70sa9CbdzOEedRuPl2cL2z2TIMYir6uWnyTd';
$cipherText3 = 'QYBdZ4yNMCkzs6gBK%2fOl5WaYVhMvCohh%2fmtFLBdJW1jblOLXV1G9jk%2fVUP1cjUoANz589QbY2lRxgDAQyxqz0becXjYZEOzZ6elaHW87Bx1aQcpD8uF8rh2l2atMx5%2ff5M8moZEQQhXaNl7MERKzxStFqUIzNQyNQz1WU1%2fk8GM0LjpGzuEteTta2NTkLaT4cyG0rtba28owaTlCGpieRJuxzxM8%2bqKF%2bJtnO%2b6pFv4%3d';

echo 'Plaintext 1: ' . oneLoginDecryptData($cipherText1) . '</br>';
echo 'Plaintext 2: ' . oneLoginDecryptData($cipherText2) . '</br>';
echo 'Plaintext 3: ' . oneLoginDecryptData($cipherText3);
