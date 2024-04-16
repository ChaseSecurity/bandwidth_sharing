<?php
#print_r(openssl_get_cipher_methods());
#$sharedKey = "c4278a0896e73fe66f54f0bfe1ffe971998b845d15a304b9aca138b6bb971296";
#$message = "plaintext";
#$encryptedMessage = openssl_encrypt($message, "aes-256-ecb", $sharedKey);
#echo $encryptedMessage;
#$decryptedMessage = openssl_decrypt($encryptedMessage, "aes-256-ecb", $sharedKey);
#echo "\n";
#print_r($decryptedMessage);
#
$sharedKey = "c4278a0896e73fe66f54f0bfe1ffe971998b845d15a304b9aca138b6bb971296";
$clientIP   = $_SERVER['REMOTE_ADDR'];
$clientPort = $_SERVER['REMOTE_PORT'];
$clientUA   = $_SERVER["HTTP_USER_AGENT"];
$requestTime = $_SERVER["REQUEST_TIME_FLOAT"];
$subResult  = array(
 "ip" => $clientIP,
 "port" => $clientPort,
 "ua" => $clientUA,
 "requestTime" => $requestTime,
 );
$subResultStr = json_encode($subResult);
$macStr = hash_hmac("sha256", $subResultStr, $sharedKey);//lower case hex
$resultArray = array(
"payload" => $subResultStr,
"identity" => $macStr,
);
$resultStr = json_encode($resultArray);
#echo $resultStr;
$keyStr = "7cd7cf8776a1428ca70f2f95fbe51c98";
$key = hex2bin($keyStr);
$ivSize = 16;
$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
$plainText = $resultStr;
$ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $plainText, MCRYPT_MODE_CBC, $iv);
$base64CipherText = base64_encode($iv . $ciphertext);
echo $base64CipherText;
