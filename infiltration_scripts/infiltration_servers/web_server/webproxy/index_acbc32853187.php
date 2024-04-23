<?php
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
echo $resultStr;
