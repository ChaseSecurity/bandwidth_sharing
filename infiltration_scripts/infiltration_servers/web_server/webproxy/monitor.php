<?php

function initNormalResponse($responseStatus = 200, $isJson = true) {
    http_response_code($responseStatus);
    header("Content-Type: application/json; charset=utf-8");
}
#print_r($_GET);
if ( ! array_key_exists("sfc", $_GET) ) {
  initNormalResponse(401);
  $responseArray = array(
    "msg" => "missing request parameters",
  );
  echo json_encode($responseArray);
  exit;
}
if ( ! array_key_exists("nf", $_GET) ) {
  initNormalResponse(402);
  $responseArray = array(
    "msg" => "missing request parameters",
  );
  echo json_encode($responseArray);
  exit;
}
if ( ! array_key_exists("event", $_GET) ) {
  initNormalResponse(403);
  $responseArray = array(
    "msg" => "missing request parameters",
  );
  echo json_encode($responseArray);
  exit;
}
$sfcName = $_GET["sfc"];
$nfName = $_GET["nf"];
$eventName = $_GET["event"];
$requestTime = $_SERVER["REQUEST_TIME_FLOAT"];
$requestTimeStr = date("Y-m-d H:i:s.u", $requestTime);
$clientIP   = $_SERVER['REMOTE_ADDR'];
$clientPort = $_SERVER['REMOTE_PORT'];
$logArray = array(
  "sfc" => $sfcName,
  "nf" => $nfName,
  "event" => $eventName,
  "requestTime" => $requestTime,
  "requestTimeStr" => $requestTimeStr,
  "clientIP" => $clientIP,
  "clientPort" => $clientPort,
);
$logMsg = json_encode($logArray) . "\n";
$result = file_put_contents(__DIR__ . "/localLog.txt", $logMsg, FILE_APPEND);
#$result = file_put_contents(__DIR__ . "/localLog.txt", $logMsg);
if ($result == FALSE) {
  initNormalResponse(500);
  echo "internal error";
  exit;
}
initNormalResponse(200);
echo $logMsg;
exit;
