<?php

function initNormalResponse($responseStatus = 200, $isJson = true) {
    http_response_code($responseStatus);
    header("Content-Type: application/json; charset=utf-8");
}
$result = file_get_contents(__DIR__ . "/localLog.txt");
initNormalResponse(200);
echo $result;
exit;
