<?php
// Set the file path
$filePath = 'path_to_your_executable_file.exe'; // Replace 'path_to_your_executable_file.exe' with the actual path to your executable file

// Content-Disposition: inline; filename="file.exe"
header('Content-Disposition: attachment; filename="file.exe"');
header("Content-Type: application/octet-stream");
readfile($filePath);
exit;
?>