<?php
header('Content-Type: application/json');
session_start();

// Unset all session variables
$_SESSION = [];

// If sessions use cookies, clear the session cookie
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Destroy the session
session_destroy();

echo json_encode([
    'success' => true,
    'message' => 'Logged out successfully'
]);
exit;
?>