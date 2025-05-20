<?php
header('Content-Type: application/json');
session_start();

$response = [
    'authenticated' => false,
    'user' => null
];

if (isset($_SESSION['user_id'])) {
    $response['authenticated'] = true;
    $response['user'] = [
        'id' => $_SESSION['user_id'],
        'username' => $_SESSION['username'],
        'email' => $_SESSION['email'],
        'role' => $_SESSION['role']
    ];
}

echo json_encode($response);
?>