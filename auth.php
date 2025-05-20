<?php
header('Content-Type: application/json');
require_once 'db.php';

$database = new Database();
$db = $database->connect();

$response = ['success' => false, 'message' => ''];

try {
    $data = json_decode(file_get_contents('php://input'), true);
    $action = $data['action'] ?? '';

    if ($action === 'login') {
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        if (empty($email) || empty($password)) {
            $response['message'] = 'Email and password are required';
            echo json_encode($response);
            exit;
        }

        $stmt = $db->prepare("SELECT * FROM users WHERE email = :email");
        $stmt->bindParam(':email', $email);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Verify password - handles both plain text and hashed passwords
            if ($password === $user['password'] || password_verify($password, $user['password'])) {
                session_start();
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['role'] = $user['role'];

                $response['success'] = true;
                $response['message'] = 'Login successful';
                $response['user'] = [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'email' => $user['email'],
                    'role' => $user['role']
                ];
            } else {
                $response['message'] = 'Invalid credentials';
            }
        } else {
            $response['message'] = 'User not found';
        }
    } 
    elseif ($action === 'signup') {
        $username = $data['username'] ?? '';
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        if (empty($username) || empty($email) || empty($password)) {
            $response['message'] = 'All fields are required';
            echo json_encode($response);
            exit;
        }

        // Check if email already exists
        $stmt = $db->prepare("SELECT id FROM users WHERE email = :email");
        $stmt->bindParam(':email', $email);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $response['message'] = 'Email already registered';
            echo json_encode($response);
            exit;
        }

        // Hash the password before storing
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        
        $stmt = $db->prepare("INSERT INTO users (username, email, password, role) VALUES (:username, :email, :password, 'user')");
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $hashed_password);

        if ($stmt->execute()) {
            $response['success'] = true;
            $response['message'] = 'Registration successful';
        } else {
            $response['message'] = 'Registration failed';
        }
    }
} catch (PDOException $e) {
    $response['message'] = 'Database error: ' . $e->getMessage();
}

echo json_encode($response);
?>