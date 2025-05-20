<?php
header('Content-Type: application/json');
require_once 'db.php';

$database = new Database();
$db = $database->connect();

session_start();
$response = ['success' => false, 'message' => ''];

if (!isset($_SESSION['user_id'])) {
    $response['message'] = 'Not authenticated';
    echo json_encode($response);
    exit;
}

$user_id = $_SESSION['user_id'];

try {
    // Get orders with their items
    $stmt = $db->prepare("
        SELECT o.*
        FROM orders o
        WHERE o.user_id = :user_id
        ORDER BY o.created_at DESC
    ");
    $stmt->bindParam(':user_id', $user_id);
    $stmt->execute();
    $orders = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Get items for each order
    foreach ($orders as &$order) {
        $stmt = $db->prepare("
            SELECT oi.*, p.product_name, p.product_image
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id = :order_id
        ");
        $stmt->bindParam(':order_id', $order['id']);
        $stmt->execute();
        $order['items'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    $response['success'] = true;
    $response['orders'] = $orders;
} catch (PDOException $e) {
    $response['message'] = 'Database error: ' . $e->getMessage();
}

echo json_encode($response);
?>