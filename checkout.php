<?php
header('Content-Type: application/json');
require_once 'db.php';

session_start();
$response = ['success' => false, 'message' => ''];

if (!isset($_SESSION['user_id'])) {
    $response['message'] = 'User not authenticated. Please login to checkout.';
    echo json_encode($response);
    exit;
}

$user_id = $_SESSION['user_id'];

try {
    $input = file_get_contents('php://input');
    if (empty($input)) {
        throw new Exception('No input data received');
    }

    $data = json_decode($input, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Invalid JSON data: ' . json_last_error_msg());
    }

    if (!isset($data['items']) || !is_array($data['items'])) {
        throw new Exception('Invalid cart items data');
    }

    $database = new Database();
    $db = $database->connect();
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->beginTransaction();

    $total_amount = 0;
    foreach ($data['items'] as $item) {
        if (!isset($item['productId'], $item['quantity'], $item['price'])) {
            throw new Exception('Invalid item format');
        }
        $total_amount += (float)$item['price'] * (int)$item['quantity'];
    }

    $stmt = $db->prepare("
        INSERT INTO orders 
        (user_id, total_amount, status, created_at, updated_at) 
        VALUES (:user_id, :total_amount, 'pending', NOW(), NOW())
    ");
    $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
    $stmt->bindParam(':total_amount', $total_amount, PDO::PARAM_STR);
    $stmt->execute();
    $order_id = $db->lastInsertId();

    foreach ($data['items'] as $item) {
        $product_id = (int)$item['productId'];
        $quantity = (int)$item['quantity'];
        $price = (float)$item['price'];

        $stmt = $db->prepare("
            SELECT id, product_name, stock_quantity 
            FROM products 
            WHERE id = :product_id 
            FOR UPDATE
        ");
        $stmt->bindParam(':product_id', $product_id, PDO::PARAM_INT);
        $stmt->execute();
        $product = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$product) {
            throw new Exception("Product not found: ID $product_id");
        }

        if ($product['stock_quantity'] < $quantity) {
            throw new Exception("Insufficient stock for {$product['product_name']} (Available: {$product['stock_quantity']}, Requested: $quantity)");
        }

        $stmt = $db->prepare("
            INSERT INTO order_items 
            (order_id, product_id, quantity, price)
            VALUES (:order_id, :product_id, :quantity, :price)
        ");
        $stmt->bindParam(':order_id', $order_id, PDO::PARAM_INT);
        $stmt->bindParam(':product_id', $product_id, PDO::PARAM_INT);
        $stmt->bindParam(':quantity', $quantity, PDO::PARAM_INT);
        $stmt->bindParam(':price', $price, PDO::PARAM_STR);
        $stmt->execute();

        $new_stock = $product['stock_quantity'] - $quantity;
        $stmt = $db->prepare("
            UPDATE products 
            SET stock_quantity = :new_stock, updated_at = NOW() 
            WHERE id = :product_id
        ");
        $stmt->bindParam(':new_stock', $new_stock, PDO::PARAM_INT);
        $stmt->bindParam(':product_id', $product_id, PDO::PARAM_INT);
        $stmt->execute();
    }

    $stmt = $db->prepare("DELETE FROM cart WHERE user_id = :user_id");
    $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
    $stmt->execute();

    $db->commit();

    $response['success'] = true;
    $response['message'] = 'Order placed successfully!';
    $response['order_id'] = $order_id;

} catch (PDOException $e) {
    if (isset($db) && $db->inTransaction()) {
        $db->rollBack();
    }
    $response['message'] = 'Database error during checkout';
    $response['error_details'] = $e->getMessage();
    error_log('Checkout error: ' . $e->getMessage());
} catch (Exception $e) {
    if (isset($db) && $db->inTransaction()) {
        $db->rollBack();
    }
    $response['message'] = $e->getMessage();
    error_log('Checkout error: ' . $e->getMessage());
}

echo json_encode($response);
?>