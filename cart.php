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
$data = json_decode(file_get_contents('php://input'), true);
$action = $_GET['action'] ?? '';

try {
    if ($action === 'add') {
        $product_id = $data['product_id'] ?? 0;
        $quantity = $data['quantity'] ?? 1;

        // Check if product exists
        $stmt = $db->prepare("SELECT id FROM products WHERE id = :product_id");
        $stmt->bindParam(':product_id', $product_id);
        $stmt->execute();

        if ($stmt->rowCount() === 0) {
            $response['message'] = 'Product not found';
            echo json_encode($response);
            exit;
        }

        // Check if item already in cart
        $stmt = $db->prepare("SELECT id, quantity FROM cart WHERE user_id = :user_id AND product_id = :product_id");
        $stmt->bindParam(':user_id', $user_id);
        $stmt->bindParam(':product_id', $product_id);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $cart_item = $stmt->fetch(PDO::FETCH_ASSOC);
            $new_quantity = $cart_item['quantity'] + $quantity;
            
            $stmt = $db->prepare("UPDATE cart SET quantity = :quantity WHERE id = :id");
            $stmt->bindParam(':quantity', $new_quantity);
            $stmt->bindParam(':id', $cart_item['id']);
            $stmt->execute();
        } else {
            $stmt = $db->prepare("INSERT INTO cart (user_id, product_id, quantity) VALUES (:user_id, :product_id, :quantity)");
            $stmt->bindParam(':user_id', $user_id);
            $stmt->bindParam(':product_id', $product_id);
            $stmt->bindParam(':quantity', $quantity);
            $stmt->execute();
        }

        $response['success'] = true;
        $response['message'] = 'Item added to cart';
    }
    elseif ($action === 'remove') {
        $product_id = $data['product_id'] ?? 0;

        $stmt = $db->prepare("DELETE FROM cart WHERE user_id = :user_id AND product_id = :product_id");
        $stmt->bindParam(':user_id', $user_id);
        $stmt->bindParam(':product_id', $product_id);
        $stmt->execute();

        $response['success'] = true;
        $response['message'] = 'Item removed from cart';
    }
    elseif ($action === 'update') {
        $product_id = $data['product_id'] ?? 0;
        $quantity = $data['quantity'] ?? 1;

        $stmt = $db->prepare("UPDATE cart SET quantity = :quantity WHERE user_id = :user_id AND product_id = :product_id");
        $stmt->bindParam(':quantity', $quantity);
        $stmt->bindParam(':user_id', $user_id);
        $stmt->bindParam(':product_id', $product_id);
        $stmt->execute();

        $response['success'] = true;
        $response['message'] = 'Cart updated';
    }
    elseif ($action === 'get') {
        $stmt = $db->prepare("
            SELECT c.*, p.product_name, p.price, p.product_image 
            FROM cart c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = :user_id
        ");
        $stmt->bindParam(':user_id', $user_id);
        $stmt->execute();

        $cart_items = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $total = 0;

        foreach ($cart_items as &$item) {
            $item['subtotal'] = $item['price'] * $item['quantity'];
            $total += $item['subtotal'];
        }

        $response['success'] = true;
        $response['cart_items'] = $cart_items;
        $response['total'] = $total;
    }
} catch (PDOException $e) {
    $response['message'] = 'Database error: ' . $e->getMessage();
}

echo json_encode($response);
?>
