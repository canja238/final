<?php
header('Content-Type: application/json');
require_once 'db.php';

$response = ['success' => false, 'message' => '', 'products' => []];

try {
    $database = new Database();
    $db = $database->connect();
    
    $stmt = $db->query("SELECT * FROM products");
    $products = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Ensure numeric prices
    $products = array_map(function($product) {
        $product['price'] = (float)$product['price'];
        return $product;
    }, $products);
    
    $response['success'] = true;
    $response['products'] = $products;
} catch (PDOException $e) {
    $response['message'] = 'Database error: ' . $e->getMessage();
}

echo json_encode($response);
?>