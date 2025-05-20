
<?php
// At the beginning of each PHP file
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/error.log');
session_start();
require_once 'db.php';
require_once 'csrf.php';

// Check if user is admin
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: /');
    exit;
}

$database = new Database();
$db = $database->connect();

// Handle actions
$action = $_GET['action'] ?? '';
$success_message = '';
$error_message = '';

// Verify CSRF token for POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCSRFToken($_POST['csrf_token'])) {
        $error_message = 'Invalid CSRF token';
    }
}

try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($error_message)) {
        if ($action === 'add_product') {
            // Validate inputs
            $product_name = trim($_POST['product_name'] ?? '');
            $price = filter_var($_POST['price'] ?? 0, FILTER_VALIDATE_FLOAT);
            $category = trim($_POST['category'] ?? '');
            $stock_quantity = filter_var($_POST['stock_quantity'] ?? 0, FILTER_VALIDATE_INT);
            $description = trim($_POST['description'] ?? '');
            $is_featured = isset($_POST['is_featured']) ? 1 : 0;
            $sku = trim($_POST['sku'] ?? '');

            if (empty($product_name) || $price === false || $stock_quantity === false) {
                throw new Exception('Invalid product data');
            }

            // Handle image upload
            $image_path = '';
            if (isset($_FILES['product_image']) && $_FILES['product_image']['error'] === UPLOAD_ERR_OK) {
                $target_dir = "uploads/products/";
                if (!file_exists($target_dir)) {
                    mkdir($target_dir, 0777, true);
                }
                
                // Validate image
                $file_info = getimagesize($_FILES["product_image"]["tmp_name"]);
                if ($file_info === false) {
                    throw new Exception('File is not an image');
                }
                
                // Generate unique filename
                $file_extension = pathinfo($_FILES["product_image"]["name"], PATHINFO_EXTENSION);
                $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
                if (!in_array(strtolower($file_extension), $allowed_extensions)) {
                    throw new Exception('Only JPG, JPEG, PNG, WEBP & GIF files are allowed');
                }
                
                $new_filename = uniqid() . '.' . $file_extension;
                $target_file = $target_dir . $new_filename;
                
                if (!move_uploaded_file($_FILES["product_image"]["tmp_name"], $target_file)) {
                    throw new Exception('Failed to upload image');
                }
                
                // Optimize image
                optimizeImage($target_file);
                
                $image_path = $target_file;
            }

            $stmt = $db->prepare("
                INSERT INTO products 
                (product_name, price, category, stock_quantity, product_description, product_image, is_featured, sku) 
                VALUES (:name, :price, :category, :stock, :desc, :image, :featured, :sku)
            ");
            $stmt->bindParam(':name', $product_name);
            $stmt->bindParam(':price', $price);
            $stmt->bindParam(':category', $category);
            $stmt->bindParam(':stock', $stock_quantity);
            $stmt->bindParam(':desc', $description);
            $stmt->bindParam(':image', $image_path);
            $stmt->bindParam(':featured', $is_featured, PDO::PARAM_INT);
            $stmt->bindParam(':sku', $sku);
            $stmt->execute();

            $success_message = 'Product added successfully!';
        }
        elseif ($action === 'update_product') {
            $product_id = filter_var($_POST['product_id'] ?? 0, FILTER_VALIDATE_INT);
            if (!$product_id) {
                throw new Exception('Invalid product ID');
            }

            $product_name = trim($_POST['product_name'] ?? '');
            $price = filter_var($_POST['price'] ?? 0, FILTER_VALIDATE_FLOAT);
            $category = trim($_POST['category'] ?? '');
            $stock_quantity = filter_var($_POST['stock_quantity'] ?? 0, FILTER_VALIDATE_INT);
            $description = trim($_POST['description'] ?? '');
            $is_featured = isset($_POST['is_featured']) ? 1 : 0;
            $sku = trim($_POST['sku'] ?? '');

            if (empty($product_name) || $price === false || $stock_quantity === false) {
                throw new Exception('Invalid product data');
            }

            // Get current image path
            $stmt = $db->prepare("SELECT product_image FROM products WHERE id = :id");
            $stmt->bindParam(':id', $product_id);
            $stmt->execute();
            $current_product = $stmt->fetch(PDO::FETCH_ASSOC);
            $image_path = $current_product['product_image'] ?? '';

            // Handle image upload if new image is provided
            if (!empty($_FILES['product_image']['name'])) {
                $target_dir = "uploads/products/";
                if (!file_exists($target_dir)) {
                    mkdir($target_dir, 0777, true);
                }
                
                // Validate image
                $file_info = getimagesize($_FILES["product_image"]["tmp_name"]);
                if ($file_info === false) {
                    throw new Exception('File is not an image');
                }
                
                // Generate unique filename
                $file_extension = pathinfo($_FILES["product_image"]["name"], PATHINFO_EXTENSION);
                $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
                if (!in_array(strtolower($file_extension), $allowed_extensions)) {
                    throw new Exception('Only JPG, JPEG, PNG, WEBP & GIF files are allowed');
                }
                
                $new_filename = uniqid() . '.' . $file_extension;
                $target_file = $target_dir . $new_filename;
                
                if (move_uploaded_file($_FILES["product_image"]["tmp_name"], $target_file)) {
                    // Delete old image if it exists
                    if (!empty($image_path) && file_exists($image_path)) {
                        unlink($image_path);
                    }
                    // Optimize the new image
                    optimizeImage($target_file);
                    $image_path = $target_file;
                } else {
                    throw new Exception('Failed to upload image');
                }
            }

            $stmt = $db->prepare("
                UPDATE products SET 
                product_name = :name, 
                price = :price, 
                category = :category, 
                stock_quantity = :stock, 
                product_description = :desc, 
                product_image = :image, 
                is_featured = :featured,
                sku = :sku,
                updated_at = NOW()
                WHERE id = :id
            ");
            $stmt->bindParam(':name', $product_name);
            $stmt->bindParam(':price', $price);
            $stmt->bindParam(':category', $category);
            $stmt->bindParam(':stock', $stock_quantity);
            $stmt->bindParam(':desc', $description);
            $stmt->bindParam(':image', $image_path);
            $stmt->bindParam(':featured', $is_featured, PDO::PARAM_INT);
            $stmt->bindParam(':sku', $sku);
            $stmt->bindParam(':id', $product_id, PDO::PARAM_INT);
            $stmt->execute();

            $success_message = 'Product updated successfully!';
        }
        elseif ($action === 'update_order_status') {
            $order_id = filter_var($_POST['order_id'] ?? 0, FILTER_VALIDATE_INT);
            $status = in_array($_POST['status'] ?? '', ['pending', 'processing', 'shipped', 'delivered', 'cancelled']) 
                ? $_POST['status'] 
                : 'pending';

            if (!$order_id) {
                throw new Exception('Invalid order ID');
            }

            $stmt = $db->prepare("UPDATE orders SET status = :status WHERE id = :id");
            $stmt->bindParam(':status', $status);
            $stmt->bindParam(':id', $order_id, PDO::PARAM_INT);
            $stmt->execute();

            $success_message = 'Order status updated successfully!';
        }
        elseif ($action === 'bulk_action') {
            $bulk_action = $_POST['bulk_action'] ?? '';
            $selected_products = $_POST['selected_products'] ?? [];
            
            if (empty($selected_products)) {
                throw new Exception('No products selected');
            }
            
            $placeholders = implode(',', array_fill(0, count($selected_products), '?'));
            
            if ($bulk_action === 'delete') {
                // First get image paths to delete the files
                $stmt = $db->prepare("SELECT id, product_image FROM products WHERE id IN ($placeholders)");
                $stmt->execute($selected_products);
                $products_to_delete = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                foreach ($products_to_delete as $product) {
                    if (!empty($product['product_image']) && file_exists($product['product_image'])) {
                        unlink($product['product_image']);
                    }
                }
                
                // Then delete the products
                $stmt = $db->prepare("DELETE FROM products WHERE id IN ($placeholders)");
                $stmt->execute($selected_products);
                
                $success_message = 'Selected products deleted successfully!';
            } elseif ($bulk_action === 'feature') {
                $stmt = $db->prepare("UPDATE products SET is_featured = 1 WHERE id IN ($placeholders)");
                $stmt->execute($selected_products);
                
                $success_message = 'Selected products marked as featured!';
            } elseif ($bulk_action === 'unfeature') {
                $stmt = $db->prepare("UPDATE products SET is_featured = 0 WHERE id IN ($placeholders)");
                $stmt->execute($selected_products);
                
                $success_message = 'Selected products unmarked as featured!';
            }
        }
    }
    elseif ($action === 'delete_product') {
        $product_id = filter_var($_GET['id'] ?? 0, FILTER_VALIDATE_INT);
        if (!$product_id) {
            throw new Exception('Invalid product ID');
        }
        
        // First get image path to delete the file
        $stmt = $db->prepare("SELECT product_image FROM products WHERE id = :id");
        $stmt->bindParam(':id', $product_id, PDO::PARAM_INT);
        $stmt->execute();
        $product = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($product && !empty($product['product_image']) && file_exists($product['product_image'])) {
            unlink($product['product_image']);
        }
        
        // Then delete the product
        $stmt = $db->prepare("DELETE FROM products WHERE id = :id");
        $stmt->bindParam(':id', $product_id, PDO::PARAM_INT);
        $stmt->execute();
        
        $success_message = 'Product deleted successfully!';
    }
} catch (PDOException $e) {
    $error_message = 'Database error: ' . $e->getMessage();
} catch (Exception $e) {
    $error_message = $e->getMessage();
}

// Get data for dashboard
$stats = [];
$products = [];
$orders = [];
$users = [];
$edit_product = null;
$recent_reviews = [];
$sales_data = [];

try {
    // Statistics
    $stmt = $db->query("SELECT COUNT(*) FROM products");
    $stats['total_products'] = $stmt->fetchColumn();
    
    $stmt = $db->query("SELECT COUNT(*) FROM orders");
    $stats['total_orders'] = $stmt->fetchColumn();
    
    $stmt = $db->query("SELECT COUNT(*) FROM users");
    $stats['total_users'] = $stmt->fetchColumn();
    
    $stmt = $db->query("SELECT SUM(total_amount) FROM orders WHERE status = 'delivered'");
    $stats['total_revenue'] = $stmt->fetchColumn() ?? 0;
    
    $stmt = $db->query("SELECT COUNT(*) FROM product_reviews");
    $stats['total_reviews'] = $stmt->fetchColumn();
    
    $stmt = $db->query("SELECT AVG(rating) FROM product_reviews");
$avg = $stmt->fetchColumn();
$stats['avg_rating'] = $avg !== null ? number_format((float)$avg, 1) : '0.0';


    // Sales data for chart (last 30 days)
    $stmt = $db->query("
        SELECT DATE(created_at) as date, COUNT(*) as order_count, SUM(total_amount) as revenue
        FROM orders
        WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        GROUP BY DATE(created_at)
        ORDER BY date
    ");
    $sales_data = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Products
    $stmt = $db->query("
        SELECT p.*, 
               (SELECT AVG(rating) FROM product_reviews WHERE product_id = p.id) as avg_rating,
               (SELECT COUNT(*) FROM product_reviews WHERE product_id = p.id) as review_count
        FROM products p
        ORDER BY created_at DESC
        LIMIT 5
    ");
    $products = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Orders
    $stmt = $db->query("
        SELECT o.*, u.username
        FROM orders o
        JOIN users u ON o.user_id = u.id
        ORDER BY o.created_at DESC
        LIMIT 5
    ");
    $orders = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Users
    $stmt = $db->query("SELECT * FROM users ORDER BY created_at DESC LIMIT 5");
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Recent reviews
    $stmt = $db->query("
        SELECT r.*, p.product_name, u.username
        FROM product_reviews r
        JOIN products p ON r.product_id = p.id
        JOIN users u ON r.user_id = u.id
        ORDER BY r.created_at DESC
        LIMIT 5
    ");
    $recent_reviews = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Get product to edit if in edit mode
    if ($action === 'edit_product') {
        $product_id = $_GET['id'] ?? 0;
        $stmt = $db->prepare("SELECT * FROM products WHERE id = :id");
        $stmt->bindParam(':id', $product_id);
        $stmt->execute();
        $edit_product = $stmt->fetch(PDO::FETCH_ASSOC);
    }

} catch (PDOException $e) {
    $error_message = 'Database error: ' . $e->getMessage();
}

function optimizeImage($file_path) {
    // This is a placeholder for actual image optimization
    // In a real implementation, you might use a library like Intervention Image
    // or a service like TinyPNG
    return true;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Dashboard - Rice Husk Furniture</title>
  <link href="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.css" rel="stylesheet">
  <style>
    :root {
      --bg-color: #1a1a1a;
      --text-color: #f0f0f0;
      --navbar-border: #1a1a1a;
      --btn-bg: #6400d6;
      --btn-hover: #797fd1;
      --input-bg: #2d2d2d;
      --input-text: #ffffff;
      --sidebar-bg: #222;
      --transition-time: 0.4s;
      --price-color: #4CAF50;
      --featured-bg: rgba(255, 215, 0, 0.1);
      --danger-color: #f44336;
      --warning-color: #ff9800;
      --info-color: #2196F3;
    }

    body.light {
      --bg-color: #f5f5f5;
      --text-color: #333;
      --navbar-border: #f5f5f5;
      --btn-bg: #f3cfcf;
      --btn-hover: #e3bfbf;
      --input-bg: #ffffff;
      --input-text: #333;
      --sidebar-bg: #f0f0f0;
      --price-color: #2E7D32;
      --featured-bg: rgba(255, 215, 0, 0.2);
    }

    body {
      margin: 0;
      font-family: 'Segoe UI', Arial, sans-serif;
      background-color: var(--bg-color);
      color: var(--text-color);
      transition: background-color var(--transition-time) ease-out, 
                  color var(--transition-time) ease-out;
      line-height: 1.6;
    }

    .admin-container {
      display: flex;
      min-height: 100vh;
    }

    .admin-sidebar {
      width: 200px;
      background-color: var(--sidebar-bg);
      padding: 20px;
      position: fixed;
      height: 100%;
      overflow-y: auto;
    }

    .admin-main {
      flex: 1;
      margin-left: 250px;
      padding: 20px;
    }

    .stat-cards {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }

    .stat-card {
      background-color: var(--input-bg);
      padding: 20px;
      border-radius: 8px;
      transition: transform 0.3s ease;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .stat-card:hover {
      transform: translateY(-5px);
      box-shadow: 0 5px 15px rgba(0,0,0,0.1);
    }

    .stat-card h3 {
      margin-top: 0;
      color: var(--btn-bg);
      font-size: 1rem;
    }

    .stat-card .value {
      font-size: 2rem;
      font-weight: bold;
      margin: 10px 0;
    }

    .stat-card .trend {
      display: flex;
      align-items: center;
      font-size: 0.9rem;
    }

    .trend-up {
      color: var(--price-color);
    }

    .trend-down {
      color: var(--danger-color);
    }

    .trend-neutral {
      color: var(--text-color);
      opacity: 0.7;
    }

    .chart-container {
      background-color: var(--input-bg);
      padding: 20px;
      border-radius: 8px;
      margin-bottom: 30px;
      height: 400px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 20px;
      background-color: var(--input-bg);
    }

    th, td {
      padding: 12px 15px;
      text-align: left;
      border-bottom: 1px solid rgba(255,255,255,0.1);
    }

    th {
      background-color: rgba(182, 179, 179, 0.2);
      font-weight: bold;
    }

    .status-pending { color: var(--warning-color); }
    .status-processing { color: var(--info-color); }
    .status-shipped { color: purple; }
    .status-delivered { color: var(--price-color); }
    .status-cancelled { color: var(--danger-color); }

    .rating {
      display: inline-flex;
      align-items: center;
    }

    .rating-stars {
      color: gold;
      margin-right: 5px;
    }

    .btn {
      background-color: var(--btn-bg);
      color: black;
      border: none;
      padding: 8px 16px;
      border-radius: 4px;
      cursor: pointer;
      font-weight: bold;
      transition: all var(--transition-time) ease-out;
      text-decoration: none;
      display: inline-block;
    }

    .btn:hover {
      background-color: var(--btn-hover);
      transform: translateY(-2px);
    }

    .btn-danger {
      background-color: var(--danger-color);
      color: white;
    }

    .btn-danger:hover {
      background-color: #D32F2F;
    }

    .btn-warning {
      background-color: var(--warning-color);
      color: black;
    }

    .btn-info {
      background-color: var(--info-color);
      color: white;
    }

    .btn-sm {
      padding: 5px 10px;
      font-size: 0.8rem;
    }

    .form-group {
      margin-bottom: 15px;
    }

    label {
      display: block;
      margin-bottom: 5px;
      font-weight: bold;
    }

    input[type="text"],
    input[type="number"],
    input[type="email"],
    input[type="password"],
    textarea,
    select {
      width: 100%;
      padding: 10px;
      border-radius: 4px;
      border: 1px solid #ccc;
      background-color: var(--input-bg);
      color: var(--input-text);
    }

    .checkbox-group {
      display: flex;
      align-items: center;
    }

    .checkbox-group input {
      width: auto;
      margin-right: 10px;
    }

    .alert {
      padding: 15px;
      margin-bottom: 20px;
      border-radius: 4px;
    }

    .alert-success {
      background-color: rgba(76, 175, 80, 0.2);
      border-left: 4px solid var(--price-color);
    }

    .alert-error {
      background-color: rgba(244, 67, 54, 0.2);
      border-left: 4px solid var(--danger-color);
    }

    .product-image-preview {
      max-width: 200px;
      max-height: 200px;
      margin-bottom: 10px;
      display: block;
      border-radius: 4px;
    }

    .bulk-actions {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
      align-items: center;
    }

    .bulk-actions select {
      width: auto;
    }

    .action-btn {
      margin-left: 10px;
    }

    .select-all-checkbox {
      margin-right: 10px;
    }

    .review-item {
      padding: 15px;
      border-bottom: 1px solid rgba(255,255,255,0.1);
    }

    .review-header {
      display: flex;
      justify-content: space-between;
      margin-bottom: 5px;
    }

    .review-product {
      font-weight: bold;
      color: var(--btn-bg);
    }

    .review-user {
      font-style: italic;
    }

    .review-content {
      margin-top: 10px;
    }

    @media (max-width: 768px) {
      .admin-container {
        flex-direction: column;
      }
      
      .admin-sidebar {
        width: 100%;
        position: relative;
        height: auto;
      }
      
      .admin-main {
        margin-left: 0;
      }
      
      .stat-cards {
        grid-template-columns: 1fr;
      }
      
      .chart-container {
        height: 300px;
      }
    }
  </style>
</head>
<body>
<div class="admin-sidebar">
  <h2>Admin Panel</h2>
  <nav>
    <ul style="list-style: none; padding: 0;">
      <li style="margin-bottom: 10px;"><a href="admin.php" class="btn" style="width: 80%; text-align: left;">Dashboard</a></li>
      <li style="margin-bottom: 10px;"><a href="admin.php?action=products" class="btn" style="width: 80%; text-align: left;">Products</a></li>
      <li style="margin-bottom: 10px;"><a href="admin.php?action=orders" class="btn" style="width: 80%; text-align: left;">Orders</a></li>
      <li style="margin-bottom: 10px;"><a href="admin.php?action=users" class="btn" style="width: 80%; text-align: left;">Users</a></li>

      <li style="margin-bottom: 10px;"><a href="index.html" class="btn btn-success" style="width: 80%; text-align: left;">Go Back Home</a></li>
    </ul>
  </nav>
</div>

<div class="admin-main">
  <?php if ($success_message): ?>
    <div class="alert alert-success"><?php echo $success_message; ?></div>
  <?php endif; ?>
  
  <?php if ($error_message): ?>
    <div class="alert alert-error"><?php echo $error_message; ?></div>
  <?php endif; ?>

  <?php if (empty($action) || $action === 'dashboard'): ?>
    <h1>Dashboard Overview</h1>
    
    <div class="stat-cards">
      <div class="stat-card">
        <h3>Total Products</h3>
        <div class="value"><?php echo $stats['total_products'] ?? 0; ?></div>
        <a href="admin.php?action=products">View all products</a>
      </div>
      <div class="stat-card">
        <h3>Total Orders</h3>
        <div class="value"><?php echo $stats['total_orders'] ?? 0; ?></div>
        <a href="admin.php?action=orders">View all orders</a>
      </div>
      <div class="stat-card">
        <h3>Total Users</h3>
        <div class="value"><?php echo $stats['total_users'] ?? 0; ?></div>
        <a href="admin.php?action=users">View all users</a>
      </div>
      <div class="stat-card">
        <h3>Total Revenue</h3>
        <div class="value">₱<?php echo number_format($stats['total_revenue'] ?? 0, 2); ?></div>
        <span>From delivered orders</span>
      </div>

      </div>
    </div>
    
    <div class="chart-container">
      <canvas id="salesChart"></canvas>
    </div>
    
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
      <div>
        <h2>Recent Products</h2>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Price</th>
              <th>Stock</th>
              <th>Rating</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($products as $product): ?>
            <tr>
              <td><?php echo htmlspecialchars($product['product_name']); ?></td>
              <td>₱<?php echo number_format($product['price'], 2); ?></td>
              <td><?php echo $product['stock_quantity']; ?></td>
              <td>
                <div class="rating">
                  <span class="rating-stars"><?php echo str_repeat('★', round($product['avg_rating'] ?? 0)); ?></span>
                  <span>(<?php echo $product['review_count'] ?? 0; ?>)</span>
                </div>
              </td>
              <td>
                <a href="admin.php?action=edit_product&id=<?php echo $product['id']; ?>" class="btn btn-sm">Edit</a>
                <a href="admin.php?action=delete_product&id=<?php echo $product['id']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure?')">Delete</a>
              </td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      
      <div>
        <h2>Recent Orders</h2>
        <table>
          <thead>
            <tr>
              <th>Order ID</th>
              <th>Customer</th>
              <th>Amount</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($orders as $order): ?>
            <tr>
              <td><?php echo $order['id']; ?></td>
              <td><?php echo htmlspecialchars($order['username']); ?></td>
              <td>₱<?php echo number_format($order['total_amount'], 2); ?></td>
              <td class="status-<?php echo $order['status']; ?>">
                <?php echo ucfirst($order['status']); ?>
              </td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>

    <div style="margin-top: 30px;">
      <h2>Recent Reviews</h2>
      <div style="background-color: var(--input-bg); border-radius: 8px;">
        <?php foreach ($recent_reviews as $review): ?>
        <div class="review-item">
          <div class="review-header">
            <span class="review-product"><?php echo htmlspecialchars($review['product_name']); ?></span>
            <span class="rating">
              <span class="rating-stars"><?php echo str_repeat('★', $review['rating']); ?></span>
              <span>by <?php echo htmlspecialchars($review['username']); ?></span>
            </span>
          </div>
          <div class="review-content">
            <p><?php echo htmlspecialchars($review['review']); ?></p>
          </div>
        </div>
        <?php endforeach; ?>
      </div>
    </div>

  <?php elseif ($action === 'products' || $action === 'edit_product' || $action === 'add_product'): ?>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
      <h1><?php echo $action === 'edit_product' ? 'Edit Product' : ($action === 'add_product' ? 'Add New Product' : 'Products'); ?></h1>
      <a href="admin.php?action=add_product" class="btn">Add Product</a>
    </div>

    <?php if ($action === 'add_product' || $action === 'edit_product'): ?>
      <form method="post" enctype="multipart/form-data" style="max-width: 600px;">
        <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
        <?php if ($action === 'edit_product'): ?>
          <input type="hidden" name="action" value="update_product">
          <input type="hidden" name="product_id" value="<?php echo $edit_product['id']; ?>">
          <input type="hidden" name="current_image" value="<?php echo $edit_product['product_image'] ?? ''; ?>">
        <?php else: ?>
          <input type="hidden" name="action" value="add_product">
        <?php endif; ?>

        <div class="form-group">
          <label for="product_name">Product Name</label>
          <input type="text" id="product_name" name="product_name" required 
                 value="<?php echo $edit_product['product_name'] ?? ''; ?>">
        </div>

        <div class="form-group">
          <label for="sku">SKU</label>
          <input type="text" id="sku" name="sku" 
                 value="<?php echo $edit_product['sku'] ?? ''; ?>">
        </div>

        <div class="form-group">
          <label for="price">Price</label>
          <input type="number" id="price" name="price" step="0.01" min="0" required 
                 value="<?php echo $edit_product['price'] ?? ''; ?>">
        </div>

        <div class="form-group">
          <label for="category">Category</label>
          <input type="text" id="category" name="category" 
                 value="<?php echo $edit_product['category'] ?? ''; ?>">
        </div>

        <div class="form-group">
          <label for="stock_quantity">Stock Quantity</label>
          <input type="number" id="stock_quantity" name="stock_quantity" min="0" required 
                 value="<?php echo $edit_product['stock_quantity'] ?? ''; ?>">
        </div>

        <div class="form-group">
          <label for="description">Description</label>
          <textarea id="description" name="description" rows="4"><?php echo $edit_product['product_description'] ?? ''; ?></textarea>
        </div>

        <div class="form-group">
          <label for="product_image">Product Image</label>
          <?php if (!empty($edit_product['product_image'])): ?>
            <img src="<?php echo $edit_product['product_image']; ?>" class="product-image-preview">
          <?php endif; ?>
          <input type="file" id="product_image" name="product_image" accept="image/*">
          <small>Recommended size: 800x800px, max 2MB</small>
        </div>

        <div class="form-group checkbox-group">
          <input type="checkbox" id="is_featured" name="is_featured" value="1" 
                 <?php echo (isset($edit_product['is_featured']) && $edit_product['is_featured']) ? 'checked' : ''; ?>>
          <label for="is_featured">Featured Product</label>
        </div>

        <button type="submit" class="btn"><?php echo $action === 'edit_product' ? 'Update Product' : 'Add Product'; ?></button>
        <a href="admin.php?action=products" class="btn btn-danger">Cancel</a>
      </form>
    <?php else: ?>
      <form method="post" action="admin.php?action=bulk_action">
        <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
        <div class="bulk-actions">
          <select name="bulk_action" class="form-control">
            <option value="">Bulk Actions</option>
            <option value="delete">Delete</option>
            <option value="feature">Mark as Featured</option>
            <option value="unfeature">Unmark as Featured</option>
          </select>
          <button type="submit" class="btn action-btn">Apply</button>
        </div>
        
        <table>
          <thead>
            <tr>
              <th width="30"><input type="checkbox" id="selectAll" class="select-all-checkbox"></th>
              <th>Name</th>
              <th>Price</th>
              <th>Category</th>
              <th>Stock</th>
              <th>Featured</th>
              <th>Rating</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <?php 
            $stmt = $db->query("
              SELECT p.*, 
                     (SELECT AVG(rating) FROM product_reviews WHERE product_id = p.id) as avg_rating,
                     (SELECT COUNT(*) FROM product_reviews WHERE product_id = p.id) as review_count
              FROM products p
              ORDER BY created_at DESC
            ");
            $all_products = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($all_products as $product): 
            ?>
            <tr>
              <td><input type="checkbox" name="selected_products[]" value="<?php echo $product['id']; ?>"></td>
              <td><?php echo htmlspecialchars($product['product_name']); ?></td>
              <td>₱<?php echo number_format($product['price'], 2); ?></td>
              <td><?php echo htmlspecialchars($product['category']); ?></td>
              <td><?php echo $product['stock_quantity']; ?></td>
              <td><?php echo $product['is_featured'] ? 'Yes' : 'No'; ?></td>
              <td>
                <div class="rating">
                  <span class="rating-stars"><?php echo str_repeat('★', round($product['avg_rating'] ?? 0)); ?></span>
                  <span>(<?php echo $product['review_count'] ?? 0; ?>)</span>
                </div>
              </td>
              <td>
                <a href="admin.php?action=edit_product&id=<?php echo $product['id']; ?>" class="btn btn-sm">Edit</a>
                <a href="admin.php?action=delete_product&id=<?php echo $product['id']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure?')">Delete</a>
              </td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </form>
    <?php endif; ?>

  <?php elseif ($action === 'orders'): ?>
  <h1>Orders</h1>
    
    <table>
        <thead>
            <tr>
                <th>Order ID</th>
                <th>Customer</th>
                <th>Amount</th>
                <th>Status</th>
                <th>Date</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php 
            $stmt = $db->query("
                SELECT o.*, u.username
                FROM orders o
                JOIN users u ON o.user_id = u.id
                ORDER BY o.created_at DESC
            ");
            $all_orders = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($all_orders as $order): 
            ?>
            <tr>
                <td><?php echo $order['id']; ?></td>
                <td><?php echo htmlspecialchars($order['username']); ?></td>
                <td>₱<?php echo number_format($order['total_amount'], 2); ?></td>
                <td class="status-<?php echo $order['status']; ?>">
                    <?php echo ucfirst($order['status']); ?>
                </td>
                <td><?php echo date('M d, Y', strtotime($order['created_at'])); ?></td>
                <td>
                    <a href="admin.php?action=view_order&id=<?php echo $order['id']; ?>" class="btn btn-sm">View</a>
                    <form method="post" action="admin.php?action=update_order_status" style="display: inline-block;">
                        <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                        <input type="hidden" name="order_id" value="<?php echo $order['id']; ?>">
                        <select name="status" onchange="this.form.submit()" style="padding: 5px; background: var(--input-bg); color: var(--input-text);">
                            <option value="pending" <?php echo $order['status'] === 'pending' ? 'selected' : ''; ?>>Pending</option>
                            <option value="processing" <?php echo $order['status'] === 'processing' ? 'selected' : ''; ?>>Processing</option>
                            <option value="shipped" <?php echo $order['status'] === 'shipped' ? 'selected' : ''; ?>>Shipped</option>
                            <option value="delivered" <?php echo $order['status'] === 'delivered' ? 'selected' : ''; ?>>Delivered</option>
                            <option value="cancelled" <?php echo $order['status'] === 'cancelled' ? 'selected' : ''; ?>>Cancelled</option>
                        </select>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>

  <?php elseif ($action === 'view_order'): ?>
    <?php
    $order_id = $_GET['id'] ?? 0;
    $stmt = $db->prepare("
      SELECT o.*, u.username, u.email
      FROM orders o
      JOIN users u ON o.user_id = u.id
      WHERE o.id = :id
    ");
    $stmt->bindParam(':id', $order_id);
    $stmt->execute();
    $order = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($order):
      $stmt = $db->prepare("
        SELECT oi.*, p.product_name, p.product_image 
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
        WHERE oi.order_id = :order_id
      ");
      $stmt->bindParam(':order_id', $order_id);
      $stmt->execute();
      $order_items = $stmt->fetchAll(PDO::FETCH_ASSOC);
    ?>
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h1>Order #<?php echo $order['id']; ?></h1>
        <a href="admin.php?action=orders" class="btn">Back to Orders</a>
      </div>

      <div style="margin-bottom: 30px;">
        <h2>Order Details</h2>
        <div style="background: var(--input-bg); padding: 20px; border-radius: 8px;">
          <p><strong>Customer:</strong> <?php echo htmlspecialchars($order['username']); ?> (<?php echo htmlspecialchars($order['email']); ?>)</p>
          <p><strong>Order Date:</strong> <?php echo date('M d, Y H:i', strtotime($order['created_at'])); ?></p>
          <p><strong>Status:</strong> <span class="status-<?php echo $order['status']; ?>"><?php echo ucfirst($order['status']); ?></span></p>
          <p><strong>Total Amount:</strong> ₱<?php echo number_format($order['total_amount'], 2); ?></p>
          <?php if (!empty($order['shipping_address'])): ?>
            <p><strong>Shipping Address:</strong> <?php echo nl2br(htmlspecialchars($order['shipping_address'])); ?></p>
          <?php endif; ?>
        </div>
      </div>

      <div>
        <h2>Order Items</h2>
        <table>
          <thead>
            <tr>
              <th>Product</th>
              <th>Price</th>
              <th>Quantity</th>
              <th>Subtotal</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($order_items as $item): ?>
            <tr>
              <td>
                <?php echo htmlspecialchars($item['product_name']); ?>
                <?php if ($item['product_image']): ?>
                  <img src="<?php echo $item['product_image']; ?>" style="max-width: 50px; max-height: 50px; margin-left: 10px;">
                <?php endif; ?>
              </td>
              <td>₱<?php echo number_format($item['price'], 2); ?></td>
              <td><?php echo $item['quantity']; ?></td>
              <td>₱<?php echo number_format($item['price'] * $item['quantity'], 2); ?></td>
            </tr>
            <?php endforeach; ?>
            <tr>
              <td colspan="3" style="text-align: right; font-weight: bold;">Total:</td>
              <td style="font-weight: bold;">₱<?php echo number_format($order['total_amount'], 2); ?></td>
            </tr>
          </tbody>
        </table>
      </div>
    <?php else: ?>
      <div class="alert alert-error">Order not found</div>
      <a href="admin.php?action=orders" class="btn">Back to Orders</a>
    <?php endif; ?>

  <?php elseif ($action === 'users'): ?>
    <h1>Users</h1>
    
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Username</th>
          <th>Email</th>
          <th>Role</th>
          <th>Joined</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        <?php 
        $stmt = $db->query("SELECT * FROM users ORDER BY created_at DESC");
        $all_users = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($all_users as $user): 
        ?>
        <tr>
          <td><?php echo $user['id']; ?></td>
          <td><?php echo htmlspecialchars($user['username']); ?></td>
          <td><?php echo htmlspecialchars($user['email']); ?></td>
          <td><?php echo ucfirst($user['role']); ?></td>
          <td><?php echo date('M d, Y', strtotime($user['created_at'])); ?></td>
          <td>
            <?php if ($user['id'] != $_SESSION['user_id']): ?>
              <a href="admin.php?action=edit_user&id=<?php echo $user['id']; ?>" class="btn btn-sm">Edit</a>
              <a href="admin.php?action=delete_user&id=<?php echo $user['id']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure?')">Delete</a>
            <?php endif; ?>
          </td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>

  <?php elseif ($action === 'reviews'): ?>
    <h1>Product Reviews</h1>
    
    <table>
      <thead>
        <tr>
          <th>Product</th>
          <th>User</th>
          <th>Rating</th>
          <th>Review</th>
          <th>Date</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        <?php 
        $stmt = $db->query("
          SELECT r.*, p.product_name, u.username
          FROM product_reviews r
          JOIN products p ON r.product_id = p.id
          JOIN users u ON r.user_id = u.id
          ORDER BY r.created_at DESC
        ");
        $all_reviews = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($all_reviews as $review): 
        ?>
        <tr>
          <td><?php echo htmlspecialchars($review['product_name']); ?></td>
          <td><?php echo htmlspecialchars($review['username']); ?></td>
          <td>
            <div class="rating">
              <span class="rating-stars"><?php echo str_repeat('★', $review['rating']); ?></span>
            </div>
          </td>
          <td><?php echo htmlspecialchars(substr($review['review'], 0, 50)); ?><?php echo strlen($review['review']) > 50 ? '...' : ''; ?></td>
          <td><?php echo date('M d, Y', strtotime($review['created_at'])); ?></td>
          <td>
            <a href="admin.php?action=view_review&id=<?php echo $review['id']; ?>" class="btn btn-sm">View</a>
            <a href="admin.php?action=delete_review&id=<?php echo $review['id']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure?')">Delete</a>
          </td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
<?php endif; ?>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js"></script>
<script>
  document.addEventListener('DOMContentLoaded', function() {
    // Select all checkbox
    const selectAllCheckbox = document.getElementById('selectAll');
    if (selectAllCheckbox) {
      selectAllCheckbox.addEventListener('change', function() {
        const checkboxes = document.querySelectorAll('input[name="selected_products[]"]');
        checkboxes.forEach(checkbox => {
          checkbox.checked = selectAllCheckbox.checked;
        });
      });
    }
    
    // Sales chart
    const salesCtx = document.getElementById('salesChart');
    if (salesCtx) {
      const salesData = <?php echo json_encode($sales_data); ?>;
      
      const labels = salesData.map(item => item.date);
      const orderData = salesData.map(item => item.order_count);
      const revenueData = salesData.map(item => item.revenue);
      
      new Chart(salesCtx, {
        type: 'line',
        data: {
          labels: labels,
          datasets: [
            {
              label: 'Orders',
              data: orderData,
              borderColor: 'rgb(75, 192, 192)',
              tension: 0.1,
              yAxisID: 'y'
            },
            {
              label: 'Revenue (₱)',
              data: revenueData,
              borderColor: 'rgb(54, 162, 235)',
              tension: 0.1,
              yAxisID: 'y1'
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              type: 'linear',
              display: true,
              position: 'left',
              title: {
                display: true,
                text: 'Orders'
              }
            },
            y1: {
              type: 'linear',
              display: true,
              position: 'right',
              title: {
                display: true,
                text: 'Revenue (₱)'
              },
              grid: {
                drawOnChartArea: false
              }
            }
          }
        }
      });
    }
  });
</script>
</body>
</html>