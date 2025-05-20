<?php
class Database {
    private $host = 'localhost'; // Change this if your database is hosted elsewhere
    private $db_name = 'rice_husk'; // Replace with your database name
    private $username = 'root'; // Replace with your database username
    private $password = ''; // Replace with your database password
    private $conn;

    public function connect() {
        $this->conn = null;

        try {
            $this->conn = new PDO(
                "mysql:host={$this->host};dbname={$this->db_name}",
                $this->username,
                $this->password
            );
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            echo 'Connection Error: ' . $e->getMessage();
        }

        return $this->conn;
    }
}
?>