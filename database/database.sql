-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 15, 2025 at 07:32 AM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `rice_husk`
--
CREATE DATABASE IF NOT EXISTS `rice_husk` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `rice_husk`;

-- --------------------------------------------------------

--
-- Table structure for table `cart`
--

CREATE TABLE IF NOT EXISTS `cart` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `quantity` int(11) DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `product_id` (`product_id`)
) ENGINE=InnoDB AUTO_INCREMENT=37 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `cart`
--

INSERT INTO `cart` (`id`, `user_id`, `product_id`, `quantity`, `created_at`, `updated_at`) VALUES
(35, 8, 55, 1, '2025-05-13 07:04:04', '2025-05-13 07:04:04');

-- --------------------------------------------------------

--
-- Table structure for table `orders`
--

CREATE TABLE IF NOT EXISTS `orders` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `total_amount` decimal(10,2) NOT NULL,
  `shipping_address` text DEFAULT NULL,
  `recipient_name` varchar(100) DEFAULT NULL,
  `address_line1` varchar(255) DEFAULT NULL,
  `address_line2` varchar(255) DEFAULT NULL,
  `city` varchar(100) DEFAULT NULL,
  `province` varchar(100) DEFAULT NULL,
  `postal_code` varchar(20) DEFAULT NULL,
  `country` varchar(100) DEFAULT NULL,
  `phone_number` varchar(20) DEFAULT NULL,
  `status` enum('pending','processing','shipped','delivered','cancelled') DEFAULT 'pending',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=105 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `orders`
--

INSERT INTO `orders` (`id`, `user_id`, `total_amount`, `shipping_address`, `recipient_name`, `address_line1`, `address_line2`, `city`, `province`, `postal_code`, `country`, `phone_number`, `status`, `created_at`, `updated_at`) VALUES
(2, 6, 2100.00, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'delivered', '2025-05-12 20:07:15', '2025-05-12 20:35:50'),
(6, 6, 890.00, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'delivered', '2025-05-13 00:25:24', '2025-05-13 17:24:21'),
(23, 6, 650.00, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'delivered', '2025-05-13 04:00:20', '2025-05-13 17:24:04'),
(101, 6, 31968.00, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'processing', '2025-05-13 17:33:40', '2025-05-13 17:34:41'),
(103, 12, 900.00, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'delivered', '2025-05-14 18:48:04', '2025-05-14 18:49:34'),
(104, 1, 900.00, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'pending', '2025-05-15 05:31:01', '2025-05-15 05:31:01');

-- --------------------------------------------------------

--
-- Table structure for table `order_items`
--

CREATE TABLE IF NOT EXISTS `order_items` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `order_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `quantity` int(11) NOT NULL,
  `price` decimal(10,2) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `order_id` (`order_id`),
  KEY `product_id` (`product_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `order_items`
--

INSERT INTO `order_items` (`id`, `order_id`, `product_id`, `quantity`, `price`, `created_at`) VALUES
(1, 104, 49, 1, 900.00, '2025-05-15 05:31:01');

-- --------------------------------------------------------

--
-- Table structure for table `products`
--

CREATE TABLE IF NOT EXISTS `products` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `product_name` varchar(100) NOT NULL,
  `sku` varchar(100) DEFAULT NULL,
  `product_description` text DEFAULT NULL,
  `price` decimal(10,2) NOT NULL,
  `category` varchar(50) DEFAULT NULL,
  `product_image` varchar(255) DEFAULT NULL,
  `stock_quantity` int(11) DEFAULT 0,
  `is_featured` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `sku` (`sku`)
) ENGINE=InnoDB AUTO_INCREMENT=63 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `products`
--

INSERT INTO `products` (`id`, `product_name`, `sku`, `product_description`, `price`, `category`, `product_image`, `stock_quantity`, `is_featured`, `created_at`, `updated_at`) VALUES
(48, 'Wood Chair Ver.1', NULL, 'made in rusk husk materials', 400.00, 'Chair', 'uploads/products/6822c13ba25a4.jpg', 27, 1, '2025-05-12 19:49:15', '2025-05-13 10:14:43'),
(49, 'Wood Chair Ver.2', NULL, 'made of rice husk materials.', 900.00, 'Chair', 'uploads/products/6822c1a03d9cf.jpg', 8, 1, '2025-05-12 19:50:56', '2025-05-15 05:31:01'),
(50, 'Wood Chair Ver.3', NULL, 'make of rice husk material.', 450.00, 'Chair', 'uploads/products/6822c1cf9955c.jpg', 4, 0, '2025-05-12 19:51:43', '2025-05-14 18:48:04'),
(51, 'Wood Chair Ver.4', NULL, '', 340.00, 'Chair', 'uploads/products/6822c1ff2d1f4.jpg', 9, 1, '2025-05-12 19:52:31', '2025-05-12 19:52:31'),
(52, 'Wood Chair Ver.5', NULL, '', 340.00, 'Chair', 'uploads/products/6822c21a62ca1.jpg', 12, 1, '2025-05-12 19:52:58', '2025-05-12 19:52:58'),
(53, 'Wood Chair Ver.6', NULL, '', 650.00, 'Chair', 'uploads/products/6822c24160050.jpg', 2, 1, '2025-05-12 19:53:37', '2025-05-13 05:02:52'),
(54, 'Board Chair Ver.1', NULL, '', 150.00, 'Board', 'uploads/products/6822c33ec133c.jpg', 34, 1, '2025-05-12 19:57:50', '2025-05-12 19:57:50'),
(55, 'Board Chair Ver.2', NULL, '', 400.00, 'Board', 'uploads/products/6822c36575d45.jpg', 19, 1, '2025-05-12 19:58:29', '2025-05-12 20:07:15'),
(56, 'Board Chair Ver.3', NULL, '', 900.00, 'Board', 'uploads/products/6822c38123a7c.jpg', 31, 1, '2025-05-12 19:58:57', '2025-05-12 19:58:57'),
(57, 'Board Chair Ver.4', NULL, '', 890.00, 'Board', 'uploads/products/6822c39eb5aeb.jpg', 42, 1, '2025-05-12 19:59:26', '2025-05-13 00:25:24'),
(58, 'Rice Husk Desk Ver.1', NULL, '', 1100.00, 'Desk', 'uploads/products/6822c459b1e85.jpg', 11, 1, '2025-05-12 20:02:33', '2025-05-12 20:02:33'),
(59, 'Rice Husk Desk Ver.2', NULL, '', 890.00, 'Desk', 'uploads/products/6822c4799b416.jpg', 10, 1, '2025-05-12 20:03:05', '2025-05-13 00:19:48'),
(61, 'Rice Husk Table Ver.1', NULL, '', 400.00, 'Table', 'uploads/products/6822c4d16c7ed.jpg', 10, 1, '2025-05-12 20:04:33', '2025-05-12 20:04:33'),
(62, 'Rice Husk Table Ver.2', NULL, '', 650.00, 'Table', 'uploads/products/6822c534e04df.jpg', 43, 1, '2025-05-12 20:06:12', '2025-05-12 20:06:12');

-- --------------------------------------------------------

--
-- Table structure for table `product_reviews`
--

CREATE TABLE IF NOT EXISTS `product_reviews` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `product_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `rating` int(11) NOT NULL,
  `review` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `product_reviews_ibfk_1` (`product_id`),
  KEY `product_reviews_ibfk_2` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `shipping_addresses`
--

CREATE TABLE IF NOT EXISTS `shipping_addresses` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `recipient_name` varchar(100) NOT NULL,
  `address_line1` varchar(255) NOT NULL,
  `address_line2` varchar(255) DEFAULT NULL,
  `city` varchar(100) NOT NULL,
  `province` varchar(100) NOT NULL,
  `postal_code` varchar(20) NOT NULL,
  `country` varchar(100) NOT NULL DEFAULT 'Philippines',
  `phone_number` varchar(20) NOT NULL,
  `is_default` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('admin','user') DEFAULT 'user',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `password`, `role`, `created_at`, `updated_at`) VALUES
(1, 'test', 'test@local.dev', 'testpass', 'user', '2025-05-15 05:29:26', '2025-05-15 05:29:26'),
(6, 'jay', 'gapoljayar945@gmail.com', '123', 'user', '2025-05-12 05:20:11', '2025-05-12 05:20:11'),
(7, 'asd', 'q@gmail.com', '1', 'user', '2025-05-12 21:29:13', '2025-05-12 21:29:13'),
(8, 'q', '1@gmail.com', '$2y$10$c3IKbnrFXu/1yBxhhLODJuyhThJwlWIwkVcTMtLBT9OGad2POk2LG', 'user', '2025-05-13 07:03:20', '2025-05-13 07:03:20'),
(9, 'cdasd', 'dada@gmail.com', '$2y$10$5YzFT0NgSDnC3eWIBQULIuFkMeUB9xSYuqab3PXSN8MDcVwmWro96', 'user', '2025-05-13 07:27:00', '2025-05-13 07:27:00'),
(10, '4', '4qwe@gmail.com', '4', 'user', '2025-05-13 09:39:41', '2025-05-13 09:39:41'),
(11, 'admin', 'admin@example.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin', '2025-05-14 10:10:12', '2025-05-14 10:10:12'),
(12, 'admin', 'admin@gmail.com', '$2y$12$SomeRandomSaltOrHash', 'admin', '2025-05-14 10:29:20', '2025-05-14 10:29:20');

--
-- Constraints for dumped tables
--

--
-- Constraints for table `cart`
--
ALTER TABLE `cart`
  ADD CONSTRAINT `cart_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `cart_ibfk_2` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `orders`
--
ALTER TABLE `orders`
  ADD CONSTRAINT `orders_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `order_items`
--
ALTER TABLE `order_items`
  ADD CONSTRAINT `order_items_ibfk_1` FOREIGN KEY (`order_id`) REFERENCES `orders` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `order_items_ibfk_2` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `product_reviews`
--
ALTER TABLE `product_reviews`
  ADD CONSTRAINT `product_reviews_ibfk_1` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `product_reviews_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `shipping_addresses`
--
ALTER TABLE `shipping_addresses`
  ADD CONSTRAINT `shipping_addresses_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
