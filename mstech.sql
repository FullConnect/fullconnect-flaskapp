-- Adminer 4.8.1 MySQL 8.0.33 dump

SET NAMES utf8;
SET time_zone = '+00:00';
SET foreign_key_checks = 0;
SET sql_mode = 'NO_AUTO_VALUE_ON_ZERO';

SET NAMES utf8mb4;

DROP TABLE IF EXISTS `cart`;
CREATE TABLE `cart` (
  `id` int NOT NULL AUTO_INCREMENT,
  `basetype` varchar(20) DEFAULT NULL,
  `extend_basetype` varchar(20) NOT NULL,
  `measuring_range` varchar(20) NOT NULL,
  `exit_range` varchar(20) NOT NULL,
  `display` varchar(20) NOT NULL,
  `connection_process` varchar(20) NOT NULL,
  `temperature_measured` varchar(20) NOT NULL,
  `process_connection_material` varchar(20) NOT NULL,
  `electrical_connection` varchar(20) NOT NULL,
  `typical_additions` varchar(20) NOT NULL,
  `liquid` varchar(20) NOT NULL,
  `quantity` int NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


DROP TABLE IF EXISTS `category`;
CREATE TABLE `category` (
  `id_cat` int NOT NULL AUTO_INCREMENT,
  `name_cat` varchar(100) NOT NULL,
  PRIMARY KEY (`id_cat`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


DROP TABLE IF EXISTS `checkout_item`;
CREATE TABLE `checkout_item` (
  `id` int NOT NULL AUTO_INCREMENT,
  `order_id` int DEFAULT NULL,
  `first_name` varchar(50) NOT NULL,
  `last_name` varchar(50) NOT NULL,
  `email` varchar(50) NOT NULL,
  `organization` varchar(100) NOT NULL,
  `phone` varchar(12) NOT NULL,
  `device` varchar(50) NOT NULL,
  `quantity` varchar(3) NOT NULL,
  `date` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


DROP TABLE IF EXISTS `paraments`;
CREATE TABLE `paraments` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_paraments` varchar(20) NOT NULL,
  `param_descr` varchar(100) NOT NULL,
  `category_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `category_id` (`category_id`),
  CONSTRAINT `paraments_ibfk_1` FOREIGN KEY (`category_id`) REFERENCES `category` (`id_cat`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


DROP TABLE IF EXISTS `service_cat`;
CREATE TABLE `service_cat` (
  `id_serv_cat` int NOT NULL AUTO_INCREMENT,
  `name_serv_cat` varchar(100) NOT NULL,
  PRIMARY KEY (`id_serv_cat`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


DROP TABLE IF EXISTS `service_records`;
CREATE TABLE `service_records` (
  `id` int NOT NULL AUTO_INCREMENT,
  `first_name` varchar(50) NOT NULL,
  `last_name` varchar(50) NOT NULL,
  `email` varchar(50) NOT NULL,
  `organization` varchar(100) NOT NULL,
  `phone` varchar(50) NOT NULL,
  `name_serv_cat` int DEFAULT NULL,
  `data` varchar(20) NOT NULL,
  `commentary` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `name_serv_cat` (`name_serv_cat`),
  CONSTRAINT `service_records_ibfk_1` FOREIGN KEY (`name_serv_cat`) REFERENCES `service_cat` (`id_serv_cat`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `id` int NOT NULL AUTO_INCREMENT,
  `first_name` varchar(50) NOT NULL,
  `last_name` varchar(50) NOT NULL,
  `email` varchar(50) NOT NULL,
  `phone` varchar(12) NOT NULL,
  `organization` varchar(100) DEFAULT NULL,
  `password` varchar(255) NOT NULL,
  `is_admin` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `password` (`password`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO `user` (`id`, `first_name`, `last_name`, `email`, `phone`, `organization`, `password`, `is_admin`) VALUES
(1,	'Роман',	'Котков',	'rowem@gmial.cum',	'+79869203184',	'FURNIWOOD',	'$2b$12$dsbN7KJzIqj/K1pBqzxg1OpzokMyvhI.pgkAaPGmm2sVXDQ3RixsK',	0),
(2,	'Роман',	'Котков',	'romankotkov1678@gmail.com',	'+79869203184',	'FURNIWOOD',	'$2b$12$hxn62wHiPHqp0OrzLJPOs.nZiZz5jhI4rFh.1EZQatrCT2cJjZuFS',	0),
(3,	'admin',	'admin',	'admin@admin.com',	'11111111111',	'none',	'$2b$12$9P7Tu4h6BBJ10APuMydFaeO1Oy/3YmKhBPMceAgRXTpAhT2eCNLH2',	1);

-- 2023-05-25 08:10:43
