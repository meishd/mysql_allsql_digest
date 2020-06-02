use digest_stat;

CREATE TABLE `db_instance` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `instance_name` varchar(50) COLLATE utf8mb4_bin NOT NULL,
  `ip_addr` varchar(15) COLLATE utf8mb4_bin NOT NULL,
  `port` int(11) NOT NULL,
  `user_name` varchar(50) COLLATE utf8mb4_bin NOT NULL,
  `password` varchar(50) COLLATE utf8mb4_bin NOT NULL,
  `status` int(1) NOT NULL DEFAULT '0' COMMENT '0:active, 1:inactive',
  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idxu_instancename` (`instance_name`),
  UNIQUE KEY `idx_ip_port` (`ip_addr`,`port`)
) ENGINE=InnoDB;

CREATE TABLE `global_query_review` (
  `checksum` varchar(200) NOT NULL,
  `fingerprint` text NOT NULL,
  `sample` longtext,
  `first_seen` datetime DEFAULT NULL,
  `last_seen` datetime DEFAULT NULL,
  `reviewed_by` varchar(20) DEFAULT NULL,
  `reviewed_on` datetime DEFAULT NULL,
  `comments` text,
  `reviewed_status` varchar(24) DEFAULT NULL,
  PRIMARY KEY (`checksum`)
) ENGINE=InnoDB;

CREATE TABLE `global_query_review_history` (
  `hostname_max` varchar(64) NOT NULL,
  `db_max` varchar(64) DEFAULT NULL,
  `checksum` varchar(200) NOT NULL,
  `sample` longtext,
  `ts_min` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `ts_max` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `ts_cnt` float DEFAULT NULL,
  `query_time_avg` float DEFAULT NULL,
  UNIQUE KEY `hostname_max` (`hostname_max`,`checksum`,`ts_min`,`ts_max`),
  KEY `ts_min` (`ts_min`),
  KEY `checksum` (`checksum`)
) ENGINE=InnoDB;
