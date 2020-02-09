CREATE TABLE IF NOT EXISTS `connections` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `timestamp` datetime DEFAULT NULL,
  `sensor` int(4) DEFAULT NULL,
  `ip` varchar(15) DEFAULT NULL,
  `local_port` int(11) DEFAULT NULL,
  `request` varchar(6) DEFAULT NULL,
  `path` varchar(256) DEFAULT NULL,
  `body` int(4) DEFAULT NULL,
  `payload` int(4) DEFAULT NULL,
  `message` int(4) DEFAULT NULL,
  `local_host` varchar(15) DEFAULT NULL,
  `remote_port` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE IF NOT EXISTS `sensors` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE IF NOT EXISTS `bodies` (
  `id` int(11) NOT NULL auto_increment,
  `input` varchar(3000) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `inputhash` varchar(66),
  PRIMARY KEY (`id`),
  UNIQUE (`inputhash`)
);

CREATE TABLE IF NOT EXISTS `payloads` (
  `id` int(11) NOT NULL auto_increment,
  `input` varchar(3000) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `inputhash` varchar(66),
  PRIMARY KEY (`id`),
  UNIQUE (`inputhash`)
);

CREATE TABLE IF NOT EXISTS `messages` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `message` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE IF NOT EXISTS `geolocation` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(15) DEFAULT NULL,
  `country_name` varchar(45) DEFAULT '',
  `country_iso_code` varchar(2) DEFAULT '',
  `city_name` varchar(128) DEFAULT '',
  `org` varchar(128) DEFAULT '',
  `org_asn` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE('ip')
);

