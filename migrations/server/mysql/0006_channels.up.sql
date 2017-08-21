ALTER TABLE `tuf_files`
  DROP INDEX `gun`;

CREATE TABLE `channels` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `deleted_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `channels` (id, name) VALUES (1, "published"), (2, "staged");

CREATE TABLE `channels_tuf_files` (
  `channel_id` INT(11) NOT NULL,
  `tuf_file_id` INT(11) NOT NULL,
  FOREIGN KEY (channel_id) REFERENCES channels(`id`) ON DELETE CASCADE,
  FOREIGN KEY (tuf_file_id) REFERENCES tuf_files(`id`) ON DELETE CASCADE,
  PRIMARY KEY (tuf_file_id, channel_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `channels_tuf_files` (channel_id, tuf_file_id) (
  SELECT 1, `id` FROM `tuf_files`
);


