ALTER TABLE "tuf_files" DROP CONSTRAINT "tuf_files_gun_role_version_key";

CREATE TABLE "channels" (
"id" serial PRIMARY KEY,
"name" VARCHAR(255) NOT NULL,
"created_at" timestamp NULL DEFAULT NULL,
"updated_at" timestamp NULL DEFAULT NULL,
"deleted_at" timestamp NULL DEFAULT NULL
);

INSERT INTO "channels" (id, name) VALUES (1, 'published'), (2, 'staged');

CREATE TABLE "channels_tuf_files" (
"channel_id" integer NOT NULL,
"tuf_file_id" integer NOT NULL,
FOREIGN KEY (channel_id) REFERENCES channels("id") ON DELETE CASCADE,
FOREIGN KEY (tuf_file_id) REFERENCES tuf_files("id") ON DELETE CASCADE,
PRIMARY KEY (tuf_file_id, channel_id)
);

INSERT INTO "channels_tuf_files" (channel_id, tuf_file_id) (
SELECT 1, "id" FROM "tuf_files"
);


