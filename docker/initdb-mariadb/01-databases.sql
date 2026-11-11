-- The pool gateway and the control plane each keep their own migration history, so they
-- need separate databases. The user proxyx (MARIADB_USER) owns both.
CREATE DATABASE proxyx_pool CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE DATABASE proxyx_control CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
GRANT ALL PRIVILEGES ON proxyx_pool.* TO 'proxyx'@'%';
GRANT ALL PRIVILEGES ON proxyx_control.* TO 'proxyx'@'%';
