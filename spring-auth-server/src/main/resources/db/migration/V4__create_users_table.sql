CREATE TABLE app_users (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_fraud BOOLEAN DEFAULT FALSE
);

-- Seed user alice_smith with password 'secret123'
-- Password pipeline: client SHA-256 hashes plaintext, server bcrypts the SHA-256 digest
-- SHA-256('secret123') = fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4
-- BCrypt(SHA-256('secret123')) = below
INSERT INTO app_users (email, password_hash)
VALUES ('alice_smith@example.com', '$2b$10$Z9xsQSpaqYAufsPE4nm6YudyWJv3JDdMr0ZKLtmLw7t9GFUWIuz/C');
