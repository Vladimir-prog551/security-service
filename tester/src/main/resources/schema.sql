CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users_roles (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    role_id INT REFERENCES roles(id)
);

CREATE TABLE IF NOT EXISTS refresh_token (
    id SERIAL PRIMARY KEY,
    token TEXT NOT NULL,
    user_id INT REFERENCES users(id),
    expirydate TIMESTAMP NOT NULL
);

INSERT INTO roles (name) VALUES
('ADMIN'),
('PREMIUM_USER'),
('GUEST');