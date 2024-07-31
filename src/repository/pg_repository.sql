CREATE TABLE IF NOT EXISTS users (
    id serial PRIMARY KEY,
    username VARCHAR NOT NULL UNIQUE,
    pwd_hash VARCHAR NOT NULL UNIQUE,
    admin bool NOT NULL,
    blocked bool NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_users__username on users USING btree (username);

CREATE TABLE IF NOT EXISTS refreshes (
    user_id INT PRIMARY KEY REFERENCES users ON DELETE CASCADE,
    token_hash VARCHAR NOT NULL,
    time_updated TIMESTAMP WITH TIME ZONE NOT NULL
)