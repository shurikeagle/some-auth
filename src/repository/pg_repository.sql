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
);

CREATE TABLE IF NOT EXISTS roles (
    id serial PRIMARY KEY,
    name VARCHAR NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_roles__name on roles USING btree (name);

CREATE TABLE IF NOT EXISTS users_roles (
    user_id int REFERENCES users,
    role_id int REFERENCES roles,

    CONSTRAINT user_id__role_id__pkey PRIMARY KEY (user_id, role_id)
);