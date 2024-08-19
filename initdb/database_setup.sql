-- Create 'admin_user' and 'normal_user' roles
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'normal_user') THEN
        CREATE ROLE normal_user NOLOGIN;
        GRANT USAGE ON SCHEMA public TO normal_user;
        -- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO normal_user;
        -- ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO normal_user;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, USAGE ON SEQUENCES TO normal_user;
        -- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO normal_user;
        -- ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO normal_user;
    END IF;

    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'admin_user') THEN
        CREATE ROLE admin_user NOLOGIN;
        GRANT USAGE ON SCHEMA public TO admin_user;
        -- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO admin_user;
        -- ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO admin_user;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, USAGE ON SEQUENCES TO admin_user;
        -- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO admin_user;
        -- ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO admin_user;
    END IF;
END $$;


CREATE TABLE users (
    id SERIAL PRIMARY KEY, 
    email TEXT NULL UNIQUE,            
    admin BOOLEAN DEFAULT FALSE,
    password TEXT NOT NULL,           
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE comments (
    id SERIAL PRIMARY KEY, 
    text TEXT NOT NULL            
);


-- Create the password hashing function
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE OR REPLACE FUNCTION hash_password_function()
RETURNS TRIGGER AS $$
BEGIN
    -- Hash the password using bcrypt
    NEW.password := crypt(NEW.password, gen_salt('bf'));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create the trigger that calls the hashing function
CREATE TRIGGER hash_password_trigger
BEFORE INSERT OR UPDATE
ON users
FOR EACH ROW
EXECUTE FUNCTION hash_password_function();

-- Trigger function to update the last_updated column upon row modification
CREATE OR REPLACE FUNCTION update_last_updated()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_updated = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers to update last_updated timestamps 
CREATE TRIGGER trg_update_timestamp_users
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_last_updated();

-- Special configuration for 'users' table
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO admin_user;
GRANT SELECT ON users TO normal_user;

GRANT SELECT, INSERT, UPDATE, DELETE ON comments TO admin_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON comments TO normal_user;

-- Row Level security (in progress)
-- ALTER TABLE users ENABLE ROW LEVEL SECURITY;
-- -- Administrator can see all rows and add any rows
-- CREATE POLICY admin_all ON users TO admin_user USING (true) WITH CHECK (true);
-- -- Normal users can view all rows
-- CREATE POLICY all_view ON users FOR SELECT TO normal_user ;
-- -- Normal users can update their own records, but
-- CREATE POLICY user_mod ON users FOR UPDATE TO normal_user
--   USING (email = current_setting('request.jwt.claims', true)::json->>'sub');

CREATE OR REPLACE FUNCTION get_jwt_claims()
RETURNS TEXT AS $$
BEGIN
    RETURN current_setting('request.jwt.claims', true)::json;
END;
$$ LANGUAGE plpgsql;