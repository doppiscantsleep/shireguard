-- Stripe billing columns on users table
ALTER TABLE users ADD COLUMN stripe_customer_id TEXT;
ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT;
CREATE INDEX idx_users_stripe_customer_id ON users(stripe_customer_id);
