ALTER TABLE users
ADD COLUMN pay_address TEXT;
CREATE TABLE IF NOT EXISTS invoices (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    amount BIGINT NOT NULL,
    validators_count BIGINT NOT NULL,
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    is_paid BOOL NOT NULL DEFAULT false,
    CONSTRAINT fk_invoices_users FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_invoices_user_id on invoices(user_id);
CREATE INDEX IF NOT EXISTS idx_invoices_is_paid on invoices(is_paid);
CREATE INDEX IF NOT EXISTS idx_invoices_starts_at on invoices(starts_at);
CREATE INDEX IF NOT EXISTS idx_invoices_ends_at on invoices(ends_at);